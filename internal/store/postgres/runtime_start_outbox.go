package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// maxRuntimeStartAttempts bounds duplicate external Start attempts. Exhausted
// entries remain undelivered for explicit reconciliation, never marked FAILED.
const maxRuntimeStartAttempts = 5

var (
	ErrInvalidRuntimeStartLease = errors.New("invalid Runtime start Outbox lease")
	ErrRuntimeStartLeaseLost    = errors.New("Runtime start Outbox lease expired or fenced")
)

// RuntimeStartLease describes an ACP-sourced Run already committed in Runtime.
// The identifiers come from joined Runs, never from a message payload.
type RuntimeStartLease struct {
	OutboxID      string
	TenantID      string
	RunIntentID   string
	RequestDigest string
	RunID         string
	WorkflowID    string
	Owner         string
	Attempt       int32
}

// ClaimRuntimeStart leases one committed ACP-originated start record.
// It does not execute or authorize a Run. Starting Temporal still requires
// the separately ratified principal/policy snapshot.
func (s *Store) ClaimRuntimeStart(ctx context.Context, owner string, ttl time.Duration) (RuntimeStartLease, bool, error) {
	if s == nil || s.pool == nil {
		return RuntimeStartLease{}, false, errors.New("Runtime PostgreSQL store unavailable")
	}
	if !validRuntimeStartOwner(owner) || ttl < time.Microsecond {
		return RuntimeStartLease{}, false, ErrInvalidRuntimeStartLease
	}
	var lease RuntimeStartLease
	err := s.pool.QueryRow(ctx, `
		WITH candidate AS (
			SELECT o.outbox_id
			FROM runtime_outbox AS o
			JOIN runs AS r ON r.run_id = o.aggregate_id AND r.tenant_id = o.tenant_id
			WHERE o.event_type = 'RUN_START_REQUESTED'
			  AND r.run_intent_id IS NOT NULL
			  AND r.source_request_digest IS NOT NULL
			  AND r.workflow_id = 'agent-run/v1/' || r.run_id::text
			  AND o.payload->>'tenant_id' = r.tenant_id
			  AND o.payload->>'run_id' = r.run_id::text
			  AND o.payload->>'workflow_id' = r.workflow_id
			  AND o.payload->>'run_intent_id' = r.run_intent_id::text
			  AND o.payload->>'request_digest' = r.source_request_digest
			  AND o.delivered_at IS NULL
			  AND o.attempts < $3
			  AND o.available_at <= clock_timestamp()
			  AND (o.lease_owner IS NULL OR o.lease_expires_at <= clock_timestamp())
			ORDER BY o.available_at, o.created_at, o.outbox_id
			LIMIT 1 FOR UPDATE OF o SKIP LOCKED
		)
		UPDATE runtime_outbox AS o
		SET attempts = o.attempts + 1,
			lease_owner = $1,
			lease_expires_at = clock_timestamp() + ($2::bigint * interval '1 microsecond')
		FROM candidate, runs AS r
		WHERE o.outbox_id = candidate.outbox_id AND r.run_id = o.aggregate_id
		RETURNING o.outbox_id::text, o.tenant_id, r.run_intent_id::text,
			r.source_request_digest, r.run_id::text, r.workflow_id,
			o.lease_owner, o.attempts
	`, owner, ttl.Microseconds(), maxRuntimeStartAttempts).Scan(
		&lease.OutboxID, &lease.TenantID, &lease.RunIntentID,
		&lease.RequestDigest, &lease.RunID, &lease.WorkflowID,
		&lease.Owner, &lease.Attempt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RuntimeStartLease{}, false, nil
	}
	if err != nil {
		return RuntimeStartLease{}, false, fmt.Errorf("claim Runtime start Outbox: %w", err)
	}
	if !validRuntimeStartLease(lease) {
		return RuntimeStartLease{}, false, ErrInvalidRuntimeStartLease
	}
	return lease, true, nil
}

// AcknowledgeRuntimeStart is permitted only after authoritative Temporal
// acceptance/identity reconciliation. An expired worker cannot ACK.
func (s *Store) AcknowledgeRuntimeStart(ctx context.Context, lease RuntimeStartLease) error {
	if s == nil || s.pool == nil {
		return errors.New("Runtime PostgreSQL store unavailable")
	}
	if !validRuntimeStartLease(lease) {
		return ErrInvalidRuntimeStartLease
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE runtime_outbox
		SET delivered_at = clock_timestamp(), lease_owner = NULL,
			lease_expires_at = NULL, last_error = NULL
		WHERE outbox_id = $1::uuid AND tenant_id = $2
		  AND aggregate_id = $3::uuid AND event_type = 'RUN_START_REQUESTED'
		  AND delivered_at IS NULL AND attempts = $4
		  AND lease_owner = $5 AND lease_expires_at > clock_timestamp()
	`, lease.OutboxID, lease.TenantID, lease.RunID, lease.Attempt, lease.Owner)
	if err != nil {
		return fmt.Errorf("acknowledge Runtime start Outbox: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrRuntimeStartLeaseLost
	}
	return nil
}

// ReleaseRuntimeStart retains the UNKNOWN outcome. Another worker may
// reconcile Temporal and retry only using the same canonical Workflow ID.
func (s *Store) ReleaseRuntimeStart(ctx context.Context, lease RuntimeStartLease, retryDelay time.Duration) error {
	if s == nil || s.pool == nil {
		return errors.New("Runtime PostgreSQL store unavailable")
	}
	if !validRuntimeStartLease(lease) || retryDelay < time.Microsecond {
		return ErrInvalidRuntimeStartLease
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE runtime_outbox
		SET available_at = clock_timestamp() + ($6::bigint * interval '1 microsecond'),
			lease_owner = NULL, lease_expires_at = NULL,
			last_error = 'TEMPORAL_ACK_UNCERTAIN'
		WHERE outbox_id = $1::uuid AND tenant_id = $2
		  AND aggregate_id = $3::uuid AND event_type = 'RUN_START_REQUESTED'
		  AND delivered_at IS NULL AND attempts = $4
		  AND lease_owner = $5 AND lease_expires_at > clock_timestamp()
	`, lease.OutboxID, lease.TenantID, lease.RunID, lease.Attempt, lease.Owner, retryDelay.Microseconds())
	if err != nil {
		return fmt.Errorf("release Runtime start Outbox: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrRuntimeStartLeaseLost
	}
	return nil
}

func validRuntimeStartOwner(owner string) bool {
	return owner != "" && len(owner) <= 128 && owner == strings.TrimSpace(owner) &&
		!strings.ContainsAny(owner, "\x00\r\n\t ")
}

func validRuntimeStartLease(l RuntimeStartLease) bool {
	_, outboxErr := uuid.Parse(l.OutboxID)
	_, runErr := uuid.Parse(l.RunID)
	_, intentErr := uuid.Parse(l.RunIntentID)
	return outboxErr == nil && runErr == nil && intentErr == nil &&
		l.TenantID != "" && l.TenantID == strings.TrimSpace(l.TenantID) &&
		strings.HasPrefix(l.RequestDigest, "sha256:") &&
		len(l.RequestDigest) == len("sha256:")+64 &&
		l.WorkflowID == "agent-run/v1/"+l.RunID &&
		validRuntimeStartOwner(l.Owner) &&
		l.Attempt >= 1 && l.Attempt <= maxRuntimeStartAttempts
}
