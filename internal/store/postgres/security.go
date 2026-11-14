package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-runtime/internal/audit"
	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrAuditEventConflict     = errors.New("Runtime audit event ID reused with different content")
	ErrBreakerNotFound        = errors.New("circuit breaker record not found")
	ErrBreakerVersionConflict = errors.New("circuit breaker version conflict")
)

type auditEventPayload struct {
	EventID          string            `json:"event_id"`
	OccurredAt       time.Time         `json:"occurred_at"`
	EventType        audit.EventType   `json:"event_type"`
	Identity         map[string]string `json:"identity"`
	Source           string            `json:"source"`
	TraceID          string            `json:"trace_id,omitempty"`
	Action           string            `json:"action,omitempty"`
	Resource         string            `json:"resource,omitempty"`
	ProposalID       string            `json:"proposal_id,omitempty"`
	ToolCallID       string            `json:"tool_call_id,omitempty"`
	ApprovalID       string            `json:"approval_id,omitempty"`
	PermitID         string            `json:"permit_id,omitempty"`
	Outcome          audit.Outcome     `json:"outcome"`
	ReasonCode       string            `json:"reason_code,omitempty"`
	RiskLevel        string            `json:"risk_level,omitempty"`
	PayloadDigest    string            `json:"payload_digest,omitempty"`
	EvidenceRef      string            `json:"evidence_ref,omitempty"`
	GuardOperationID string            `json:"guard_operation_id,omitempty"`
	ParentEventID    string            `json:"parent_event_id,omitempty"`
	BreakerEpoch     uint64            `json:"breaker_epoch,omitempty"`
}

func newAuditEventPayload(event audit.Event) auditEventPayload {
	claims := event.Identity.Claims()
	return auditEventPayload{
		EventID:    event.EventID,
		OccurredAt: event.OccurredAt.UTC(),
		EventType:  event.Type,
		Identity: map[string]string{
			"tenant_id":        claims.TenantID,
			"subject_id":       claims.SubjectID,
			"actor_id":         claims.ActorID,
			"agent_id":         claims.AgentID,
			"agent_release_id": claims.AgentReleaseID,
			"session_id":       claims.SessionID,
			"run_id":           claims.RunID,
			"run_attempt_id":   claims.RunAttemptID,
			"turn_id":          claims.TurnID,
			"policy_revision":  claims.PolicyRevision,
		},
		Source:           event.Source,
		TraceID:          event.TraceID,
		Action:           event.Action,
		Resource:         event.Resource,
		ProposalID:       event.ProposalID,
		ToolCallID:       event.ToolCallID,
		ApprovalID:       event.ApprovalID,
		PermitID:         event.PermitID,
		Outcome:          event.Outcome,
		ReasonCode:       event.ReasonCode,
		RiskLevel:        event.RiskLevel,
		PayloadDigest:    event.PayloadDigest,
		EvidenceRef:      event.EvidenceRef,
		GuardOperationID: event.GuardOperationID,
		ParentEventID:    event.ParentEventID,
		BreakerEpoch:     event.BreakerEpoch,
	}
}

// appendAuditTx writes an immutable audit fact in the caller's transaction.
// The Runtime execution outbox remains a separate delivery mechanism.
func appendAuditTx(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	payload, err := json.Marshal(newAuditEventPayload(event))
	if err != nil {
		return fmt.Errorf("marshal Runtime security audit event: %w", err)
	}
	claims := event.Identity.Claims()
	tag, err := tx.Exec(ctx, `
		INSERT INTO runtime_security_audit_events (
			tenant_id, event_id, run_id, event_type, occurred_at, source,
			trace_id, proposal_id, tool_call_id, approval_id, permit_id,
			guard_operation_id, payload_digest, payload
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)
		ON CONFLICT (tenant_id, event_id) DO NOTHING
	`,
		claims.TenantID, event.EventID, claims.RunID, string(event.Type),
		event.OccurredAt.UTC(), event.Source, event.TraceID, event.ProposalID,
		event.ToolCallID, event.ApprovalID, event.PermitID, event.GuardOperationID,
		event.PayloadDigest, string(payload),
	)
	if err != nil {
		return fmt.Errorf("insert Runtime security audit event: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var identical bool
		if err := tx.QueryRow(ctx, `
			SELECT payload = $3::jsonb
			FROM runtime_security_audit_events
			WHERE tenant_id=$1 AND event_id=$2
			FOR SHARE
		`, claims.TenantID, event.EventID, string(payload)).Scan(&identical); err != nil {
			return fmt.Errorf("verify Runtime audit replay: %w", err)
		}
		if !identical {
			return ErrAuditEventConflict
		}
	}
	return nil
}

// Append implements audit.Recorder. Replaying the same event ID with identical
// content is idempotent; a different payload under that identity is rejected.
func (s *Store) Append(ctx context.Context, event audit.Event) error {
	if s == nil || s.pool == nil {
		return audit.ErrRecorderUnavailable
	}
	if err := event.Validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Runtime audit append: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := appendAuditTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Runtime security audit event: %w", err)
	}
	return nil
}

// GetRunBreaker binds a RUN breaker lookup to the authoritative Run tenant.
// The Run row is the tenant ownership source; scope_id alone is not sufficient.
func (s *Store) GetRunBreaker(ctx context.Context, tenantID, runID string) (breaker.Record, error) {
	if s == nil || s.pool == nil {
		return breaker.Record{}, errors.New("PostgreSQL pool is unavailable")
	}
	if tenantID == "" || strings.TrimSpace(tenantID) != tenantID || runID == "" || strings.TrimSpace(runID) != runID {
		return breaker.Record{}, breaker.ErrInvalidScope
	}
	var record breaker.Record
	var state string
	var openedAt pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `
		SELECT b.scope_kind, b.scope_id, b.state, b.epoch, b.version,
			b.reason_code, b.trigger_event_id, b.opened_at,
			b.recovery_approval_id, b.last_recovery_evidence_ref, b.updated_at
		FROM runtime_circuit_breakers b
		INNER JOIN runs r
			ON r.run_id::text = b.scope_id
			AND b.scope_kind = 'RUN'
		WHERE r.tenant_id=$1 AND r.run_id::text=$2
	`, tenantID, runID).Scan(
		&record.Scope.Kind, &record.Scope.ID, &state, &record.Epoch,
		&record.Version, &record.ReasonCode, &record.TriggerEventID,
		&openedAt, &record.RecoveryApprovalID,
		&record.LastRecoveryEvidenceRef, &record.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return breaker.Record{}, ErrBreakerNotFound
	}
	if err != nil {
		return breaker.Record{}, fmt.Errorf("load tenant-bound Run circuit breaker: %w", err)
	}
	record.State = breaker.State(state)
	if openedAt.Valid {
		record.OpenedAt = openedAt.Time.UTC()
	}
	if err := record.Validate(); err != nil {
		return breaker.Record{}, fmt.Errorf("validate tenant-bound Run breaker: %w", err)
	}
	return record, nil
}

func (s *Store) GetBreaker(ctx context.Context, scope breaker.Scope) (breaker.Record, error) {
	if s == nil || s.pool == nil {
		return breaker.Record{}, errors.New("PostgreSQL pool is unavailable")
	}
	if _, err := breaker.NewClosed(scope, time.Now().UTC()); err != nil {
		return breaker.Record{}, err
	}
	record, err := loadBreaker(ctx, s.pool, scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return breaker.Record{}, ErrBreakerNotFound
	}
	if err != nil {
		return breaker.Record{}, fmt.Errorf("load circuit breaker: %w", err)
	}
	return record, nil
}

type breakerQueryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func loadBreaker(ctx context.Context, queryer breakerQueryer, scope breaker.Scope) (breaker.Record, error) {
	var record breaker.Record
	var state string
	var openedAt pgtype.Timestamptz
	err := queryer.QueryRow(ctx, `
		SELECT scope_kind, scope_id, state, epoch, version, reason_code,
			trigger_event_id, opened_at, recovery_approval_id,
			last_recovery_evidence_ref, updated_at
		FROM runtime_circuit_breakers
		WHERE scope_kind=$1 AND scope_id=$2
	`, string(scope.Kind), scope.ID).Scan(
		&record.Scope.Kind, &record.Scope.ID, &state, &record.Epoch,
		&record.Version, &record.ReasonCode, &record.TriggerEventID,
		&openedAt, &record.RecoveryApprovalID,
		&record.LastRecoveryEvidenceRef, &record.UpdatedAt,
	)
	if err != nil {
		return breaker.Record{}, err
	}
	record.State = breaker.State(state)
	if openedAt.Valid {
		record.OpenedAt = openedAt.Time.UTC()
	}
	if err := record.Validate(); err != nil {
		return breaker.Record{}, fmt.Errorf("validate persisted circuit breaker: %w", err)
	}
	return record, nil
}

// CompareAndSwapBreaker persists one breaker transition without an associated
// security event. Enforcement paths should prefer TransitionBreakerWithAudit.
func (s *Store) CompareAndSwapBreaker(
	ctx context.Context,
	expectedVersion uint64,
	next breaker.Record,
) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL pool is unavailable")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if expectedVersion == ^uint64(0) || next.Version != expectedVersion+1 {
		return ErrBreakerVersionConflict
	}
	var openedAt any
	if !next.OpenedAt.IsZero() {
		openedAt = next.OpenedAt.UTC()
	}
	if expectedVersion == 0 {
		if next.Version != 1 || next.Epoch != 1 || next.State != breaker.StateClosed {
			return ErrBreakerVersionConflict
		}
		tag, err := s.pool.Exec(ctx, `
			INSERT INTO runtime_circuit_breakers (
				scope_kind, scope_id, state, epoch, version, reason_code,
				trigger_event_id, opened_at, recovery_approval_id,
				last_recovery_evidence_ref, updated_at
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (scope_kind, scope_id) DO NOTHING
		`, string(next.Scope.Kind), next.Scope.ID, string(next.State), next.Epoch,
			next.Version, next.ReasonCode, next.TriggerEventID, openedAt,
			next.RecoveryApprovalID, next.LastRecoveryEvidenceRef, next.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("create circuit breaker: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrBreakerVersionConflict
		}
		return nil
	}

	tag, err := s.pool.Exec(ctx, breakerUpdateSQL,
		string(next.State), next.Epoch, next.Version, next.ReasonCode,
		next.TriggerEventID, openedAt, next.RecoveryApprovalID,
		next.LastRecoveryEvidenceRef, next.UpdatedAt.UTC(),
		string(next.Scope.Kind), next.Scope.ID, expectedVersion)
	if err != nil {
		return fmt.Errorf("compare-and-swap circuit breaker: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrBreakerVersionConflict
	}
	return nil
}

const breakerUpdateSQL = `
	UPDATE runtime_circuit_breakers
	SET state=$1, epoch=$2, version=$3, reason_code=$4,
		trigger_event_id=$5, opened_at=$6, recovery_approval_id=$7,
		last_recovery_evidence_ref=$8, updated_at=$9
	WHERE scope_kind=$10 AND scope_id=$11
		AND version=$12 AND epoch + 1 = $2
		AND (
			(state='CLOSED' AND $1='OPEN')
			OR (state='OPEN' AND $1='HALF_OPEN')
			OR (state='HALF_OPEN' AND $1 IN ('OPEN','CLOSED'))
		)
`

// TransitionBreakerWithAudit commits a breaker transition and its security
// event in one PostgreSQL transaction. It fails closed if either write fails.
// Replaying the same already-committed state+event after a lost acknowledgement
// is idempotent, but a different event or stale transition remains a conflict.
func (s *Store) TransitionBreakerWithAudit(
	ctx context.Context,
	expectedVersion uint64,
	next breaker.Record,
	event audit.Event,
) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL pool is unavailable")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if expectedVersion == 0 || expectedVersion == ^uint64(0) ||
		next.Version != expectedVersion+1 || next.Epoch < 2 {
		return ErrBreakerVersionConflict
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.BreakerEpoch != next.Epoch {
		return fmt.Errorf("%w: audit event breaker epoch mismatch", ErrInvalidEventBinding)
	}
	if err := validateBreakerAuditBinding(next, event); err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin atomic breaker/audit transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var openedAt any
	if !next.OpenedAt.IsZero() {
		openedAt = next.OpenedAt.UTC()
	}
	tag, err := tx.Exec(ctx, breakerUpdateSQL,
		string(next.State), next.Epoch, next.Version, next.ReasonCode,
		next.TriggerEventID, openedAt, next.RecoveryApprovalID,
		next.LastRecoveryEvidenceRef, next.UpdatedAt.UTC(),
		string(next.Scope.Kind), next.Scope.ID, expectedVersion)
	if err != nil {
		return fmt.Errorf("update circuit breaker with audit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		current, loadErr := s.GetBreaker(ctx, next.Scope)
		if loadErr != nil || !breakerRecordsEqual(current, next) {
			return ErrBreakerVersionConflict
		}
		identical, auditErr := s.auditEventMatches(ctx, event)
		if auditErr != nil {
			return auditErr
		}
		if !identical {
			return ErrBreakerVersionConflict
		}
		return nil
	}
	if err := appendAuditTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit atomic breaker/audit transition: %w", err)
	}
	return nil
}

var ErrInvalidEventBinding = errors.New("Runtime audit event does not match breaker transition")

func validateBreakerAuditBinding(next breaker.Record, event audit.Event) error {
	claims := event.Identity.Claims()
	switch next.Scope.Kind {
	case breaker.ScopeRun:
		if claims.RunID != next.Scope.ID {
			return ErrInvalidEventBinding
		}
	case breaker.ScopeAgentInstance:
		if claims.AgentID != next.Scope.ID {
			return ErrInvalidEventBinding
		}
	case breaker.ScopeTenant:
		if claims.TenantID != next.Scope.ID {
			return ErrInvalidEventBinding
		}
	}
	switch next.State {
	case breaker.StateOpen:
		if event.Type != audit.EventBreakerTripped || event.ReasonCode != next.ReasonCode {
			return ErrInvalidEventBinding
		}
	case breaker.StateHalfOpen:
		if event.Type != audit.EventApprovalResolved || event.ApprovalID != next.RecoveryApprovalID {
			return ErrInvalidEventBinding
		}
	case breaker.StateClosed:
		if event.Type != audit.EventBreakerRecovered || event.EvidenceRef != next.LastRecoveryEvidenceRef {
			return ErrInvalidEventBinding
		}
	default:
		return ErrInvalidEventBinding
	}
	return nil
}

func breakerRecordsEqual(left, right breaker.Record) bool {
	return left.Scope == right.Scope &&
		left.State == right.State &&
		left.Epoch == right.Epoch &&
		left.Version == right.Version &&
		left.ReasonCode == right.ReasonCode &&
		left.TriggerEventID == right.TriggerEventID &&
		left.OpenedAt.Equal(right.OpenedAt) &&
		left.RecoveryApprovalID == right.RecoveryApprovalID &&
		left.LastRecoveryEvidenceRef == right.LastRecoveryEvidenceRef &&
		left.UpdatedAt.Equal(right.UpdatedAt)
}

func (s *Store) auditEventMatches(ctx context.Context, event audit.Event) (bool, error) {
	payload, err := json.Marshal(newAuditEventPayload(event))
	if err != nil {
		return false, fmt.Errorf("marshal Runtime security audit event: %w", err)
	}
	var identical bool
	err = s.pool.QueryRow(ctx, `
		SELECT payload = $3::jsonb
		FROM runtime_security_audit_events
		WHERE tenant_id=$1 AND event_id=$2
	`, event.Identity.TenantID(), event.EventID, string(payload)).Scan(&identical)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify atomic breaker/audit replay: %w", err)
	}
	if !identical {
		return false, ErrAuditEventConflict
	}
	return true, nil
}

var _ audit.Recorder = (*Store)(nil)
