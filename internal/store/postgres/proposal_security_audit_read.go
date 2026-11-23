package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/avaargsh/agent-runtime/internal/audit"
	"github.com/google/uuid"
)

// ErrInvalidProposalAuditQuery rejects unbounded or noncanonical audit reads.
// This reader is internal to Runtime, not an external authorization endpoint.
var ErrInvalidProposalAuditQuery = errors.New("invalid Proposal security audit query")

const maxProposalAuditRead = 100

// ProposalSecurityAuditEvent exposes only the trusted archive's correlation
// metadata. The potentially sensitive JSON payload is never selected or
// returned. Execution outbox delivery messages are NOT security audit facts.
type ProposalSecurityAuditEvent struct {
	EventID          string          `json:"event_id"`
	EventType        audit.EventType `json:"event_type"`
	OccurredAt       time.Time       `json:"occurred_at"`
	Source           string          `json:"source"`
	TraceID          string          `json:"trace_id,omitempty"`
	PayloadDigest    string          `json:"payload_digest,omitempty"`
	GuardOperationID string          `json:"guard_operation_id,omitempty"`
}

// ListProposalSecurityAudit reads a bounded, chronological slice of immutable
// Runtime security-audit metadata for a canonical, tenant-owned Proposal/Run.
//
// This is a forensic read, not a Permit, an operation journal or a complete
// Proposal transition history: transition delivery remains in the outbox,
// while security audit writers explicitly append separate redacted facts.
// No raw audit JSON, prompt, tool arguments or Vault data cross this boundary.
func (s *Store) ListProposalSecurityAudit(
	ctx context.Context, tenantID, runID, proposalID string, limit int,
) ([]ProposalSecurityAuditEvent, error) {
	if s == nil || s.pool == nil {
		return nil, audit.ErrRecorderUnavailable
	}
	if !validProposalAuditScope(tenantID, 255) ||
		!validProposalAuditScope(proposalID, 255) ||
		limit < 1 || limit > maxProposalAuditRead {
		return nil, ErrInvalidProposalAuditQuery
	}
	id, err := uuid.Parse(runID)
	if err != nil || id.String() != runID {
		return nil, ErrInvalidProposalAuditQuery
	}

	// A caller-supplied Proposal ID alone is never sufficient evidence of
	// tenant/Run ownership. The v3 authoritative Proposal has a foreign key
	// to the canonical Runtime Run and an immutable Run scope.
	var exists bool
	err = s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM runtime_proposals p
			JOIN runs r ON r.tenant_id=p.tenant_id AND r.run_id=p.run_id
			WHERE p.tenant_id=$1 AND p.run_id=$2::uuid AND p.proposal_id=$3
		)
	`, tenantID, runID, proposalID).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("verify canonical Proposal security audit scope: %w", err)
	}
	if !exists {
		// Do not distinguish absent from cross-tenant/cross-Run proposals.
		return nil, ErrProposalNotFound
	}

	rows, err := s.pool.Query(ctx, `
		SELECT event_id, event_type, occurred_at, source, trace_id,
		       payload_digest, guard_operation_id
		FROM runtime_security_audit_events
		WHERE tenant_id=$1 AND run_id=$2 AND proposal_id=$3
		ORDER BY occurred_at ASC, event_id ASC
		LIMIT $4
	`, tenantID, runID, proposalID, limit)
	if err != nil {
		return nil, fmt.Errorf("read Proposal security audit metadata: %w", err)
	}
	defer rows.Close()
	facts := make([]ProposalSecurityAuditEvent, 0)
	for rows.Next() {
		var fact ProposalSecurityAuditEvent
		var eventType string
		if err := rows.Scan(
			&fact.EventID, &eventType, &fact.OccurredAt, &fact.Source,
			&fact.TraceID, &fact.PayloadDigest, &fact.GuardOperationID,
		); err != nil {
			return nil, fmt.Errorf("scan Proposal security audit metadata: %w", err)
		}
		fact.EventType = audit.EventType(eventType)
		facts = append(facts, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Proposal security audit metadata: %w", err)
	}
	return facts, nil
}

func validProposalAuditScope(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n\t")
}
