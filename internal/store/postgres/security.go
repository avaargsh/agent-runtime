package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-runtime/internal/audit"
	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrAuditEventConflict    = errors.New("Runtime audit event ID reused with different content")
	ErrBreakerNotFound       = errors.New("circuit breaker record not found")
	ErrBreakerVersionConflict = errors.New("circuit breaker version conflict")
)

type auditEventPayload struct {
	EventID          string                 `json:"event_id"`
	OccurredAt       time.Time              `json:"occurred_at"`
	EventType        audit.EventType        `json:"event_type"`
	Identity         map[string]string      `json:"identity"`
	Source           string                 `json:"source"`
	TraceID          string                 `json:"trace_id,omitempty"`
	Action           string                 `json:"action,omitempty"`
	Resource         string                 `json:"resource,omitempty"`
	ProposalID       string                 `json:"proposal_id,omitempty"`
	ToolCallID       string                 `json:"tool_call_id,omitempty"`
	ApprovalID       string                 `json:"approval_id,omitempty"`
	PermitID         string                 `json:"permit_id,omitempty"`
	Outcome          audit.Outcome          `json:"outcome"`
	ReasonCode       string                 `json:"reason_code,omitempty"`
	RiskLevel        string                 `json:"risk_level,omitempty"`
	PayloadDigest    string                 `json:"payload_digest,omitempty"`
	EvidenceRef      string                 `json:"evidence_ref,omitempty"`
	GuardOperationID string                 `json:"guard_operation_id,omitempty"`
	ParentEventID    string                 `json:"parent_event_id,omitempty"`
	BreakerEpoch     uint64                 `json:"breaker_epoch,omitempty"`
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

// Append implements audit.Recorder. Replaying the same event ID with identical
// content is idempotent; a different payload under that identity is rejected.
func (s *Store) Append(ctx context.Context, event audit.Event) error {
	if s == nil || s.pool == nil {
		return audit.ErrRecorderUnavailable
	}
	if err := event.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(newAuditEventPayload(event))
	if err != nil {
		return fmt.Errorf("marshal Runtime security audit event: %w", err)
	}
	claims := event.Identity.Claims()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Runtime audit append: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Runtime security audit event: %w", err)
	}
	return nil
}

func (s *Store) GetBreaker(ctx context.Context, scope breaker.Scope) (breaker.Record, error) {
	if s == nil || s.pool == nil {
		return breaker.Record{}, errors.New("PostgreSQL pool is unavailable")
	}
	if _, err := breaker.NewClosed(scope, time.Now().UTC()); err != nil {
		return breaker.Record{}, err
	}

	var record breaker.Record
	var state string
	var openedAt pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `
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
	if errors.Is(err, pgx.ErrNoRows) {
		return breaker.Record{}, ErrBreakerNotFound
	}
	if err != nil {
		return breaker.Record{}, fmt.Errorf("load circuit breaker: %w", err)
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

// CompareAndSwapBreaker persists one breaker transition. expectedVersion=0
// creates the initial CLOSED record; later calls require an exact version and
// strictly greater fencing epoch so stale workers cannot overwrite newer state.
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
		if next.Version != 1 || next.State != breaker.StateClosed {
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

	tag, err := s.pool.Exec(ctx, `
		UPDATE runtime_circuit_breakers
		SET state=$1, epoch=$2, version=$3, reason_code=$4,
			trigger_event_id=$5, opened_at=$6, recovery_approval_id=$7,
			last_recovery_evidence_ref=$8, updated_at=$9
		WHERE scope_kind=$10 AND scope_id=$11
			AND version=$12 AND epoch < $2
	`, string(next.State), next.Epoch, next.Version, next.ReasonCode,
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

var _ audit.Recorder = (*Store)(nil)
