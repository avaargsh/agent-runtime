package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetTrustedGuardExecutionAuthority returns the exact current Runtime
// Run/Attempt/Turn tuple requested by an authenticated Guard peer. The
// requested Turn ID is only a selector: it must be persisted under the
// current generation-one Attempt and be the highest persisted turn_index.
// All authority facts are read in one PostgreSQL MVCC statement.
func (s *Store) GetTrustedGuardExecutionAuthority(
	ctx context.Context, tenantID, runID, turnID string,
) (run.GuardExecutionAuthority, error) {
	var result run.GuardExecutionAuthority
	if s == nil || s.pool == nil || ctx == nil {
		return result, run.ErrRepositoryUnavailable
	}
	if tenantID == "" || len(tenantID) > 255 || !utf8.ValidString(tenantID) ||
		strings.TrimSpace(tenantID) != tenantID || strings.ContainsAny(tenantID, "\x00\r\n\t") {
		return result, run.ErrGuardExecutionAuthorityDenied
	}
	for _, value := range []string{runID, turnID} {
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return result, run.ErrGuardExecutionAuthorityDenied
		}
	}
	rel, err := s.checkpointRelations()
	if err != nil {
		return result, run.ErrRepositoryUnavailable
	}
	err = s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT r.tenant_id, r.run_id::text, r.agent_id, r.agent_release_id,
		       r.session_id, r.workflow_id, a.temporal_execution_id::text,
		       a.run_attempt_id::text, t.turn_id::text, t.invocation_id::text,
		       t.turn_index, current_attempt.generation, current_attempt.breaker_epoch,
		       r.status, b.state, b.epoch, b.version
		FROM %s r
		JOIN %s p
		  ON p.tenant_id=r.tenant_id AND p.run_id=r.run_id
		 AND p.snapshot_version='acp-principal/v1'
		JOIN %s current_attempt
		  ON current_attempt.tenant_id=r.tenant_id AND current_attempt.run_id=r.run_id
		 AND current_attempt.generation=1 AND current_attempt.breaker_epoch=1
		JOIN %s a
		  ON a.tenant_id=current_attempt.tenant_id AND a.run_id=current_attempt.run_id
		 AND a.run_attempt_id=current_attempt.attempt_id AND a.workflow_id=r.workflow_id
		JOIN %s t
		  ON t.tenant_id=a.tenant_id AND t.run_id=a.run_id
		 AND t.run_attempt_id=a.run_attempt_id AND t.turn_id=$3::uuid
		 AND t.invocation_id=t.turn_id
		JOIN %s b
		  ON b.scope_kind='RUN' AND b.scope_id=r.run_id::text
		WHERE r.tenant_id=$1 AND r.run_id=$2::uuid
		  AND r.run_intent_id IS NOT NULL AND r.source_request_digest IS NOT NULL
		  AND r.status='RUNNING'
		  AND b.state='CLOSED' AND b.epoch=current_attempt.breaker_epoch AND b.version=1
		  AND NOT EXISTS (
		    SELECT 1 FROM %s other_attempt
		    WHERE other_attempt.tenant_id=a.tenant_id AND other_attempt.run_id=a.run_id
		      AND other_attempt.run_attempt_id<>a.run_attempt_id
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM %s newer_turn
		    WHERE newer_turn.tenant_id=t.tenant_id AND newer_turn.run_id=t.run_id
		      AND newer_turn.run_attempt_id=t.run_attempt_id
		      AND newer_turn.turn_index>t.turn_index
		  )
	`, rel.runs, rel.principals, rel.currentAttempts, rel.attempts,
		rel.turns, rel.breakers, rel.attempts, rel.turns),
		tenantID, runID, turnID,
	).Scan(
		&result.TenantID, &result.RunID, &result.AgentID, &result.AgentReleaseID,
		&result.SessionID, &result.WorkflowID, &result.TemporalExecutionID,
		&result.RunAttemptID, &result.TurnID, &result.InvocationID,
		&result.TurnIndex, &result.AttemptGeneration, &result.AttemptBreakerEpoch,
		&result.Status, &result.BreakerState, &result.BreakerEpoch, &result.BreakerVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return run.GuardExecutionAuthority{}, run.ErrGuardExecutionAuthorityDenied
	}
	if err != nil {
		return run.GuardExecutionAuthority{}, run.ErrRepositoryUnavailable
	}
	result.SchemaVersion = run.GuardExecutionAuthoritySchema
	if result.Validate() != nil || result.TenantID != tenantID ||
		result.RunID != runID || result.TurnID != turnID {
		return run.GuardExecutionAuthority{}, run.ErrGuardExecutionAuthorityDenied
	}
	return result, nil
}
