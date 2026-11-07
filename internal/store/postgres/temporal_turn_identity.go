package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrTemporalTurnUntrustedRun = errors.New("Runtime Run is not bound to an immutable ACP principal")
	ErrTemporalExecutionConflict = errors.New("different Temporal execution attempted to own an existing Runtime Run")
)

// GetOrCreateTemporalTurn commits Runtime-owned RunAttempt/Turn identities
// before model or tool egress. Its Temporal execution ID must originate from
// the Temporal Server's authenticated Activity/Workflow metadata: this Store
// method does NOT prove that any caller-supplied execution ID came from Temporal.
// Until fenced continuation is implemented, a different server execution for
// the same logical Run conflicts rather than creating another Attempt.
// No public API accepts a caller-supplied Attempt, Turn or Invocation ID.
func (s *Store) GetOrCreateTemporalTurn(
	ctx context.Context, tenantID, runID, workflowID, temporalExecutionID string, turnIndex int32,
) (run.TemporalTurnIdentity, error) {
	var empty run.TemporalTurnIdentity
	if s == nil || s.pool == nil {
		return empty, run.ErrRepositoryUnavailable
	}
	runUUID, runErr := uuid.Parse(runID)
	executionUUID, execErr := uuid.Parse(temporalExecutionID)
	if runErr != nil || execErr != nil || runUUID.String() != runID ||
		executionUUID.String() != temporalExecutionID ||
		workflowID != run.ACPWorkflowPrefix+runID ||
		tenantID == "" || len(tenantID) > 255 ||
		strings.TrimSpace(tenantID) != tenantID ||
		strings.ContainsAny(tenantID, "\x00\r\n\t") ||
		turnIndex < 1 || turnIndex > 10000 {
		return empty, run.ErrInvalidRequest
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return empty, fmt.Errorf("begin Runtime Temporal identity binding: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// Serialize all execution identity writes for one canonical Run. A
	// different Temporal execution cannot win concurrently after a lost ACK.
	var persistedStatus string
	err = tx.QueryRow(ctx, `
		SELECT r.status
		FROM runs AS r
		JOIN runtime_run_principal_snapshots AS p
		  ON p.run_id = r.run_id AND p.tenant_id = r.tenant_id
		WHERE r.tenant_id = $1 AND r.run_id = $2::uuid
		  AND r.workflow_id = $3
		  AND r.run_intent_id IS NOT NULL
		  AND r.source_request_digest IS NOT NULL
		  AND p.snapshot_version = 'acp-principal/v1'
		FOR UPDATE OF r
	`, tenantID, runID, workflowID).Scan(&persistedStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, ErrTemporalTurnUntrustedRun
	}
	if err != nil {
		return empty, fmt.Errorf("load canonical Runtime Run/ACP principal: %w", err)
	}

	var attemptID, existingExecution string
	err = tx.QueryRow(ctx, `
		SELECT run_attempt_id::text, temporal_execution_id::text
		FROM runtime_run_attempts
		WHERE tenant_id=$1 AND run_id=$2::uuid
		FOR UPDATE
	`, tenantID, runID).Scan(&attemptID, &existingExecution)
	if errors.Is(err, pgx.ErrNoRows) {
		if persistedStatus != string(run.StatusQueued) && persistedStatus != string(run.StatusRunning) {
			return empty, ErrTemporalTurnUntrustedRun
		}
		attemptID = uuid.NewString()
		_, err = tx.Exec(ctx, `
			INSERT INTO runtime_run_attempts
			(tenant_id, run_id, run_attempt_id, workflow_id, temporal_execution_id)
			VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)
		`, tenantID, runID, attemptID, workflowID, temporalExecutionID)
		if err != nil {
			return empty, fmt.Errorf("persist Runtime Temporal RunAttempt: %w", err)
		}
	} else if err != nil {
		return empty, fmt.Errorf("read existing Runtime Temporal RunAttempt: %w", err)
	} else if existingExecution != temporalExecutionID {
		return empty, ErrTemporalExecutionConflict
	}

	var turnID, invocationID string
	err = tx.QueryRow(ctx, `
		SELECT turn_id::text, invocation_id::text
		FROM runtime_decision_turns
		WHERE tenant_id=$1 AND run_id=$2::uuid
		  AND run_attempt_id=$3::uuid AND turn_index=$4
		FOR UPDATE
	`, tenantID, runID, attemptID, turnIndex).Scan(&turnID, &invocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		if persistedStatus != string(run.StatusQueued) && persistedStatus != string(run.StatusRunning) {
			return empty, ErrTemporalTurnUntrustedRun
		}
		turnID = uuid.NewString()
		invocationID = turnID
		_, err = tx.Exec(ctx, `
			INSERT INTO runtime_decision_turns
			(tenant_id,run_id,run_attempt_id,turn_id,invocation_id,turn_index)
			VALUES ($1,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6)
		`, tenantID, runID, attemptID, turnID, invocationID, turnIndex)
		if err != nil {
			return empty, fmt.Errorf("persist Runtime Decision Turn: %w", err)
		}
	} else if err != nil {
		return empty, fmt.Errorf("read existing Runtime Decision Turn: %w", err)
	}

	identity := run.TemporalTurnIdentity{
		TenantID: tenantID, RunID: runID, WorkflowID: workflowID,
		TemporalExecutionID: temporalExecutionID,
		RunAttemptID: attemptID, TurnID: turnID,
		InvocationID: invocationID, TurnIndex: turnIndex,
	}
	if err := identity.Validate(); err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit Runtime Temporal identity binding: %w", err)
	}
	return identity, nil
}
