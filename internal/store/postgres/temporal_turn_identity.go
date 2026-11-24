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
	ErrTemporalTurnUntrustedRun        = errors.New("Runtime Run is not bound to an immutable ACP principal")
	ErrTemporalExecutionConflict       = errors.New("different Temporal execution attempted to own an existing Runtime Run")
	ErrTemporalAttemptAuthorityMissing = errors.New("Runtime Temporal Attempt has no current authority generation")
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

	identity, err := s.bindTemporalTurn(ctx, tx, tenantID, runID, workflowID, temporalExecutionID, turnIndex)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit Runtime Temporal identity binding: %w", err)
	}
	return identity, nil
}

// bindTemporalTurn is shared by the identity-only API and the atomic
// accepted business checkpoint. Caller owns the transaction and validation.
func (s *Store) bindTemporalTurn(ctx context.Context, tx pgx.Tx, tenantID, runID, workflowID, temporalExecutionID string, turnIndex int32) (run.TemporalTurnIdentity, error) {
	var empty run.TemporalTurnIdentity
	rel, err := s.checkpointRelations()
	if err != nil {
		return empty, err
	}
	// Serialize identity writes against the canonical Run and the RUN
	// breaker transition. Replaying an existing Attempt/Turn is not an
	// authorization shortcut after cancellation or revocation. A breaker
	// that has ever changed epoch cannot silently reauthorize a stale Turn:
	// the explicit epoch-bound continuation contract is not implemented.
	var persistedStatus, breakerState string
	var breakerEpoch, breakerVersion int64
	err = tx.QueryRow(ctx, fmt.Sprintf(`
		SELECT r.status, b.state, b.epoch, b.version
		FROM %s AS r
		JOIN %s AS p
		  ON p.run_id = r.run_id AND p.tenant_id = r.tenant_id
		JOIN %s AS b
		  ON b.scope_kind='RUN' AND b.scope_id=r.run_id::text
		WHERE r.tenant_id = $1 AND r.run_id = $2::uuid
		  AND r.workflow_id = $3
		  AND r.run_intent_id IS NOT NULL
		  AND r.source_request_digest IS NOT NULL
		  AND p.snapshot_version = 'acp-principal/v1'
		FOR UPDATE OF r FOR SHARE OF b
	`, rel.runs, rel.principals, rel.breakers), tenantID, runID, workflowID).
		Scan(&persistedStatus, &breakerState, &breakerEpoch, &breakerVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, ErrTemporalTurnUntrustedRun
	}
	if err != nil {
		return empty, fmt.Errorf("load canonical Runtime Run/ACP principal and breaker: %w", err)
	}
	if (persistedStatus != string(run.StatusQueued) && persistedStatus != string(run.StatusRunning)) ||
		breakerState != "CLOSED" || breakerEpoch != 1 || breakerVersion != 1 {
		return empty, ErrTemporalTurnUntrustedRun
	}

	// Until fenced continuation exists, exactly one persisted Attempt may
	// authorize a Turn. QueryRow would silently choose an arbitrary row
	// if durable authority were inconsistent. The canonical Run lock
	// serializes supported Attempt writers, not privileged out-of-band DML.
	var attemptID, existingExecution string
	rows, err := tx.Query(ctx, fmt.Sprintf(`
		SELECT run_attempt_id::text, temporal_execution_id::text
		FROM %s
		WHERE tenant_id=$1 AND run_id=$2::uuid
		LIMIT 2
		FOR UPDATE
	`, rel.attempts), tenantID, runID)
	if err != nil {
		return empty, fmt.Errorf("read existing Runtime Temporal RunAttempt: %w", err)
	}
	attemptCount := 0
	for rows.Next() {
		attemptCount++
		if attemptCount > 1 {
			rows.Close()
			return empty, ErrTemporalExecutionConflict
		}
		if err := rows.Scan(&attemptID, &existingExecution); err != nil {
			rows.Close()
			return empty, fmt.Errorf("scan existing Runtime Temporal RunAttempt: %w", err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("read existing Runtime Temporal RunAttempt: %w", err)
	}
	var attemptGeneration int64
	if attemptCount == 0 {
		if persistedStatus != string(run.StatusQueued) && persistedStatus != string(run.StatusRunning) {
			return empty, ErrTemporalTurnUntrustedRun
		}
		attemptID = uuid.NewString()
		_, err = tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO %s
			(tenant_id, run_id, run_attempt_id, workflow_id, temporal_execution_id)
			VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)
		`, rel.attempts), tenantID, runID, attemptID, workflowID, temporalExecutionID)
		if err != nil {
			return empty, fmt.Errorf("persist Runtime Temporal RunAttempt: %w", err)
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO %s
			(tenant_id,run_id,attempt_id,generation,breaker_epoch)
			VALUES ($1,$2::uuid,$3::uuid,1,$4)
		`, rel.currentAttempts), tenantID, runID, attemptID, breakerEpoch); err != nil {
			return empty, fmt.Errorf("persist initial Runtime Attempt pointer: %w", err)
		}
		attemptGeneration = 1
	} else if existingExecution != temporalExecutionID {
		return empty, ErrTemporalExecutionConflict
	} else {
		var authorityBreakerEpoch int64
		err = tx.QueryRow(ctx, fmt.Sprintf(`
			SELECT current_attempt.generation, current_attempt.breaker_epoch
			FROM %s current_attempt
			WHERE current_attempt.tenant_id=$1 AND current_attempt.run_id=$2::uuid
			  AND current_attempt.attempt_id=$3::uuid
			FOR SHARE
		`, rel.currentAttempts), tenantID, runID, attemptID).
			Scan(&attemptGeneration, &authorityBreakerEpoch)
		if errors.Is(err, pgx.ErrNoRows) {
			return empty, ErrTemporalAttemptAuthorityMissing
		}
		if err != nil {
			return empty, fmt.Errorf("read current Runtime Temporal Attempt authority: %w", err)
		}
		if attemptGeneration < 1 || authorityBreakerEpoch != breakerEpoch {
			return empty, ErrTemporalExecutionConflict
		}
	}

	var turnID, invocationID string
	err = tx.QueryRow(ctx, fmt.Sprintf(`
		SELECT turn_id::text, invocation_id::text
		FROM %s
		WHERE tenant_id=$1 AND run_id=$2::uuid
		  AND run_attempt_id=$3::uuid AND turn_index=$4
		FOR UPDATE
	`, rel.turns), tenantID, runID, attemptID, turnIndex).Scan(&turnID, &invocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		if persistedStatus != string(run.StatusQueued) && persistedStatus != string(run.StatusRunning) {
			return empty, ErrTemporalTurnUntrustedRun
		}
		turnID = uuid.NewString()
		invocationID = turnID
		_, err = tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO %s
			(tenant_id,run_id,run_attempt_id,turn_id,invocation_id,turn_index)
			VALUES ($1,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6)
		`, rel.turns), tenantID, runID, attemptID, turnID, invocationID, turnIndex)
		if err != nil {
			return empty, fmt.Errorf("persist Runtime Decision Turn: %w", err)
		}
	} else if err != nil {
		return empty, fmt.Errorf("read existing Runtime Decision Turn: %w", err)
	}

	identity := run.TemporalTurnIdentity{
		TenantID: tenantID, RunID: runID, WorkflowID: workflowID,
		TemporalExecutionID: temporalExecutionID,
		RunAttemptID:        attemptID, TurnID: turnID,
		InvocationID: invocationID, TurnIndex: turnIndex,
		AttemptGeneration: attemptGeneration, BreakerEpoch: breakerEpoch,
	}
	if err := identity.Validate(); err != nil {
		return empty, err
	}
	return identity, nil
}
