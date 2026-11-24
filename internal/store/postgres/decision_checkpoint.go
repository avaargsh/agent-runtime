package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type checkpointQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type checkpointRelations struct {
	runs, principals, attempts, authorities, turns, breakers, checkpoints string
}

func (s *Store) checkpointRelations() (checkpointRelations, error) {
	_, runs, principals, attempts, err := s.harnessRelations()
	if err != nil {
		return checkpointRelations{}, run.ErrDecisionPreparationDenied
	}
	schema := s.pool.Config().ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		schema = "public"
	}
	rel := func(name string) string { return pgx.Identifier{schema, name}.Sanitize() }
	return checkpointRelations{runs, principals, attempts, rel("runtime_run_attempt_authorities"),
		rel("runtime_decision_turns"), rel("runtime_circuit_breakers"), rel("runtime_decision_checkpoints")}, nil
}

// Read the accepted business input using the pinned schema, current active
// lifecycle and closed Run breaker. The transaction variant takes row locks
// so cancellation and breaker updates cannot interleave with the commit.
func readDecisionPreparation(ctx context.Context, q checkpointQueryer, rel checkpointRelations, ref run.AcceptedDecisionRef, lock bool) (run.DecisionCheckpoint, error) {
	var raw []byte
	var p run.PrincipalSnapshot
	query := fmt.Sprintf(`
		SELECT r.input, p.snapshot_version, p.issuer_spiffe_id, p.project_id,
		       p.subject_id, p.actor_id, p.policy_revision, p.config_digest
		FROM %s r
		JOIN %s p ON p.tenant_id=r.tenant_id AND p.run_id=r.run_id
		JOIN %s b ON b.scope_kind='RUN' AND b.scope_id=r.run_id::text
		WHERE r.tenant_id=$1 AND r.run_id=$2::uuid AND r.workflow_id=$3
		  AND r.run_intent_id=$4::uuid AND r.source_request_digest=$5
		  AND r.status IN ('QUEUED','RUNNING') AND b.state='CLOSED'
	`, rel.runs, rel.principals, rel.breakers)
	if lock {
		query += " FOR UPDATE OF r FOR SHARE OF b"
	}
	err := q.QueryRow(ctx, query, ref.TenantID, ref.RunID, ref.WorkflowID, ref.RunIntentID, ref.RequestDigest).
		Scan(&raw, &p.Version, &p.IssuerSPIFFEID, &p.ProjectID, &p.SubjectID, &p.ActorID, &p.PolicyRevision, &p.ConfigDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return run.DecisionCheckpoint{}, run.ErrDecisionPreparationDenied
	}
	if err != nil {
		return run.DecisionCheckpoint{}, run.ErrRepositoryUnavailable
	}
	if p.Validate() != nil {
		return run.DecisionCheckpoint{}, run.ErrDecisionPreparationDenied
	}
	digest, err := run.DigestSREDecisionInput(raw)
	if err != nil {
		return run.DecisionCheckpoint{}, err
	}
	return run.DecisionCheckpoint{AcceptedDecisionRef: ref, InputDigest: digest,
		PolicyRevision: p.PolicyRevision, ConfigDigest: p.ConfigDigest, Phase: run.DecisionWaitingAuthority}, nil
}

// PrepareAcceptedDecision is the first business checkpoint. The caller must
// derive executionID from authenticated Temporal Activity metadata. It does
// not authorize Decision Core calls, publish capabilities or issue permits.
func (s *Store) PrepareAcceptedDecision(ctx context.Context, ref run.AcceptedDecisionRef, executionID string) (run.DecisionCheckpoint, error) {
	var empty run.DecisionCheckpoint
	execution, err := uuid.Parse(executionID)
	if ref.Validate() != nil || err != nil || execution.String() != executionID {
		return empty, run.ErrDecisionPreparationDenied
	}
	rel, err := s.checkpointRelations()
	if err != nil {
		return empty, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	checkpoint, err := readDecisionPreparation(ctx, tx, rel, ref, true)
	if err != nil {
		return empty, err
	}

	// Reuse the existing Runtime identity transaction helper, operating on
	// the same locked Run, with no second allocator for Attempt/Turn.
	bound, err := s.bindTemporalTurn(ctx, tx, ref.TenantID, ref.RunID, ref.WorkflowID, executionID, 1)
	if err != nil {
		return empty, err
	}
	checkpoint.ExecutionID = bound.TemporalExecutionID
	checkpoint.AttemptID = bound.RunAttemptID
	checkpoint.TurnID = bound.TurnID
	query := fmt.Sprintf(`
		INSERT INTO %s (run_id,tenant_id,run_intent_id,request_digest,workflow_id,
		  execution_id,attempt_id,turn_id,input_digest,policy_revision,config_digest,phase)
		VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6::uuid,$7::uuid,$8::uuid,$9,$10,$11,$12)
		ON CONFLICT (run_id) DO NOTHING
	`, rel.checkpoints)
	if _, err := tx.Exec(ctx, query, ref.RunID, ref.TenantID, ref.RunIntentID, ref.RequestDigest, ref.WorkflowID,
		checkpoint.ExecutionID, checkpoint.AttemptID, checkpoint.TurnID, checkpoint.InputDigest,
		checkpoint.PolicyRevision, checkpoint.ConfigDigest, checkpoint.Phase); err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	var persisted run.DecisionCheckpoint
	query = fmt.Sprintf(`
		SELECT tenant_id, run_id::text, workflow_id, run_intent_id::text, request_digest,
		       execution_id::text, attempt_id::text, turn_id::text, input_digest,
		       policy_revision, config_digest, phase
		FROM %s WHERE tenant_id=$1 AND run_id=$2::uuid
	`, rel.checkpoints)
	err = tx.QueryRow(ctx, query, ref.TenantID, ref.RunID).Scan(
		&persisted.TenantID, &persisted.RunID, &persisted.WorkflowID, &persisted.RunIntentID, &persisted.RequestDigest,
		&persisted.ExecutionID, &persisted.AttemptID, &persisted.TurnID, &persisted.InputDigest,
		&persisted.PolicyRevision, &persisted.ConfigDigest, &persisted.Phase)
	if err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	if persisted != checkpoint {
		return empty, run.ErrDecisionPreparationDenied
	}
	// This trusted Activity has persisted its canonical execution and
	// first business checkpoint in the same transaction. Only now may
	// Runtime advance the accepted Run to RUNNING. Replay keeps the
	// original transition timestamp; cancellation holds the same Run lock.
	tag, err := tx.Exec(ctx, fmt.Sprintf(`
		UPDATE %s SET status='RUNNING',
		  updated_at=CASE WHEN status='QUEUED' THEN clock_timestamp() ELSE updated_at END
		WHERE tenant_id=$1 AND run_id=$2::uuid AND status IN ('QUEUED','RUNNING')
	`, rel.runs), ref.TenantID, ref.RunID)
	if err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	if tag.RowsAffected() != 1 {
		return empty, run.ErrDecisionPreparationDenied
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	return persisted, nil
}

// CancelPreparedDecision is scoped to this pre-Decision Workflow only:
// there is a committed WAITING_AUTHORITY checkpoint and no external effect.
// Future post-dispatch cancellation must reconcile effect journals first.
func (s *Store) CancelPreparedDecision(ctx context.Context, ref run.AcceptedDecisionRef, executionID string) error {
	id, err := uuid.Parse(executionID)
	if ref.Validate() != nil || err != nil || id.String() != executionID {
		return run.ErrDecisionPreparationDenied
	}
	rel, err := s.checkpointRelations()
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, fmt.Sprintf(`
		UPDATE %s r SET status='CANCELLED',
		  updated_at=CASE WHEN r.status='RUNNING' THEN clock_timestamp() ELSE r.updated_at END
		FROM %s c
		WHERE r.tenant_id=$1 AND r.run_id=$2::uuid AND r.workflow_id=$3
		  AND r.run_intent_id=$4::uuid AND r.source_request_digest=$5
		  AND r.status IN ('RUNNING','CANCELLED')
		  AND c.tenant_id=r.tenant_id AND c.run_id=r.run_id
		  AND c.run_intent_id=r.run_intent_id AND c.request_digest=r.source_request_digest
		  AND c.workflow_id=r.workflow_id AND c.execution_id=$6::uuid
		  AND c.phase='WAITING_AUTHORITY'
	`, rel.runs, rel.checkpoints), ref.TenantID, ref.RunID, ref.WorkflowID, ref.RunIntentID, ref.RequestDigest, executionID)
	if err != nil {
		return run.ErrRepositoryUnavailable
	}
	if tag.RowsAffected() != 1 {
		return run.ErrDecisionPreparationDenied
	}
	return nil
}
