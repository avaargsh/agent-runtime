package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetDecisionAuthority independently checks the committed first business
// checkpoint, canonical Attempt/Turn, accepted principal and current Run
// breaker in one statement. No caller supplied context or raw input leaves
// this boundary. The caller must authenticate the Decision workload first.
func (s *Store) GetDecisionAuthority(ctx context.Context, tenant, runID, invocationID string) (run.DecisionAuthority, error) {
	var empty run.DecisionAuthority
	if s == nil || s.pool == nil {
		return empty, run.ErrRepositoryUnavailable
	}
	for _, value := range []string{runID, invocationID} {
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return empty, run.ErrDecisionPreparationDenied
		}
	}
	if tenant == "" || len(tenant) > 255 {
		return empty, run.ErrDecisionPreparationDenied
	}
	rel, err := s.checkpointRelations()
	if err != nil {
		return empty, err
	}
	return readDecisionAuthority(ctx, s.pool, rel, tenant, runID, invocationID, false)
}

// The acceptance transaction locks the exact active Run and breaker rows;
// both cancellation and breaker transitions must wait for the local CAS.
// Reject already-visible ambiguous Attempt identities until explicit fenced
// continuation exists. Supported Attempt writers use the canonical Run lock;
// this snapshot check is not a fence against privileged out-of-band DML.
func readDecisionAuthority(ctx context.Context, q checkpointQueryer, rel checkpointRelations, tenant, runID, invocationID string, lock bool) (run.DecisionAuthority, error) {
	var empty run.DecisionAuthority
	var a run.DecisionAuthority
	var principal run.PrincipalSnapshot
	var input []byte
	query := fmt.Sprintf(`
		SELECT r.tenant_id, r.run_id::text, r.run_intent_id::text, r.source_request_digest,
		       r.workflow_id, c.execution_id::text, c.attempt_id::text, c.turn_id::text,
		       t.invocation_id::text, r.agent_id, r.agent_release_id, r.session_id,
		       p.project_id, p.subject_id, p.actor_id, p.policy_revision, p.config_digest,
		       c.input_digest, c.phase, r.status, b.state, b.epoch, b.version,
		       p.snapshot_version, p.issuer_spiffe_id, r.input
		FROM %s r
		JOIN %s p ON p.tenant_id=r.tenant_id AND p.run_id=r.run_id
		JOIN %s c ON c.tenant_id=r.tenant_id AND c.run_id=r.run_id
		  AND c.run_intent_id=r.run_intent_id AND c.request_digest=r.source_request_digest
		  AND c.workflow_id=r.workflow_id AND c.policy_revision=p.policy_revision
		  AND c.config_digest=p.config_digest
		JOIN %s a ON a.tenant_id=r.tenant_id AND a.run_id=r.run_id
		  AND a.run_attempt_id=c.attempt_id AND a.temporal_execution_id=c.execution_id
		  AND a.workflow_id=r.workflow_id
		JOIN %s t ON t.tenant_id=r.tenant_id AND t.run_id=r.run_id
		  AND t.run_attempt_id=a.run_attempt_id AND t.turn_id=c.turn_id
		  AND t.invocation_id=t.turn_id AND t.turn_index=1
		JOIN %s b ON b.scope_kind='RUN' AND b.scope_id=r.run_id::text
		JOIN %s aa ON aa.tenant_id=r.tenant_id AND aa.run_id=r.run_id
		  AND aa.attempt_id=a.run_attempt_id
		  AND aa.generation=1 AND aa.breaker_epoch=b.epoch
		WHERE r.tenant_id=$1 AND r.run_id=$2::uuid AND t.invocation_id=$3::uuid
		  AND r.status='RUNNING' AND b.state='CLOSED'
		  -- No explicit generation transition exists: all v13 current
		  -- Attempts require the original RUN breaker version. Match the
		  -- Temporal Turn and trusted Guard admission fences.
		  AND b.version=1
		  AND c.phase='WAITING_AUTHORITY' AND p.actor_id=p.subject_id
		  AND NOT EXISTS (
		    SELECT 1 FROM %s AS other_attempt
		    WHERE other_attempt.tenant_id=r.tenant_id AND other_attempt.run_id=r.run_id
		      AND other_attempt.run_attempt_id<>a.run_attempt_id
		  )
	`, rel.runs, rel.principals, rel.checkpoints, rel.attempts, rel.turns, rel.breakers, rel.currentAttempts, rel.attempts)
	if lock {
		query += " FOR UPDATE OF r FOR SHARE OF b"
	}
	err := q.QueryRow(ctx, query, tenant, runID, invocationID).Scan(
		&a.TenantID, &a.RunID, &a.RunIntentID, &a.RequestDigest, &a.WorkflowID,
		&a.ExecutionID, &a.AttemptID, &a.TurnID, &a.InvocationID, &a.AgentID, &a.AgentReleaseID, &a.SessionID,
		&a.ProjectID, &a.SubjectID, &a.ActorID, &a.PolicyRevision, &a.ConfigDigest,
		&a.InputDigest, &a.Phase, &a.Status, &a.BreakerState, &a.BreakerEpoch, &a.BreakerVersion,
		&principal.Version, &principal.IssuerSPIFFEID, &input)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, run.ErrDecisionPreparationDenied
	}
	if err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	principal.ProjectID, principal.SubjectID, principal.ActorID = a.ProjectID, a.SubjectID, a.ActorID
	principal.PolicyRevision, principal.ConfigDigest = a.PolicyRevision, a.ConfigDigest
	a.SchemaVersion = run.DecisionAuthoritySchema
	digest, err := run.DigestSREDecisionInput(input)
	if err != nil || digest != a.InputDigest || principal.Validate() != nil || a.Validate() != nil ||
		a.TenantID != tenant || a.RunID != runID || a.InvocationID != invocationID {
		return empty, run.ErrRepositoryUnavailable
	}
	return a, nil
}
