package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/jackc/pgx/v5"
)

// LookupIntentWithPrincipal checks the same immutable binding as v2 accept
// in one committed snapshot, without inserting or locking a Run for writes.
// A v1 receipt alone cannot prove subject, policy or input equivalence.
// Absence (including foreign tenant) is uncertain; never a retry permit.
func (s *Store) LookupIntentWithPrincipal(ctx context.Context, command run.IntentStartRequest, principal run.PrincipalSnapshot) (run.IntentReceipt, error) {
	if s == nil || s.pool == nil {
		return run.IntentReceipt{}, run.ErrRepositoryUnavailable
	}
	if command.Validate() != nil || principal.Validate() != nil {
		return run.IntentReceipt{}, run.ErrInvalidRequest
	}
	input, err := run.CanonicalIntentInput(command.Input)
	if err != nil {
		return run.IntentReceipt{}, run.ErrInvalidRequest
	}
	runTable, principalTable, _, err := s.runIntentRelations()
	if err != nil {
		return run.IntentReceipt{}, err
	}
	var receipt run.IntentReceipt
	var matches bool
	err = s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT r.tenant_id, r.run_intent_id::text, r.source_request_digest,
		       r.run_id::text, r.workflow_id,
		       COALESCE(r.agent_id=$3 AND r.agent_release_id=$4 AND r.session_id=$5
		         AND r.input=$6::jsonb AND p.snapshot_version=$7 AND p.issuer_spiffe_id=$8
		         AND p.project_id=$9 AND p.subject_id=$10 AND p.actor_id=$11
		         AND p.policy_revision=$12 AND p.config_digest=$13, false)
		FROM %s r
		LEFT JOIN %s p
		  ON p.run_id=r.run_id AND p.tenant_id=r.tenant_id
		WHERE r.tenant_id=$1 AND r.run_intent_id=$2::uuid
	`, runTable, principalTable), command.TenantID, command.RunIntentID, command.AgentID, command.AgentReleaseID,
		command.SessionID, string(input), principal.Version, principal.IssuerSPIFFEID,
		principal.ProjectID, principal.SubjectID, principal.ActorID, principal.PolicyRevision,
		principal.ConfigDigest).Scan(&receipt.TenantID, &receipt.RunIntentID, &receipt.RequestDigest,
		&receipt.RunID, &receipt.WorkflowID, &matches)
	if errors.Is(err, pgx.ErrNoRows) {
		return run.IntentReceipt{}, run.ErrIntentNotFound
	}
	if err != nil {
		// Do not attach PostgreSQL diagnostics that may contain task input.
		return run.IntentReceipt{}, run.ErrRepositoryUnavailable
	}
	if !matches || receipt.TenantID != command.TenantID || receipt.RunIntentID != command.RunIntentID ||
		receipt.RequestDigest != command.RequestDigest || receipt.WorkflowID != run.ACPWorkflowPrefix+receipt.RunID {
		return run.IntentReceipt{}, run.ErrIdempotencyConflict
	}
	return receipt, nil
}
