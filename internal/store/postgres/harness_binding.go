package postgres

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ acp.BindingStore = (*Store)(nil)

// LookupBinding implements the existing ACP v1 recovery/cancel read seam.
// Only a durably CONFIRMED session can be loaded or sent a best-effort
// cancellation. PREPARED, UNKNOWN and an absent row are not final absence
// and MUST NOT be used to start another session or replay a prompt.
//
// This read does not authorize an external Harness command, permission,
// protected effect or new dispatch grant. An already-cancelled Run may still
// need its confirmed Session ID to send session/cancel. Recovery eligibility
// samples the initial CLOSED breaker epoch and unambiguous Attempt together
// with historical evidence; it is not a fence against later revocation.
func (s *Store) LookupBinding(ctx context.Context, tenantID, runID string) (acp.Binding, error) {
	var none acp.Binding
	if s == nil || s.pool == nil {
		return none, run.ErrRepositoryUnavailable
	}
	id, err := uuid.Parse(runID)
	if err != nil || id.String() != runID ||
		tenantID == "" || len(tenantID) > 255 ||
		tenantID != strings.TrimSpace(tenantID) ||
		!utf8.ValidString(tenantID) ||
		strings.ContainsAny(tenantID, "\x00\r\n\t") {
		return none, acp.ErrBindingInvalid
	}
	claimTable, runTable, principalTable, attemptTable, err := s.harnessRelations()
	if err != nil {
		return none, err
	}
	relations, err := s.checkpointRelations()
	if err != nil {
		return none, err
	}
	var binding acp.Binding
	err = s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT c.tenant_id, c.run_id::text, r.status, c.attempt_id::text,
			c.harness_instance_id, c.agent_session_id, c.working_dir,
			NOT EXISTS (SELECT 1 FROM %s AS other_attempt
				WHERE other_attempt.tenant_id=r.tenant_id AND other_attempt.run_id=r.run_id
				AND other_attempt.run_attempt_id<>a.run_attempt_id)
			AND EXISTS (SELECT 1 FROM %s AS b
				WHERE b.scope_kind='RUN' AND b.scope_id=r.run_id::text
				AND b.state='CLOSED' AND b.epoch=1 AND b.version>=1)
		FROM %s AS c
		JOIN %s AS r ON r.tenant_id=c.tenant_id AND r.run_id=c.run_id
			AND r.agent_release_id=c.agent_release_id
			AND r.source_request_digest=c.request_digest
		JOIN %s AS p ON p.tenant_id=c.tenant_id AND p.run_id=c.run_id
			AND p.snapshot_version='acp-principal/v1'
			AND p.policy_revision=c.policy_revision
		JOIN %s AS a ON a.tenant_id=c.tenant_id AND a.run_id=c.run_id
			AND a.run_attempt_id=c.attempt_id AND a.workflow_id=r.workflow_id
		WHERE c.tenant_id=$1 AND c.run_id=$2::uuid
			AND c.state='CONFIRMED' AND c.agent_session_id IS NOT NULL
	`, attemptTable, relations.breakers, claimTable, runTable, principalTable, attemptTable), tenantID, runID).
		Scan(&binding.TenantID, &binding.RunID, &binding.RunStatus, &binding.AttemptID,
			&binding.HarnessInstanceID, &binding.AgentSessionID, &binding.WorkingDir, &binding.RecoveryEligible)
	if errors.Is(err, pgx.ErrNoRows) {
		return none, acp.ErrBindingInvalid
	}
	if err != nil {
		return none, fmt.Errorf("load confirmed Runtime Harness session: %w", err)
	}
	if binding.TenantID != tenantID || binding.RunID != runID ||
		binding.HarnessInstanceID == "" || len(binding.HarnessInstanceID) > 255 ||
		binding.HarnessInstanceID != strings.TrimSpace(binding.HarnessInstanceID) ||
		!utf8.ValidString(binding.HarnessInstanceID) ||
		strings.ContainsAny(binding.HarnessInstanceID, "\x00\r\n\t") ||
		binding.AgentSessionID == "" || len(binding.AgentSessionID) > 255 ||
		strings.TrimSpace(binding.AgentSessionID) != binding.AgentSessionID ||
		!utf8.ValidString(binding.AgentSessionID) ||
		strings.ContainsAny(binding.AgentSessionID, "\x00\r\n\t") ||
		!filepath.IsAbs(binding.WorkingDir) ||
		filepath.Clean(binding.WorkingDir) != binding.WorkingDir ||
		!utf8.ValidString(binding.WorkingDir) ||
		strings.ContainsRune(binding.WorkingDir, '\x00') {
		return none, acp.ErrBindingInvalid
	}
	binding.Confirmed = true
	return binding, nil
}
