package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// GetGuardRunSafetySnapshot reads the canonical tenant-owned Run and its
// versioned RUN breaker in one PostgreSQL MVCC statement. A missing or
// malformed breaker fails closed; this never returns a Guard authorization.
//
// The consuming Guard must still independently authenticate Runtime and
// verify Decision, Plan, Step, capability and current policy with the owning
// authorities. This read cannot atomically fence a later breaker transition.
func (s *Store) GetGuardRunSafetySnapshot(
	ctx context.Context, tenantID, runID string,
) (run.GuardRunSafetySnapshot, error) {
	return s.guardRunSnapshot(ctx, tenantID, runID, false)
}

// GetTrustedGuardRunSafetySnapshot is the network authority projection. It
// accepts only ACP principal-bound Runs, never legacy diagnostic rows.
func (s *Store) GetTrustedGuardRunSafetySnapshot(ctx context.Context, tenantID, runID string) (run.GuardRunSafetySnapshot, error) {
	return s.guardRunSnapshot(ctx, tenantID, runID, true)
}

func (s *Store) guardRunSnapshot(ctx context.Context, tenantID, runID string, requirePrincipal bool) (run.GuardRunSafetySnapshot, error) {
	var result run.GuardRunSafetySnapshot
	if s == nil || s.pool == nil {
		return result, errors.New("Runtime Run authority database unavailable")
	}
	if tenantID == "" || len(tenantID) > 255 ||
		strings.TrimSpace(tenantID) != tenantID || strings.ContainsAny(tenantID, "\x00\r\n\t") {
		return result, fmt.Errorf("%w: invalid tenant scope", run.ErrInvalidRequest)
	}
	canonical, err := uuid.Parse(runID)
	if err != nil {
		return result, fmt.Errorf("%w: malformed Run ID", run.ErrInvalidRequest)
	}

	_, runs, principals, _, err := s.harnessRelations()
	if err != nil {
		return result, err
	}
	schema := s.pool.Config().ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		schema = "public"
	}
	breakers := pgx.Identifier{schema, "runtime_circuit_breakers"}.Sanitize()
	var workflowID string
	var acpBound, principalBound bool
	var breakerState pgtype.Text
	var breakerEpoch, breakerVersion pgtype.Int8
	err = s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT r.run_id::text, r.tenant_id, r.agent_id,
			r.agent_release_id, r.session_id, r.workflow_id,
			(r.run_intent_id IS NOT NULL), r.status,
			(p.run_id IS NOT NULL AND p.snapshot_version='acp-principal/v1'),
			b.state, b.epoch, b.version
		FROM %s r
		LEFT JOIN %s p ON p.tenant_id=r.tenant_id AND p.run_id=r.run_id
		LEFT JOIN %s b
		  ON b.scope_kind='RUN' AND b.scope_id=r.run_id::text
		WHERE r.tenant_id=$1 AND r.run_id=$2::uuid
	`, runs, principals, breakers), tenantID, canonical.String()).Scan(
		&result.Identity.RunID, &result.Identity.TenantID,
		&result.Identity.AgentID, &result.Identity.AgentReleaseID,
		&result.Identity.SessionID, &workflowID, &acpBound, &result.Status, &principalBound,
		&breakerState, &breakerEpoch, &breakerVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return run.GuardRunSafetySnapshot{}, run.ErrRunNotFound
	}
	if err != nil {
		return run.GuardRunSafetySnapshot{}, fmt.Errorf("load tenant-bound Run safety snapshot: %w", err)
	}
	if requirePrincipal && (!acpBound || !principalBound) {
		return run.GuardRunSafetySnapshot{}, run.ErrRunNotFound
	}
	if err := result.Identity.Validate(); err != nil {
		return run.GuardRunSafetySnapshot{}, fmt.Errorf("persisted Run identity invalid: %w", err)
	}
	// A persisted ACP RunIntent owns the versioned Workflow namespace. Do not
	// accept either prefix indiscriminately: that would hide corrupt bindings.
	expectedWorkflowID := run.WorkflowIDPrefix + result.Identity.RunID
	if acpBound {
		expectedWorkflowID = run.ACPWorkflowPrefix + result.Identity.RunID
	}
	if result.Identity.TenantID != tenantID ||
		result.Identity.RunID != canonical.String() ||
		workflowID != expectedWorkflowID {
		return run.GuardRunSafetySnapshot{}, fmt.Errorf("%w: persisted Run/workflow binding inconsistent", run.ErrInvalidIdentity)
	}
	switch result.Status {
	case run.StatusQueued, run.StatusRunning, run.StatusSucceeded, run.StatusFailed, run.StatusCancelled:
	default:
		return run.GuardRunSafetySnapshot{}, fmt.Errorf("%w: unknown persisted Run status", run.ErrInvalidIdentity)
	}
	if !breakerState.Valid || !breakerEpoch.Valid || !breakerVersion.Valid {
		return run.GuardRunSafetySnapshot{}, ErrBreakerNotFound
	}
	if breakerEpoch.Int64 < 1 || breakerVersion.Int64 < 1 {
		return run.GuardRunSafetySnapshot{}, fmt.Errorf("%w: invalid Run breaker fencing version", ErrBreakerNotFound)
	}
	switch breakerState.String {
	case "CLOSED", "OPEN", "HALF_OPEN":
	default:
		return run.GuardRunSafetySnapshot{}, fmt.Errorf("%w: unrecognized Run breaker state", ErrBreakerNotFound)
	}
	result.BreakerState = breakerState.String
	result.BreakerEpoch = uint64(breakerEpoch.Int64)
	result.BreakerVersion = uint64(breakerVersion.Int64)
	return result, nil
}
