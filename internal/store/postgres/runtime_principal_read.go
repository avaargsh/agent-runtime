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

var ErrRunPrincipalSnapshotNotFound = errors.New("trusted Runtime Run principal snapshot not found")

// GetRunPrincipalSnapshot reads only the immutable, tenant-bound ACP principal
// accepted with the canonical Runtime Run. Workflow or plugin-supplied fields
// cannot substitute for this record. Absence must fail closed before egress.
func (s *Store) GetRunPrincipalSnapshot(ctx context.Context, tenantID, runID string) (run.PrincipalSnapshot, error) {
	if s == nil || s.pool == nil {
		return run.PrincipalSnapshot{}, errors.New("Runtime PostgreSQL store unavailable")
	}
	if _, err := uuid.Parse(runID); err != nil || tenantID == "" ||
		tenantID != strings.TrimSpace(tenantID) || len(tenantID) > 255 ||
		strings.ContainsAny(tenantID, "\x00\r\n\t") {
		return run.PrincipalSnapshot{}, run.ErrInvalidRequest
	}
	var snapshot run.PrincipalSnapshot
	err := s.pool.QueryRow(ctx, `
		SELECT p.snapshot_version, p.issuer_spiffe_id, p.project_id,
		       p.subject_id, p.actor_id, p.policy_revision, p.config_digest
		FROM runtime_run_principal_snapshots AS p
		JOIN runs AS r ON r.run_id = p.run_id AND r.tenant_id = p.tenant_id
		WHERE p.run_id = $1::uuid AND p.tenant_id = $2
		  AND r.run_intent_id IS NOT NULL
		  AND r.source_request_digest IS NOT NULL
		  AND r.workflow_id = 'agent-run/v1/' || r.run_id::text
	`, runID, tenantID).Scan(
		&snapshot.Version, &snapshot.IssuerSPIFFEID, &snapshot.ProjectID,
		&snapshot.SubjectID, &snapshot.ActorID, &snapshot.PolicyRevision,
		&snapshot.ConfigDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return run.PrincipalSnapshot{}, ErrRunPrincipalSnapshotNotFound
	}
	if err != nil {
		return run.PrincipalSnapshot{}, fmt.Errorf("resolve immutable Run principal snapshot: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return run.PrincipalSnapshot{}, fmt.Errorf("stored Run principal snapshot is invalid: %w", err)
	}
	return snapshot, nil
}
