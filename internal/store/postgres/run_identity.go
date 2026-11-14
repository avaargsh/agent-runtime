package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetRunIdentity resolves a Run by its canonical ID alone and returns the
// persisted tenant/Agent binding. Callers must compare untrusted Workflow
// correlation fields with this record before using them for authorization.
func (s *Store) GetRunIdentity(ctx context.Context, runID string) (run.Identity, error) {
	if s == nil || s.pool == nil {
		return run.Identity{}, errors.New("PostgreSQL pool is unavailable")
	}
	if _, err := uuid.Parse(runID); err != nil {
		return run.Identity{}, fmt.Errorf("%w: malformed Run ID", run.ErrInvalidRequest)
	}

	var identity run.Identity
	err := s.pool.QueryRow(ctx, `
		SELECT run_id::text, tenant_id, agent_id, agent_release_id, session_id
		FROM runs
		WHERE run_id = $1::uuid
	`, runID).Scan(
		&identity.RunID,
		&identity.TenantID,
		&identity.AgentID,
		&identity.AgentReleaseID,
		&identity.SessionID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return run.Identity{}, fmt.Errorf("%w: %s", run.ErrRunNotFound, runID)
	}
	if err != nil {
		return run.Identity{}, fmt.Errorf("load canonical Run identity: %w", err)
	}
	if err := identity.Validate(); err != nil {
		return run.Identity{}, fmt.Errorf("stored Run identity is invalid: %w", err)
	}
	return identity, nil
}
