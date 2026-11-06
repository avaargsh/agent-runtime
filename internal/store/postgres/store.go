package postgres

import (
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.up.sql
var migrationFiles embed.FS

const (
	initialSchemaVersion int64 = 1
	migrationLockKey     int64 = 0x41525452554E
	runStartEventType          = "RUN_START_REQUESTED"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Migrate(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL pool is unavailable")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("lock schema migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS runtime_schema_migrations (
			version BIGINT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create schema migration ledger: %w", err)
	}

	var applied bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM runtime_schema_migrations WHERE version = $1)",
		initialSchemaVersion,
	).Scan(&applied); err != nil {
		return fmt.Errorf("read schema migration ledger: %w", err)
	}
	if !applied {
		script, err := migrationFiles.ReadFile("migrations/0001_runtime_runs.up.sql")
		if err != nil {
			return fmt.Errorf("read initial schema migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("apply initial schema migration: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO runtime_schema_migrations (version) VALUES ($1)",
			initialSchemaVersion,
		); err != nil {
			return fmt.Errorf("record initial schema migration: %w", err)
		}
	}

	// Migration v2 is additive and supports already-populated development DBs.
	var v2Applied bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM runtime_schema_migrations WHERE version = 2)",
	).Scan(&v2Applied); err != nil {
		return fmt.Errorf("read ACP binding migration ledger: %w", err)
	}
	if !v2Applied {
		script, err := migrationFiles.ReadFile("migrations/0002_acp_run_intent.up.sql")
		if err != nil {
			return fmt.Errorf("read ACP migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("apply ACP migration: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO runtime_schema_migrations (version) VALUES (2)",
		); err != nil {
			return fmt.Errorf("record ACP migration: %w", err)
		}
	}
	// Migration v3 adds Runtime-owned TurnIntent / Proposal state and its
	// append-only event outbox under the same advisory-locked transaction.
	var v3Applied bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM runtime_schema_migrations WHERE version = 3)",
	).Scan(&v3Applied); err != nil {
		return fmt.Errorf("read Runtime Proposal migration ledger: %w", err)
	}
	if !v3Applied {
		script, err := migrationFiles.ReadFile("migrations/0003_runtime_proposals.up.sql")
		if err != nil {
			return fmt.Errorf("read Runtime Proposal migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("apply Runtime Proposal migration: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO runtime_schema_migrations (version) VALUES (3)",
		); err != nil {
			return fmt.Errorf("record Runtime Proposal migration: %w", err)
		}
	}
	// Migration v4 adds the append-only Runtime security audit archive and
	// durable versioned circuit-breaker state. It remains separate from the
	// execution outbox, which is a delivery mechanism.
	var v4Applied bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM runtime_schema_migrations WHERE version = 4)",
	).Scan(&v4Applied); err != nil {
		return fmt.Errorf("read Runtime security migration ledger: %w", err)
	}
	if !v4Applied {
		script, err := migrationFiles.ReadFile("migrations/0004_runtime_security.up.sql")
		if err != nil {
			return fmt.Errorf("read Runtime security migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("apply Runtime security migration: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO runtime_schema_migrations (version) VALUES (4)",
		); err != nil {
			return fmt.Errorf("record Runtime security migration: %w", err)
		}
	}
	// Migration v5 installs TRUNCATE protection for previously migrated v4
	// databases. The original v4 script must remain unchanged.
	var v5Applied bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM runtime_schema_migrations WHERE version = 5)",
	).Scan(&v5Applied); err != nil {
		return fmt.Errorf("read Runtime audit TRUNCATE migration ledger: %w", err)
	}
	if !v5Applied {
		script, err := migrationFiles.ReadFile("migrations/0005_runtime_security_audit_truncate.up.sql")
		if err != nil {
			return fmt.Errorf("read Runtime audit TRUNCATE migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("apply Runtime audit TRUNCATE migration: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO runtime_schema_migrations (version) VALUES (5)",
		); err != nil {
			return fmt.Errorf("record Runtime audit TRUNCATE migration: %w", err)
		}
	}
	// V6 adds the immutable ACP Harness session creation claim/UNKNOWN fence.
	// Never rewrite already-applied schema migrations.
	var v6Applied bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM runtime_schema_migrations WHERE version = 6)",
	).Scan(&v6Applied); err != nil {
		return fmt.Errorf("read Runtime Harness migration ledger: %w", err)
	}
	if !v6Applied {
		script, err := migrationFiles.ReadFile("migrations/0006_runtime_harness_session_claims.up.sql")
		if err != nil {
			return fmt.Errorf("read Runtime Harness migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("apply Runtime Harness migration: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO runtime_schema_migrations (version) VALUES (6)",
		); err != nil {
			return fmt.Errorf("record Runtime Harness migration: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

func (s *Store) CreateOrGet(ctx context.Context, candidate run.Run) (run.Run, bool, error) {
	if s == nil || s.pool == nil {
		return run.Run{}, false, errors.New("PostgreSQL pool is unavailable")
	}
	if err := validateCandidate(candidate); err != nil {
		return run.Run{}, false, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return run.Run{}, false, fmt.Errorf("begin Run transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	inserted, err := scanRun(tx.QueryRow(ctx, `
		INSERT INTO runs (
			run_id, tenant_id, agent_id, agent_release_id, session_id,
			idempotency_key, request_digest, workflow_id, status, input,
			created_at, updated_at
		)
		VALUES (
			$1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $11
		)
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
		RETURNING
			run_id::text, tenant_id, agent_id, agent_release_id, session_id,
			idempotency_key, request_digest, workflow_id, status, input,
			created_at, updated_at
	`,
		candidate.ID,
		candidate.TenantID,
		candidate.AgentID,
		candidate.AgentReleaseID,
		candidate.SessionID,
		candidate.IdempotencyKey,
		candidate.RequestDigest,
		candidate.WorkflowID,
		string(candidate.Status),
		string(candidate.Input),
		candidate.CreatedAt,
	))
	if err == nil {
		payload, marshalErr := json.Marshal(struct {
			RunID      string `json:"run_id"`
			WorkflowID string `json:"workflow_id"`
		}{RunID: inserted.ID, WorkflowID: inserted.WorkflowID})
		if marshalErr != nil {
			return run.Run{}, false, fmt.Errorf("marshal Run start outbox payload: %w", marshalErr)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO runtime_outbox (
				outbox_id, tenant_id, aggregate_id, event_type, payload,
				created_at, available_at
			)
			VALUES ($1::uuid, $2, $3::uuid, $4, $5::jsonb, $6, $6)
		`,
			uuid.NewString(),
			inserted.TenantID,
			inserted.ID,
			runStartEventType,
			string(payload),
			inserted.CreatedAt,
		); err != nil {
			return run.Run{}, false, fmt.Errorf("insert Run start outbox record: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return run.Run{}, false, fmt.Errorf("commit Run and start outbox: %w", err)
		}
		return inserted, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return run.Run{}, false, fmt.Errorf("insert Run: %w", err)
	}

	existing, err := scanRun(tx.QueryRow(ctx, `
		SELECT
			run_id::text, tenant_id, agent_id, agent_release_id, session_id,
			idempotency_key, request_digest, workflow_id, status, input,
			created_at, updated_at
		FROM runs
		WHERE tenant_id = $1 AND idempotency_key = $2
		FOR UPDATE
	`, candidate.TenantID, candidate.IdempotencyKey))
	if err != nil {
		return run.Run{}, false, fmt.Errorf("load existing idempotent Run: %w", err)
	}
	if existing.RequestDigest != candidate.RequestDigest {
		return run.Run{}, false, run.ErrIdempotencyConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return run.Run{}, false, fmt.Errorf("commit idempotent Run lookup: %w", err)
	}
	return existing, false, nil
}

func validateCandidate(candidate run.Run) error {
	if _, err := uuid.Parse(candidate.ID); err != nil {
		return fmt.Errorf("%w: Run ID must be a UUID", run.ErrInvalidRequest)
	}
	if candidate.WorkflowID != run.WorkflowIDPrefix+candidate.ID {
		return fmt.Errorf("%w: Workflow ID must be derived from Run ID", run.ErrInvalidRequest)
	}
	if candidate.TenantID == "" || candidate.AgentID == "" ||
		candidate.AgentReleaseID == "" || candidate.SessionID == "" ||
		candidate.IdempotencyKey == "" || candidate.Status != run.StatusQueued {
		return fmt.Errorf("%w: incomplete Run candidate", run.ErrInvalidRequest)
	}
	if len(candidate.RequestDigest) != 64 {
		return fmt.Errorf("%w: request digest must be a SHA-256 hex digest", run.ErrInvalidRequest)
	}
	if _, err := hex.DecodeString(candidate.RequestDigest); err != nil {
		return fmt.Errorf("%w: request digest must be a SHA-256 hex digest", run.ErrInvalidRequest)
	}
	var input map[string]any
	if err := json.Unmarshal(candidate.Input, &input); err != nil || input == nil {
		return fmt.Errorf("%w: Run input must be a JSON object", run.ErrInvalidRequest)
	}
	if candidate.CreatedAt.IsZero() {
		return fmt.Errorf("%w: Run creation timestamp is required", run.ErrInvalidRequest)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRun(row rowScanner) (run.Run, error) {
	var result run.Run
	var status string
	var input []byte
	if err := row.Scan(
		&result.ID,
		&result.TenantID,
		&result.AgentID,
		&result.AgentReleaseID,
		&result.SessionID,
		&result.IdempotencyKey,
		&result.RequestDigest,
		&result.WorkflowID,
		&status,
		&input,
		&result.CreatedAt,
		&result.UpdatedAt,
	); err != nil {
		return run.Run{}, err
	}
	result.Status = run.Status(status)
	result.Input = append(json.RawMessage(nil), input...)
	return result, nil
}

var _ run.Repository = (*Store)(nil)
