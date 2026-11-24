package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
)

func authorityMigrationIntent() run.IntentStartRequest {
	return testIntent()
}

func acceptAuthorityMigrationRun(t *testing.T, store *postgres.Store, intentID string) run.AcceptedIntentReceipt {
	t.Helper()
	intent := authorityMigrationIntent()
	intent.RunIntentID = intentID
	receipt, err := store.AcceptIntentWithPrincipal(context.Background(), intent, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func seedAuthorityMigrationAttempt(t *testing.T, pool *pgxpool.Pool, receipt run.AcceptedIntentReceipt, executionID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO runtime_run_attempts
		(tenant_id, run_id, run_attempt_id, workflow_id, temporal_execution_id)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)
	`, receipt.TenantID, receipt.RunID, uuid.NewString(), receipt.WorkflowID, executionID); err != nil {
		t.Fatalf("seed v12 Attempt: %v", err)
	}
}

// Migration v13 must not infer a current Attempt from row order or timestamps.
// It backfills only one active Attempt protected by the untouched initial
// breaker; ambiguous, terminal, revoked and missing-breaker history stays inert.
func TestCurrentAttemptAuthorityMigrationBackfillsOnlyUnambiguousInitialAttempts(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	unique := acceptAuthorityMigrationRun(t, store, uuid.NewString())
	ambiguous := acceptAuthorityMigrationRun(t, store, uuid.NewString())
	revoked := acceptAuthorityMigrationRun(t, store, uuid.NewString())
	terminal := acceptAuthorityMigrationRun(t, store, uuid.NewString())
	missingBreaker := acceptAuthorityMigrationRun(t, store, uuid.NewString())

	// Recreate the v12 schema boundary so the test exercises the real v13
	// migration backfill rather than the live generation-1 writer.
	for _, statement := range []string{
		"DROP TABLE runtime_run_attempt_authorities CASCADE",
		"DROP FUNCTION enforce_runtime_run_attempt_authority_insert()",
		"DROP FUNCTION reject_runtime_run_attempt_authority_mutation()",
		"ALTER TABLE runtime_run_attempts DROP CONSTRAINT runtime_run_attempt_authority_identity_unique",
		"DELETE FROM runtime_schema_migrations WHERE version=13",
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("reset v13 migration state (%s): %v", statement, err)
		}
	}

	seedAuthorityMigrationAttempt(t, pool, unique, firstTemporalExecutionID)
	seedAuthorityMigrationAttempt(t, pool, ambiguous, firstTemporalExecutionID)
	seedAuthorityMigrationAttempt(t, pool, ambiguous, secondTemporalExecutionID)
	seedAuthorityMigrationAttempt(t, pool, revoked, firstTemporalExecutionID)
	seedAuthorityMigrationAttempt(t, pool, terminal, firstTemporalExecutionID)
	seedAuthorityMigrationAttempt(t, pool, missingBreaker, firstTemporalExecutionID)

	breakerRecord, err := store.GetRunBreaker(ctx, revoked.TenantID, revoked.RunID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := breakerRecord.Trip("TEST_REVOKED", "authority-migration-revoked", breakerRecord.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, breakerRecord.Version, opened); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='CANCELLED' WHERE tenant_id=$1 AND run_id=$2::uuid", terminal.TenantID, terminal.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM runtime_circuit_breakers WHERE scope_kind='RUN' AND scope_id=$1", missingBreaker.RunID); err != nil {
		t.Fatal(err)
	}

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("apply v13 migration: %v", err)
	}

	var generation, breakerEpoch int64
	var attemptID, executionID string
	if err := pool.QueryRow(ctx, `
		SELECT generation, run_attempt_id::text, temporal_execution_id::text, breaker_epoch
		FROM runtime_run_attempt_authorities WHERE tenant_id=$1 AND run_id=$2::uuid
	`, unique.TenantID, unique.RunID).Scan(&generation, &attemptID, &executionID, &breakerEpoch); err != nil {
		t.Fatalf("unique initial Attempt was not backfilled: %v", err)
	}
	if generation != 1 || attemptID == "" || executionID != firstTemporalExecutionID || breakerEpoch != 1 {
		t.Fatalf("wrong backfilled authority: generation=%d attempt=%s execution=%s epoch=%d", generation, attemptID, executionID, breakerEpoch)
	}

	for name, receipt := range map[string]run.AcceptedIntentReceipt{
		"ambiguous": ambiguous, "revoked": revoked, "terminal": terminal, "missing-breaker": missingBreaker,
	} {
		var count int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM runtime_run_attempt_authorities
			WHERE tenant_id=$1 AND run_id=$2::uuid
		`, receipt.TenantID, receipt.RunID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("%s history received %d inferred authority rows", name, count)
		}
	}
	var attempts int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_run_attempts WHERE tenant_id=$1 AND run_id=$2::uuid
	`, ambiguous.TenantID, ambiguous.RunID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("migration rewrote ambiguous Attempt history: count=%d", attempts)
	}
}

// The generation ledger is append-only. The first generation cannot be
// rewritten, deleted or truncated, and a second generation cannot reuse the
// same breaker epoch.
func TestCurrentAttemptAuthorityLedgerIsImmutableAndGenerationFenced(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"UPDATE runtime_run_attempt_authorities SET generation=2 WHERE tenant_id=$1 AND run_id=$2::uuid",
		"DELETE FROM runtime_run_attempt_authorities WHERE tenant_id=$1 AND run_id=$2::uuid",
	} {
		if _, err := pool.Exec(ctx, statement, receipt.TenantID, receipt.RunID); err == nil {
			t.Fatalf("immutable Attempt authority mutation succeeded: %s", statement)
		}
	}
	if _, err := pool.Exec(ctx, "TRUNCATE runtime_run_attempt_authorities"); err == nil {
		t.Fatal("Attempt authority TRUNCATE succeeded")
	}

	// A distinct immutable Attempt cannot become generation 2 under the
	// unchanged epoch 1. Continuation requires a newer, explicitly recovered
	// breaker epoch and is not implemented by this slice.
	secondAttempt := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)
	`, receipt.TenantID, receipt.RunID, secondAttempt, receipt.WorkflowID, secondTemporalExecutionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime_run_attempt_authorities
		(tenant_id,run_id,generation,run_attempt_id,temporal_execution_id,breaker_epoch)
		VALUES ($1,$2::uuid,2,$3::uuid,$4::uuid,1)
	`, receipt.TenantID, receipt.RunID, secondAttempt, secondTemporalExecutionID); err == nil {
		t.Fatal("new Attempt authority reused the original breaker epoch")
	}
	if identity.AttemptGeneration != 1 || identity.BreakerEpoch != 1 {
		t.Fatalf("returned identity omitted generation fence: %+v", identity)
	}
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_run_attempt_authorities
		WHERE tenant_id=$1 AND run_id=$2::uuid
	`, receipt.TenantID, receipt.RunID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rejected generation advanced ledger: rows=%d", count)
	}
	_ = time.Second
}
