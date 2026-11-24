package postgres_test

import (
	"context"
	"testing"
)

// Startup must not accept a v13 ledger entry as evidence that the shadow
// pointer retains its exact constraints or immutability guards.
func TestCurrentAttemptMigrationRejectsCatalogDrift(t *testing.T) {
	cases := []struct {
		name string
		ddl  string
	}{
		{"weaken generation", "ALTER TABLE runtime_current_attempts DROP CONSTRAINT runtime_current_attempts_generation_check; ALTER TABLE runtime_current_attempts ADD CONSTRAINT runtime_current_attempts_generation_check CHECK (TRUE)"},
		{"weaken epoch", "ALTER TABLE runtime_current_attempts DROP CONSTRAINT runtime_current_attempts_breaker_epoch_check; ALTER TABLE runtime_current_attempts ADD CONSTRAINT runtime_current_attempts_breaker_epoch_check CHECK (TRUE)"},
		{"missing scope reference", "ALTER TABLE runtime_current_attempts DROP CONSTRAINT runtime_current_attempts_tenant_id_run_id_attempt_id_fkey"},
		{"missing unique scope", "ALTER TABLE runtime_current_attempts DROP CONSTRAINT runtime_current_attempts_pkey"},
		{"nullable epoch", "ALTER TABLE runtime_current_attempts ALTER COLUMN breaker_epoch DROP NOT NULL"},
		{"disabled update guard", "ALTER TABLE runtime_current_attempts DISABLE TRIGGER runtime_current_attempt_no_mutation"},
		{"disabled truncate guard", "ALTER TABLE runtime_current_attempts DISABLE TRIGGER runtime_current_attempt_no_truncate"},
		{"unlogged relation", "ALTER TABLE runtime_current_attempts SET UNLOGGED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, store := newTestStore(t)
			ctx := context.Background()
			if _, err := pool.Exec(ctx, tc.ddl); err != nil {
				t.Fatalf("install catalog drift: %v", err)
			}
			if err := store.Migrate(ctx); err == nil {
				t.Fatal("previously applied v13 migration concealed catalog drift")
			}
		})
	}
}

func TestCurrentAttemptCompositeFKAndImmutableInitialGeneration(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	a, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent()
	intent.TenantID = "tenant-2"
	intent.RunIntentID = "22222222-2222-4222-8222-222222222222"
	b, err := store.AcceptIntentWithPrincipal(ctx, intent, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.GetOrCreateTemporalTurn(ctx, a.TenantID, a.RunID, a.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	// B has no pointer, so rejection must come from the composite FK, not
	// a conflicting primary key. The referenced Attempt belongs to A.
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_current_attempts
		(tenant_id,run_id,attempt_id,generation,breaker_epoch)
		VALUES ($1,$2::uuid,$3::uuid,1,1)`, b.TenantID, b.RunID, first.RunAttemptID); err == nil {
		t.Fatal("foreign tenant Attempt accepted")
	}
	for _, query := range []string{
		"UPDATE runtime_current_attempts SET generation=2",
		"UPDATE runtime_current_attempts SET breaker_epoch=2",
		"DELETE FROM runtime_current_attempts",
		"TRUNCATE runtime_current_attempts",
	} {
		if _, err := pool.Exec(ctx, query); err == nil {
			t.Fatalf("initial generation mutated: %s", query)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_current_attempts").Scan(&count); err != nil || count != 1 {
		t.Fatalf("unexpected pointer count %d: %v", count, err)
	}
}

func TestCurrentAttemptInitializationRollsBackOnPointerFailure(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION reject_test_pointer_insert() RETURNS trigger
		LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced pointer insert failure'; END$$;
		CREATE TRIGGER reject_test_pointer_insert BEFORE INSERT ON runtime_current_attempts
		FOR EACH ROW EXECUTE FUNCTION reject_test_pointer_insert()
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1); err == nil {
		t.Fatal("forced pointer failure returned success")
	}
	var attempts, current, turns int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM runtime_run_attempts),
		(SELECT count(*) FROM runtime_current_attempts), (SELECT count(*) FROM runtime_decision_turns)`).
		Scan(&attempts, &current, &turns); err != nil || attempts != 0 || current != 0 || turns != 0 {
		t.Fatalf("failed pointer transaction persisted identity: %d/%d/%d err=%v", attempts, current, turns, err)
	}
}
