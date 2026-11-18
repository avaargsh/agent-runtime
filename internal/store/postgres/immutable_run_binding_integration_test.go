package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestAcceptedRunBindingCannotBeChangedBeforeExecution(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command, principal := testIntent(), trustedSnapshot()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"input", "UPDATE runs SET input='{\"message\":\"tampered\"}'::jsonb WHERE run_id=$1::uuid"},
		{"agent", "UPDATE runs SET agent_id='other-agent' WHERE run_id=$1::uuid"},
		{"release", "UPDATE runs SET agent_release_id='other-release' WHERE run_id=$1::uuid"},
		{"session", "UPDATE runs SET session_id='other-session' WHERE run_id=$1::uuid"},
		{"digest pair", "UPDATE runs SET request_digest=repeat('b',64), source_request_digest='sha256:'||repeat('b',64) WHERE run_id=$1::uuid"},
		{"idempotency key", "UPDATE runs SET idempotency_key='other-key' WHERE run_id=$1::uuid"},
		{"creation timestamp", "UPDATE runs SET created_at=created_at-interval '1 second' WHERE run_id=$1::uuid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, tc.sql, receipt.RunID)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "runs_acp_binding_immutable" {
				t.Fatalf("accepted binding mutation was not rejected by the database fence: %v", err)
			}
		})
	}
	// Lifecycle transitions remain legal; the accepted binding is not the
	// mutable execution state.
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='RUNNING', updated_at=clock_timestamp() WHERE run_id=$1::uuid", receipt.RunID); err != nil {
		t.Fatalf("valid lifecycle transition blocked: %v", err)
	}
	got, err := store.LookupIntentWithPrincipal(ctx, command, principal)
	if err != nil || got.RunID != receipt.RunID || got.Created {
		t.Fatalf("original accepted execution binding changed: %+v %v", got, err)
	}
}

func TestImmutableRunBindingMigrationRejectsDisabledTrigger(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "ALTER TABLE runs DISABLE TRIGGER runs_acp_binding_immutable"); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err == nil {
		t.Fatal("applied ledger hid disabled immutable Run binding trigger")
	}
}

func TestImmutableRunBindingMigrationRejectsNarrowedTrigger(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	for _, sql := range []string{
		"DROP TRIGGER runs_acp_binding_immutable ON runs",
		"CREATE TRIGGER runs_acp_binding_immutable BEFORE UPDATE OF input OR DELETE ON runs FOR EACH ROW EXECUTE FUNCTION enforce_immutable_acp_run_binding()",
		"ALTER TABLE runs ENABLE ALWAYS TRIGGER runs_acp_binding_immutable",
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Migrate(ctx); err == nil {
		t.Fatal("narrowed UPDATE OF trigger passed catalog attestation")
	}
}
