package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// Generation one is created only with a new Runtime-owned Attempt in its
// existing transaction. The record alone is not a dispatch permit.
func TestCurrentAttemptInitialGenerationDurable(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		var attempt string
		var generation, epoch int64
		err := pool.QueryRow(ctx, `
			SELECT attempt_id::text, generation, breaker_epoch
			FROM runtime_current_attempts
			WHERE tenant_id=$1 AND run_id=$2::uuid
		`, r.TenantID, r.RunID).Scan(&attempt, &generation, &epoch)
		if err != nil || attempt != first.RunAttemptID || generation != 1 || epoch != 1 {
			t.Fatalf("missing or changed initial authority: attempt=%q generation=%d epoch=%d err=%v", attempt, generation, epoch, err)
		}
	}
	check()
	restarted := postgres.New(pool)
	replay, err := restarted.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil || replay != first {
		t.Fatalf("replay changed identity: %+v %v", replay, err)
	}
	second, err := restarted.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 2)
	if err != nil || second.RunAttemptID != first.RunAttemptID || second.TurnID == first.TurnID {
		t.Fatalf("second turn changed Attempt: %+v %v", second, err)
	}
	if _, err := restarted.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, secondTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalExecutionConflict) {
		t.Fatalf("unfenced new execution accepted: %v", err)
	}
	check()
}

// A later Turn write failure must roll back the Attempt and generation too.
func TestCurrentAttemptInitializationRollsBackOnTurnFailure(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION reject_test_turn_insert() RETURNS trigger
		LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced Turn insert failure'; END$$;
		CREATE TRIGGER reject_test_turn_insert BEFORE INSERT ON runtime_decision_turns
		FOR EACH ROW EXECUTE FUNCTION reject_test_turn_insert()
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1); err == nil {
		t.Fatal("forced Turn failure returned success")
	}
	var attempts, current, turns int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM runtime_run_attempts),
		(SELECT count(*) FROM runtime_current_attempts), (SELECT count(*) FROM runtime_decision_turns)`).
		Scan(&attempts, &current, &turns); err != nil || attempts != 0 || current != 0 || turns != 0 {
		t.Fatalf("failed transaction persisted identity: %d/%d/%d err=%v", attempts, current, turns, err)
	}
}

// Simulate v12 history by removing only the additive table and its ledger row
// in an isolated fixture. Migration must not infer new authority from history.
func TestCurrentAttemptMigrationDoesNotPromoteLegacyAttempt(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE runtime_current_attempts;
		DELETE FROM runtime_schema_migrations WHERE version=13`); err != nil {
		t.Fatal(err)
	}
	restarted := postgres.New(pool)
	for i := 0; i < 2; i++ {
		if err := restarted.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	replay, err := restarted.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
	if !errors.Is(err, postgres.ErrTemporalAttemptAuthorityMissing) || replay != (run.TemporalTurnIdentity{}) {
		t.Fatalf("legacy Attempt without a current pointer was replayed: %+v %v", replay, err)
	}
	var count, turns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_current_attempts").Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy history promoted implicitly: count=%d err=%v", count, err)
	}
	var persistedTurn string
	if err := pool.QueryRow(ctx, `
		SELECT turn_id::text FROM runtime_decision_turns
		WHERE tenant_id=$1 AND run_id=$2::uuid AND run_attempt_id=$3::uuid AND turn_index=1
	`, r.TenantID, r.RunID, first.RunAttemptID).Scan(&persistedTurn); err != nil || persistedTurn != first.TurnID {
		t.Fatalf("legacy Turn history changed after denied replay: turn=%s want=%s err=%v", persistedTurn, first.TurnID, err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid", r.TenantID, r.RunID).Scan(&turns); err != nil || turns != 1 {
		t.Fatalf("legacy Turn history count changed after denied replay: turns=%d err=%v", turns, err)
	}
}
