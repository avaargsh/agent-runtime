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

// A lone historical Attempt row without the generation-one pointer is not
// an implicit current Attempt and must not create a new Decision Turn.
func TestTemporalTurnRejectsAttemptWithoutCurrentPointer(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	attemptID := "33333333-3333-4333-8333-333333333331"
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)
	`, r.TenantID, r.RunID, attemptID, r.WorkflowID, firstTemporalExecutionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalAttemptAuthorityMissing) {
		t.Fatalf("pointer-less Attempt created a Turn: %v", err)
	}
	var turns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid", r.TenantID, r.RunID).Scan(&turns); err != nil || turns != 0 {
		t.Fatalf("pointer-less Attempt persisted %d Turns: %v", turns, err)
	}
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
	ref := run.AcceptedDecisionRef{
		TenantID: r.TenantID, RunID: r.RunID, WorkflowID: r.WorkflowID,
		RunIntentID: r.RunIntentID, RequestDigest: r.RequestDigest,
	}
	checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, firstTemporalExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	oldAuthority, err := store.GetDecisionAuthority(ctx, r.TenantID, r.RunID, checkpoint.TurnID)
	if err != nil {
		t.Fatal(err)
	}
	oldReceipt := testContinuationReceipt(t, oldAuthority)
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
	if _, err := restarted.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalAttemptAuthorityMissing) {
		t.Fatalf("legacy Attempt replay gained current authority: %v", err)
	}
	if _, err := restarted.GetDecisionAuthority(ctx, r.TenantID, r.RunID, checkpoint.TurnID); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("legacy checkpoint retained current Decision authority: %v", err)
	}
	if _, err := restarted.AcceptDecisionContinuation(ctx, oldAuthority, oldReceipt); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("legacy receipt committed after pointer removal: %v", err)
	}
	var current, checkpoints, acceptances int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_current_attempts").Scan(&current); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_checkpoints WHERE tenant_id=$1 AND run_id=$2::uuid", r.TenantID, r.RunID).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_acceptances WHERE tenant_id=$1 AND run_id=$2::uuid", r.TenantID, r.RunID).Scan(&acceptances); err != nil {
		t.Fatal(err)
	}
	if current != 0 || checkpoints != 1 || acceptances != 0 {
		t.Fatalf("legacy history changed: current=%d checkpoints=%d acceptances=%d", current, checkpoints, acceptances)
	}
}
