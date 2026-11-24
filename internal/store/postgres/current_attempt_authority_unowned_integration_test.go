package postgres_test

import (
	"context"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

// A historical Attempt row is not current authority unless Runtime committed
// the generation-one pointer in the same transaction. A replay must not
// silently manufacture a Decision Turn for an unowned Attempt.
func TestTemporalTurnRejectsUnownedPersistedAttempt(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	attemptID := "33333333-3333-4333-8333-333333333331"
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)
	`, receipt.TenantID, receipt.RunID, attemptID, receipt.WorkflowID, firstTemporalExecutionID); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 1)
	if err == nil || got != (run.TemporalTurnIdentity{}) {
		t.Fatalf("unowned Attempt gained Turn authority: %+v err=%v", got, err)
	}
	var turns int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid
	`, receipt.TenantID, receipt.RunID).Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if turns != 0 {
		t.Fatalf("unowned Attempt created %d Decision Turns", turns)
	}
}
