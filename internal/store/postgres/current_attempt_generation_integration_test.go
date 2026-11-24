package postgres_test

import (
	"context"
	"errors"
	"testing"

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
