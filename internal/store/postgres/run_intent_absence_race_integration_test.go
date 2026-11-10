package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// This is the conservative G01 contract: an absent SELECT is not a durable
// final-absence barrier. Another StartRun may already have inserted a Run
// in a transaction that has not yet committed.
func TestLookupIntentDuringUncommittedAcceptanceDoesNotClaimFinalAbsence(t *testing.T) {
	pool, store := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Prevent the real AcceptIntentWithPrincipal transaction from committing
	// its mandatory start-Outbox event. The Run INSERT happens first in the
	// same SQL transaction; a competing Inspect uses a different connection.
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, "LOCK TABLE runtime_outbox IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatalf("lock start Outbox: %v", err)
	}

	type acceptResult struct {
		receipt run.IntentReceipt
		err     error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		receipt, acceptErr := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
		accepted <- acceptResult{receipt: receipt, err: acceptErr}
	}()

	// Wait for actual PostgreSQL lock contention, not a timing-dependent
	// sleep. We must inspect while the accepting transaction is in flight.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	blocked := false
	for !blocked {
		if err := pool.QueryRow(ctx, `
            SELECT EXISTS (
                SELECT 1 FROM pg_locks
                WHERE relation='runtime_outbox'::regclass
                  AND locktype='relation'
                  AND mode='RowExclusiveLock'
                  AND NOT granted
            )`).Scan(&blocked); err != nil {
			t.Fatalf("inspect PostgreSQL lock wait: %v", err)
		}
		if blocked {
			break
		}
		select {
		case result := <-accepted:
			t.Fatalf("acceptance completed before injected outbox lock was reached: %+v", result)
		case <-deadline.C:
			t.Fatal("real acceptance never reached blocked outbox INSERT")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}

	// The Run row exists only in the uncommitted acceptance transaction.
	// Its absence to a concurrent read MUST remain uncertain to ACP.
	if _, err := store.LookupIntent(ctx, testIntent().TenantID,
		testIntent().RunIntentID, testIntent().RequestDigest); !errors.Is(err, run.ErrIntentNotFound) {
		t.Fatalf("pre-commit lookup must be uncertain, got: %v", err)
	}

	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("release outbox lock: %v", err)
	}
	var first acceptResult
	select {
	case first = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if first.err != nil || !first.receipt.Created || first.receipt.RunID == "" {
		t.Fatalf("acceptance after release: %+v", first)
	}
	found, err := postgres.New(pool).LookupIntent(ctx, testIntent().TenantID,
		testIntent().RunIntentID, testIntent().RequestDigest)
	if err != nil || found.RunID != first.receipt.RunID ||
		found.WorkflowID != "agent-run/v1/"+first.receipt.RunID {
		t.Fatalf("post-commit inspect did not converge to one Run: found=%+v err=%v", found, err)
	}
	replay, err := postgres.New(pool).AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil || replay.Created || replay.RunID != found.RunID ||
		replay.WorkflowID != found.WorkflowID {
		t.Fatalf("lost ACK replay minted a second Run: %+v err=%v", replay, err)
	}
	var runs, outbox, principal int
	if err := pool.QueryRow(ctx, `
        SELECT
            (SELECT count(*) FROM runs WHERE run_intent_id=$1::uuid),
            (SELECT count(*) FROM runtime_outbox WHERE aggregate_id=$2::uuid AND event_type='RUN_START_REQUESTED'),
            (SELECT count(*) FROM runtime_run_principal_snapshots WHERE run_id=$2::uuid)
    `, sampleIntentID, first.receipt.RunID).Scan(&runs, &outbox, &principal); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || outbox != 1 || principal != 1 {
		t.Fatalf("non-atomic or duplicate acceptance rows: runs=%d outbox=%d principal=%d",
			runs, outbox, principal)
	}
}
