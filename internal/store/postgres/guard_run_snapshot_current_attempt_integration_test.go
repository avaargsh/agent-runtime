package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

// Guard's authenticated network-facing safety read must not treat a RUNNING
// Run as executable without the Runtime-owned current Attempt pointer.
// The diagnostic reader remains independent of authorization decisions.
func TestTrustedGuardRunSafetyRequiresCurrentAttemptAndMatchingBreakerEpoch(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE runs SET status='RUNNING',updated_at=now() WHERE run_id=$1::uuid", receipt.RunID); err != nil {
		t.Fatal(err)
	}

	// RED on the old implementation: a RUNNING Run with no Attempt pointer
	// incorrectly passes the trusted Guard projection.
	if _, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); !errors.Is(err, run.ErrInvalidIdentity) {
		t.Fatalf("trusted Guard read accepted RUNNING Run with no current Attempt: %v", err)
	}
	if diagnostic, err := store.GetGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); err != nil || diagnostic.Status != run.StatusRunning {
		t.Fatalf("diagnostic Run read unexpectedly changed: %+v err=%v", diagnostic, err)
	}

	// Create an actual persisted Attempt via the canonical Runtime writer.
	turn, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil || turn.AttemptGeneration != 1 || turn.BreakerEpoch != 1 {
		t.Fatalf("canonical current Attempt unavailable: %+v err=%v", turn, err)
	}
	authorized, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID)
	if err != nil || !authorized.EligibleForGuardSubmission() {
		t.Fatalf("valid current Attempt must allow only Guard's prerequisite safety read: %+v err=%v", authorized, err)
	}

	// Simulate successful breaker recovery: the stale Attempt remains
	// generation=1/epoch=1 and must not silently regain authority.
	if _, err := pool.Exec(ctx, `UPDATE runtime_circuit_breakers
		SET epoch=2,version=2,updated_at=now()
		WHERE scope_kind='RUN' AND scope_id=$1`, receipt.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); !errors.Is(err, run.ErrInvalidIdentity) {
		t.Fatalf("trusted Guard read accepted stale Attempt after breaker epoch changed: %v", err)
	}
}
