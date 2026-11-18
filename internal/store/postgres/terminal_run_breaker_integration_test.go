package postgres_test

import (
	"context"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/breaker"
)

// Terminal state and breaker state are distinct authorities. A CLOSED
// breaker retained for audit cannot authorize a cancelled/completed Run.
func TestDecisionBreakerRejectsTerminalRunEvenWithClosedBreaker(t *testing.T) {
	for _, status := range []string{"CANCELLED", "FAILED", "SUCCEEDED"} {
		t.Run(status, func(t *testing.T) {
			pool, store := newTestStore(t)
			ctx := context.Background()
			receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			// Positive control: a queued or running Run can resolve its
			// closed breaker. No authorization to execute protected effects
			// is implied by this necessary condition.
			first, err := store.GetRunBreaker(ctx, receipt.TenantID, receipt.RunID)
			if err != nil || first.State != breaker.StateClosed {
				t.Fatalf("active owned breaker unavailable: %+v %v", first, err)
			}
			if _, err := pool.Exec(ctx, "UPDATE runs SET status='RUNNING', updated_at=clock_timestamp() WHERE run_id=$1::uuid", receipt.RunID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetRunBreaker(ctx, receipt.TenantID, receipt.RunID); err != nil {
				t.Fatalf("RUNNING breaker unavailable: %v", err)
			}
			if _, err := pool.Exec(ctx, "UPDATE runs SET status=$2, updated_at=clock_timestamp() WHERE run_id=$1::uuid", receipt.RunID, status); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetRunBreaker(ctx, receipt.TenantID, receipt.RunID); err == nil {
				t.Fatal("terminal Run remained eligible for Decision egress")
			}
			// Preserve the actual breaker for forensic/owner inspection.
			raw, err := store.GetBreaker(ctx, first.Scope)
			if err != nil || raw != first {
				t.Fatalf("terminal admission check mutated the audit breaker: %+v %v", raw, err)
			}
		})
	}
}
