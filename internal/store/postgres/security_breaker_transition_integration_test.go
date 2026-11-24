package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
)

func TestCircuitBreakerRejectsStateOnlyTransitionAtDatabaseBoundary(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	scope := breaker.Scope{Kind: breaker.ScopeRun, ID: "run-breaker-state-only"}
	initial, err := breaker.NewClosed(scope, time.Date(2026, 11, 24, 7, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, 0, initial); err != nil {
		t.Fatalf("create initial breaker: %v", err)
	}

	// A direct SQL writer can currently mutate only the state metadata while
	// preserving the epoch/version that a generation-one Turn already pinned.
	_, err = pool.Exec(ctx, `
		UPDATE runtime_circuit_breakers
		SET state='HALF_OPEN',
			reason_code='RECOVERY_IN_PROGRESS',
			trigger_event_id='event-state-only',
			opened_at=clock_timestamp(),
			recovery_approval_id='approval-state-only',
			updated_at=clock_timestamp()
		WHERE scope_kind='RUN' AND scope_id=$1
	`, scope.ID)
	if err == nil {
		t.Fatal("database accepted CLOSED to HALF_OPEN state-only mutation without advancing epoch/version")
	}

	persisted, err := store.GetBreaker(ctx, scope)
	if err != nil {
		t.Fatalf("read breaker after rejected transition: %v", err)
	}
	if persisted.State != breaker.StateClosed || persisted.Epoch != 1 || persisted.Version != 1 {
		t.Fatalf("rejected transition mutated durable breaker: %+v", persisted)
	}
}
