package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/jackc/pgx/v5/pgconn"
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

	// A newly inserted breaker is also required to begin CLOSED at epoch and
	// version one; a caller cannot seed a read-only HALF_OPEN probe directly.
	_, err = pool.Exec(ctx, `
		INSERT INTO runtime_circuit_breakers (
			scope_kind, scope_id, state, epoch, version, reason_code,
			trigger_event_id, opened_at, recovery_approval_id,
			last_recovery_evidence_ref, updated_at
		)
		VALUES ('RUN', 'run-breaker-initial-half-open', 'HALF_OPEN', 1, 1,
			'RECOVERY_IN_PROGRESS', 'event-initial-half-open',
			clock_timestamp(), 'approval-initial-half-open', '', clock_timestamp())
	`)
	if err == nil {
		t.Fatal("database accepted an initially HALF_OPEN breaker at epoch/version one")
	}

	persisted, err := store.GetBreaker(ctx, scope)
	if err != nil {
		t.Fatalf("read breaker after rejected transition: %v", err)
	}
	if persisted.State != breaker.StateClosed || persisted.Epoch != 1 || persisted.Version != 1 {
		t.Fatalf("rejected transition mutated durable breaker: %+v", persisted)
	}

	// Even a correctly incremented tuple cannot skip the OPEN admission step.
	_, err = pool.Exec(ctx, `
		UPDATE runtime_circuit_breakers
		SET state='HALF_OPEN', epoch=2, version=2,
			reason_code='RECOVERY_IN_PROGRESS',
			trigger_event_id='event-illegal-jump',
			opened_at=clock_timestamp(),
			recovery_approval_id='approval-illegal-jump',
			updated_at=clock_timestamp()
		WHERE scope_kind='RUN' AND scope_id=$1
	`, scope.ID)
	if err == nil {
		t.Fatal("database accepted unsupported CLOSED to HALF_OPEN transition")
	}

	// All supported state-machine transitions still pass through the DB fence.
	opened, err := initial.Trip("UNAUTHORIZED_EGRESS", "event-supported-open", initial.UpdatedAt.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, initial.Version, opened); err != nil {
		t.Fatalf("supported CLOSED to OPEN transition rejected: %v", err)
	}
	halfOpen, err := opened.BeginRecovery("approval-supported", opened.UpdatedAt.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, opened.Version, halfOpen); err != nil {
		t.Fatalf("supported OPEN to HALF_OPEN transition rejected: %v", err)
	}
	recovered, err := halfOpen.CompleteRecovery("approval-supported", "evidence://breaker/recovery", halfOpen.UpdatedAt.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, halfOpen.Version, recovered); err != nil {
		t.Fatalf("supported HALF_OPEN to CLOSED transition rejected: %v", err)
	}
	if final, err := store.GetBreaker(ctx, scope); err != nil ||
		final.State != breaker.StateClosed || final.Epoch != 4 || final.Version != 4 {
		t.Fatalf("supported recovery did not persist: %+v err=%v", final, err)
	}

	// A failed recovery probe may reopen the breaker. This remains a legal
	// HALF_OPEN->OPEN transition even when all timestamps collapse to the
	// same PostgreSQL microsecond; epoch/version provide the strict ordering.
	trippedAgain, err := recovered.Trip("RECOVERY_FAILED", "event-recovery-failed", recovered.UpdatedAt.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, recovered.Version, trippedAgain); err != nil {
		t.Fatalf("supported second CLOSED to OPEN transition rejected: %v", err)
	}
	halfOpenAgain, err := trippedAgain.BeginRecovery("approval-supported-again", trippedAgain.UpdatedAt.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, trippedAgain.Version, halfOpenAgain); err != nil {
		t.Fatalf("supported second OPEN to HALF_OPEN transition rejected: %v", err)
	}
	reopened, err := halfOpenAgain.Trip("RECOVERY_FAILED", "event-recovery-failed-again", halfOpenAgain.UpdatedAt.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, halfOpenAgain.Version, reopened); err != nil {
		t.Fatalf("supported HALF_OPEN to OPEN transition rejected at PostgreSQL timestamp precision: %v", err)
	}
	if final, err := store.GetBreaker(ctx, scope); err != nil ||
		final.State != breaker.StateOpen || final.Epoch != 7 || final.Version != 7 {
		t.Fatalf("reopened breaker did not persist: %+v err=%v", final, err)
	}
}

type breakerTransitionTestDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// disableBreakerTransitionTrigger simulates a privileged database owner
// corrupting a row, so consumer fail-closed tests continue to exercise that
// separate defense after ordinary application DML is fenced.
func disableBreakerTransitionTrigger(t *testing.T, db breakerTransitionTestDB) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `ALTER TABLE runtime_circuit_breakers DISABLE TRIGGER runtime_circuit_breaker_transition`); err != nil {
		t.Fatalf("disable breaker transition trigger for privileged fixture: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(context.Background(), `ALTER TABLE runtime_circuit_breakers ENABLE ALWAYS TRIGGER runtime_circuit_breaker_transition`); err != nil {
			t.Errorf("restore breaker transition trigger: %v", err)
		}
	})
}

func TestCircuitBreakerTransitionCatalogRejectsDisabledTrigger(t *testing.T) {
	pool, store := newTestStore(t)
	disableBreakerTransitionTrigger(t, pool)
	if err := store.Migrate(context.Background()); err == nil {
		t.Fatal("Runtime startup/migration accepted a disabled breaker transition trigger")
	}
}


func requireBreakerMutationBlocked(t *testing.T, err error) {
	t.Helper()
	pgErr, ok := err.(*pgconn.PgError)
	if !ok || pgErr.Code != "23514" {
		t.Fatalf("expected breaker mutation rejection (SQLSTATE 23514), got %v", err)
	}
}

func TestCircuitBreakerRowsCannotBeDeleted(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	scope := breaker.Scope{Kind: breaker.ScopeRun, ID: "run-breaker-delete-red"}
	initial, err := breaker.NewClosed(scope, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, 0, initial); err != nil {
		t.Fatalf("create initial breaker: %v", err)
	}

	_, err = pool.Exec(ctx,
		"DELETE FROM runtime_circuit_breakers WHERE scope_kind='RUN' AND scope_id=$1",
		scope.ID,
	)
	requireBreakerMutationBlocked(t, err)
	if _, err := store.GetBreaker(ctx, scope); err != nil {
		t.Fatalf("rejected DELETE removed durable breaker: %v", err)
	}
}

func TestCircuitBreakerRowsCannotBeTruncated(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	scope := breaker.Scope{Kind: breaker.ScopeRun, ID: "run-breaker-truncate-red"}
	initial, err := breaker.NewClosed(scope, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, 0, initial); err != nil {
		t.Fatalf("create initial breaker: %v", err)
	}

	_, err = pool.Exec(ctx, "TRUNCATE runtime_circuit_breakers")
	requireBreakerMutationBlocked(t, err)
	if _, err := store.GetBreaker(ctx, scope); err != nil {
		t.Fatalf("rejected TRUNCATE removed durable breaker: %v", err)
	}
}
