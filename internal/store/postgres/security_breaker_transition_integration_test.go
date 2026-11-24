package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/jackc/pgx/v5/pgconn"
)

func seedBreakerForTransitionTest(t *testing.T, scopeID string) (*testBreakerFixture, breaker.Record) {
	t.Helper()
	pool, store := newTestStore(t)
	initial, err := breaker.NewClosed(
		breaker.Scope{Kind: breaker.ScopeRun, ID: scopeID},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(context.Background(), 0, initial); err != nil {
		t.Fatalf("create initial breaker: %v", err)
	}
	return &testBreakerFixture{pool: pool, store: store}, initial
}

type testBreakerFixture struct {
	pool interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	}
	store interface {
		GetBreaker(context.Context, breaker.Scope) (breaker.Record, error)
		CompareAndSwapBreaker(context.Context, uint64, breaker.Record) error
	}
}

func requireBreakerCheckViolation(t *testing.T, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("expected database CHECK-style transition rejection (SQLSTATE 23514), got %v", err)
	}
}

func TestCircuitBreakerRejectsStateOnlyAndUnsupportedTransitionsAtDatabaseBoundary(t *testing.T) {
	fixture, initial := seedBreakerForTransitionTest(t, "run-breaker-transition-red")
	ctx := context.Background()
	statements := []struct {
		name string
		sql  string
	}{
		{
			name: "state-only CLOSED to HALF_OPEN",
			sql: `UPDATE runtime_circuit_breakers
				SET state='HALF_OPEN', reason_code='RECOVERY_IN_PROGRESS',
					trigger_event_id='event-state-only', opened_at=clock_timestamp(),
					recovery_approval_id='approval-state-only', updated_at=clock_timestamp()
				WHERE scope_kind='RUN' AND scope_id=$1`,
		},
		{
			name: "CLOSED to HALF_OPEN even with incremented fence",
			sql: `UPDATE runtime_circuit_breakers
				SET state='HALF_OPEN', epoch=epoch+1, version=version+1,
					reason_code='RECOVERY_IN_PROGRESS', trigger_event_id='event-illegal-jump',
					opened_at=clock_timestamp(), recovery_approval_id='approval-illegal-jump',
					updated_at=clock_timestamp()
				WHERE scope_kind='RUN' AND scope_id=$1`,
		},
		{
			name: "version-only mutation",
			sql: `UPDATE runtime_circuit_breakers
				SET version=version+1, updated_at=clock_timestamp()
				WHERE scope_kind='RUN' AND scope_id=$1`,
		},
		{
			name: "epoch-only mutation",
			sql: `UPDATE runtime_circuit_breakers
				SET epoch=epoch+1, updated_at=clock_timestamp()
				WHERE scope_kind='RUN' AND scope_id=$1`,
		},
		{
			name: "same-state counter bump",
			sql: `UPDATE runtime_circuit_breakers
				SET epoch=epoch+1, version=version+1, updated_at=clock_timestamp()
				WHERE scope_kind='RUN' AND scope_id=$1`,
		},
		{
			name: "skipped epoch and version",
			sql: `UPDATE runtime_circuit_breakers
				SET epoch=epoch+2, version=version+2, updated_at=clock_timestamp()
				WHERE scope_kind='RUN' AND scope_id=$1`,
		},
	}
	for _, statement := range statements {
		t.Run(statement.name, func(t *testing.T) {
			_, err := fixture.pool.Exec(ctx, statement.sql, initial.Scope.ID)
			requireBreakerCheckViolation(t, err)
			persisted, err := fixture.store.GetBreaker(ctx, initial.Scope)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.State != breaker.StateClosed || persisted.Epoch != 1 || persisted.Version != 1 {
				t.Fatalf("rejected transition mutated breaker: %+v", persisted)
			}
		})
	}
}

func TestCircuitBreakerRejectsInitiallyHalfOpenRows(t *testing.T) {
	pool, _ := newTestStore(t)
	_, err := pool.Exec(context.Background(), `
		INSERT INTO runtime_circuit_breakers (
			scope_kind, scope_id, state, epoch, version, reason_code,
			trigger_event_id, opened_at, recovery_approval_id,
			last_recovery_evidence_ref, updated_at
		)
		VALUES ('RUN', 'run-breaker-initial-half-open', 'HALF_OPEN', 1, 1,
			'RECOVERY_IN_PROGRESS', 'event-initial-half-open',
			clock_timestamp(), 'approval-initial-half-open', '', clock_timestamp())
	`)
	requireBreakerCheckViolation(t, err)
}

func TestCircuitBreakerRowsCannotBeDeleted(t *testing.T) {
	fixture, initial := seedBreakerForTransitionTest(t, "run-breaker-delete-red")
	_, err := fixture.pool.Exec(context.Background(),
		"DELETE FROM runtime_circuit_breakers WHERE scope_kind='RUN' AND scope_id=$1",
		initial.Scope.ID,
	)
	requireBreakerCheckViolation(t, err)
	if _, err := fixture.store.GetBreaker(context.Background(), initial.Scope); err != nil {
		t.Fatalf("rejected DELETE removed durable breaker: %v", err)
	}
}

func TestCircuitBreakerRowsCannotBeTruncated(t *testing.T) {
	fixture, initial := seedBreakerForTransitionTest(t, "run-breaker-truncate-red")
	_, err := fixture.pool.Exec(context.Background(), "TRUNCATE runtime_circuit_breakers")
	requireBreakerCheckViolation(t, err)
	if _, err := fixture.store.GetBreaker(context.Background(), initial.Scope); err != nil {
		t.Fatalf("rejected TRUNCATE removed durable breaker: %v", err)
	}
}


func TestCircuitBreakerAcceptsSupportedTransitionsWithSynchronizedCounters(t *testing.T) {
	fixture, initial := seedBreakerForTransitionTest(t, "run-breaker-supported-transitions")
	ctx := context.Background()

	opened, err := initial.Trip("UNAUTHORIZED_EGRESS", "event-supported-open", initial.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CompareAndSwapBreaker(ctx, initial.Version, opened); err != nil {
		t.Fatalf("CLOSED to OPEN: %v", err)
	}
	halfOpen, err := opened.BeginRecovery("approval-supported-one", opened.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CompareAndSwapBreaker(ctx, opened.Version, halfOpen); err != nil {
		t.Fatalf("OPEN to HALF_OPEN: %v", err)
	}
	reopened, err := halfOpen.Trip("RECOVERY_PROBE_FAILED", "event-supported-reopen", halfOpen.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CompareAndSwapBreaker(ctx, halfOpen.Version, reopened); err != nil {
		t.Fatalf("HALF_OPEN to OPEN: %v", err)
	}
	halfOpenAgain, err := reopened.BeginRecovery("approval-supported-two", reopened.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CompareAndSwapBreaker(ctx, reopened.Version, halfOpenAgain); err != nil {
		t.Fatalf("second OPEN to HALF_OPEN: %v", err)
	}
	recovered, err := halfOpenAgain.CompleteRecovery(
		"approval-supported-two", "evidence://breaker/recovery-supported", halfOpenAgain.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CompareAndSwapBreaker(ctx, halfOpenAgain.Version, recovered); err != nil {
		t.Fatalf("HALF_OPEN to CLOSED: %v", err)
	}
	final, err := fixture.store.GetBreaker(ctx, initial.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != breaker.StateClosed || final.Epoch != 6 || final.Version != 6 {
		t.Fatalf("supported state machine ended at %+v, want CLOSED/6/6", final)
	}
}

func TestCircuitBreakerRejectsUnsupportedRecoveryShortcuts(t *testing.T) {
	fixture, initial := seedBreakerForTransitionTest(t, "run-breaker-recovery-shortcuts")
	ctx := context.Background()
	opened, err := initial.Trip("UNAUTHORIZED_EGRESS", "event-recovery-shortcut", initial.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CompareAndSwapBreaker(ctx, initial.Version, opened); err != nil {
		t.Fatal(err)
	}

	_, err = fixture.pool.Exec(ctx,
		"UPDATE runtime_circuit_breakers SET state='CLOSED',epoch=epoch+1,version=version+1,"+
			"reason_code='',trigger_event_id='',opened_at=NULL,recovery_approval_id='',updated_at=clock_timestamp() "+
			"WHERE scope_kind='RUN' AND scope_id=$1",
		initial.Scope.ID,
	)
	requireBreakerCheckViolation(t, err)

	halfOpen, err := opened.BeginRecovery("approval-shortcut-test", opened.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CompareAndSwapBreaker(ctx, opened.Version, halfOpen); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.pool.Exec(ctx,
		"UPDATE runtime_circuit_breakers SET state='CLOSED',epoch=epoch+1,version=version+1,"+
			"reason_code='',trigger_event_id='',opened_at=NULL,recovery_approval_id='',updated_at=clock_timestamp() "+
			"WHERE scope_kind='RUN' AND scope_id=$1",
		initial.Scope.ID,
	)
	requireBreakerCheckViolation(t, err)
}

func TestCircuitBreakerTransitionCatalogRejectsDisabledOrReplacedGuards(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"transition disabled", "ALTER TABLE runtime_circuit_breakers DISABLE TRIGGER runtime_circuit_breaker_transition"},
		{"delete guard disabled", "ALTER TABLE runtime_circuit_breakers DISABLE TRIGGER runtime_circuit_breaker_no_delete"},
		{"truncate guard disabled", "ALTER TABLE runtime_circuit_breakers DISABLE TRIGGER runtime_circuit_breaker_no_truncate"},
		{"delete guard missing", "DROP TRIGGER runtime_circuit_breaker_no_delete ON runtime_circuit_breakers"},
		{"truncate guard missing", "DROP TRIGGER runtime_circuit_breaker_no_truncate ON runtime_circuit_breakers"},
		{"transition function replaced", "CREATE OR REPLACE FUNCTION enforce_runtime_circuit_breaker_transition() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END;'"},
		{"mutation function replaced", "CREATE OR REPLACE FUNCTION reject_runtime_circuit_breaker_mutation() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END;'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, store := newTestStore(t)
			if _, err := pool.Exec(context.Background(), tc.sql); err != nil {
				t.Fatalf("prepare catalog drift: %v", err)
			}
			if err := store.Migrate(context.Background()); err == nil {
				t.Fatalf("Runtime migration/startup accepted catalog drift: %s", tc.name)
			}
		})
	}
}

type breakerTransitionTestDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// disableBreakerTransitionTrigger simulates privileged catalog tampering so
// consumer fail-closed tests continue to exercise the separate read boundary.
func disableBreakerTransitionTrigger(t *testing.T, db breakerTransitionTestDB) {
	t.Helper()
	if _, err := db.Exec(context.Background(), "ALTER TABLE runtime_circuit_breakers DISABLE TRIGGER runtime_circuit_breaker_transition"); err != nil {
		t.Fatalf("disable breaker transition trigger for privileged fixture: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(context.Background(), "ALTER TABLE runtime_circuit_breakers ENABLE ALWAYS TRIGGER runtime_circuit_breaker_transition"); err != nil {
			t.Errorf("restore breaker transition trigger: %v", err)
		}
	})
}

// disableBreakerDeleteTrigger simulates privileged deletion of a durable
// breaker to test consumer fail-closed behavior for a missing row.
func disableBreakerDeleteTrigger(t *testing.T, db breakerTransitionTestDB) func() {
	t.Helper()
	if _, err := db.Exec(context.Background(), "ALTER TABLE runtime_circuit_breakers DISABLE TRIGGER runtime_circuit_breaker_no_delete"); err != nil {
		t.Fatalf("disable breaker delete trigger for privileged fixture: %v", err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := db.Exec(context.Background(), "ALTER TABLE runtime_circuit_breakers ENABLE ALWAYS TRIGGER runtime_circuit_breaker_no_delete"); err != nil {
			t.Errorf("restore breaker delete trigger: %v", err)
		}
	}
	t.Cleanup(restore)
	return restore
}
