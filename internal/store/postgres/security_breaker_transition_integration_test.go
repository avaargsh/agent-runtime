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
