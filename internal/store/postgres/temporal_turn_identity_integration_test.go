package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/google/uuid"
)

const firstTemporalExecutionID = "d98f86e9-2511-464f-8c63-012345678901"
const secondTemporalExecutionID = "d98f86e9-2511-464f-8c63-012345678902"

func TestTemporalTurnIdentityIsDurableAcrossRetryAndWorkerRestart(t *testing.T) {
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
	if uuid.Validate(first.RunAttemptID) != nil || uuid.Validate(first.TurnID) != nil ||
		first.InvocationID != first.TurnID || first.RunID != r.RunID ||
		first.WorkflowID != r.WorkflowID || first.TemporalExecutionID != firstTemporalExecutionID {
		t.Fatalf("invalid Runtime-owned identity: %+v", first)
	}
	afterRestart := postgres.New(pool)
	replay, err := afterRestart.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil || replay != first {
		t.Fatalf("Temporal retry changed durable identity: first=%+v replay=%+v err=%v", first, replay, err)
	}
	secondTurn, err := afterRestart.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 2)
	if err != nil || secondTurn.RunAttemptID != first.RunAttemptID || secondTurn.TurnID == first.TurnID {
		t.Fatalf("new decision turn failed to retain Attempt: %+v %v", secondTurn, err)
	}
	// A second Temporal Server execution for the same logical Run might be
	// a replay after history retention expiry. Without an explicit fenced
	// continuation contract, a second Attempt could repeat effects.
	if _, err := afterRestart.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, secondTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalExecutionConflict) {
		t.Fatalf("new Temporal execution bypassed UNKNOWN reconciliation: %v", err)
	}
	var attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_run_attempts WHERE run_id=$1::uuid", r.RunID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns WHERE run_id=$1::uuid", r.RunID).Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || turns != 2 {
		t.Fatalf("duplicated canonical identities: attempts=%d turns=%d", attempts, turns)
	}
}

func TestTemporalTurnConcurrentSameExecutionHasOneAuthorityRecord(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	const n = 10
	identities := make(chan run.TemporalTurnIdentity, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := postgres.New(pool).GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
			identities <- got
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	close(identities)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first run.TemporalTurnIdentity
	for id := range identities {
		if first.RunAttemptID == "" {
			first = id
		} else if first != id {
			t.Fatalf("concurrent replay minted different identity: first=%+v got=%+v", first, id)
		}
	}
	var attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_run_attempts").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns").Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || turns != 1 {
		t.Fatalf("concurrent Temporal retries created duplicates: attempts=%d turns=%d", attempts, turns)
	}
}

func TestTemporalTurnIdentityRejectsUnboundLegacyWrongScopeAndMalformedExecution(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	bound, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		tenant, runID, workflow, execution string
		ordinal int32
	}{
		{"wrong tenant", "tenant-victim", bound.RunID, bound.WorkflowID, firstTemporalExecutionID, 1},
		{"wrong workflow", bound.TenantID, bound.RunID, "agent-run/v1/spoof", firstTemporalExecutionID, 1},
		{"invalid execution", bound.TenantID, bound.RunID, bound.WorkflowID, "random-untrusted-key", 1},
		{"zero ordinal", bound.TenantID, bound.RunID, bound.WorkflowID, firstTemporalExecutionID, 0},
		{"huge ordinal", bound.TenantID, bound.RunID, bound.WorkflowID, firstTemporalExecutionID, 10001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.GetOrCreateTemporalTurn(ctx, tc.tenant, tc.runID, tc.workflow, tc.execution, tc.ordinal); err == nil {
				t.Fatal("untrusted Temporal identity accepted")
			}
		})
	}
	legacyIntent := testIntent()
	legacyIntent.RunIntentID = "11111111-1111-4111-8111-111111111112"
	legacy, err := store.AcceptIntent(ctx, legacyIntent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, legacy.TenantID, legacy.RunID, legacy.WorkflowID, firstTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalTurnUntrustedRun) {
		t.Fatalf("legacy Run without immutable ACP principal got Temporal identity: %v", err)
	}
	var attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_run_attempts").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns").Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || turns != 0 {
		t.Fatalf("rejected execution wrote identities: %d/%d", attempts, turns)
	}
}

func TestTemporalAttemptTurnIdentityCannotBeRewrittenOrTruncated(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"UPDATE runtime_run_attempts SET temporal_execution_id='00000000-0000-4000-8000-000000000000'",
		"DELETE FROM runtime_run_attempts",
		"TRUNCATE runtime_run_attempts CASCADE",
		"UPDATE runtime_decision_turns SET turn_index=2",
		"DELETE FROM runtime_decision_turns",
		"TRUNCATE runtime_decision_turns",
	} {
		if _, err := pool.Exec(ctx, query); err == nil {
			t.Fatalf("immutable Execution ID changed or removed: %s", query)
		}
	}
}
