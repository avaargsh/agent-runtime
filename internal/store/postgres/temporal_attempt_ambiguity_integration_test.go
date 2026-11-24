package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// The schema permits several immutable Attempt rows for a Run. Until an
// explicit current-Attempt authority exists, no one of those rows may
// authorize a Decision Turn just because QueryRow happens to select it.
func TestTemporalTurnRejectsAmbiguousPersistedAttempts(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	for i, attempt := range []string{
		"33333333-3333-4333-8333-333333333331",
		"33333333-3333-4333-8333-333333333332",
	} {
		execution := []string{firstTemporalExecutionID, secondTemporalExecutionID}[i]
		if _, err := pool.Exec(ctx, `INSERT INTO runtime_run_attempts
			(tenant_id, run_id, run_attempt_id, workflow_id, temporal_execution_id)
			VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)`,
			r.TenantID, r.RunID, attempt, r.WorkflowID, execution); err != nil {
			t.Fatalf("seed ambiguous persisted Attempt: %v", err)
		}
	}
	// Exercise both executions against the same fixture so the regression
	// cannot pass by chance based on the unspecified order of QueryRow.
	for _, execution := range []string{firstTemporalExecutionID, secondTemporalExecutionID} {
		got, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, execution, 1)
		if !errors.Is(err, postgres.ErrTemporalExecutionConflict) || got != (run.TemporalTurnIdentity{}) {
			t.Errorf("ambiguous Attempt returned Turn authority: execution=%s identity=%+v err=%v", execution, got, err)
		}
	}
	var attempts, turns int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM runtime_run_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
		(SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid)`,
		r.TenantID, r.RunID).Scan(&attempts, &turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || turns != 0 {
		t.Fatalf("ambiguous identity changed durable state: attempts=%d turns=%d", attempts, turns)
	}
}
