package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// A Temporal Attempt is not current merely because it is the only row in
// runtime_run_attempts. Runtime must commit an explicit generation-1
// authority fact in the same transaction before it creates any Decision Turn.
// A lone immutable Attempt row without a Runtime authority generation is
// historical/untrusted input, not an implicit current Attempt.
func TestTemporalTurnRejectsUnownedPersistedAttempt(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	attemptID := "33333333-3333-4333-8333-333333333331"
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)
	`, receipt.TenantID, receipt.RunID, attemptID, receipt.WorkflowID, firstTemporalExecutionID); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 1)
	if !errors.Is(err, postgres.ErrTemporalAttemptAuthorityMissing) || got != (run.TemporalTurnIdentity{}) {
		t.Fatalf("unowned Attempt gained Turn authority: %+v err=%v", got, err)
	}
	var turns int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid
	`, receipt.TenantID, receipt.RunID).Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if turns != 0 {
		t.Fatalf("unowned Attempt created %d Decision Turns", turns)
	}
}

func TestTemporalTurnCreatesAndReusesCurrentAttemptAuthorityGenerationOne(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}

	first, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("first Runtime identity invalid: %+v: %v", first, err)
	}

	assertAuthority := func(want run.TemporalTurnIdentity) {
		t.Helper()
		var generation, breakerEpoch int64
		var attemptID, executionID string
		if err := pool.QueryRow(ctx, `
			SELECT generation, run_attempt_id::text, temporal_execution_id::text, breaker_epoch
			FROM runtime_run_attempt_authorities
			WHERE tenant_id=$1 AND run_id=$2::uuid
			ORDER BY generation DESC LIMIT 1
		`, receipt.TenantID, receipt.RunID).Scan(&generation, &attemptID, &executionID, &breakerEpoch); err != nil {
			t.Fatalf("load current Attempt authority: %v", err)
		}
		if generation != 1 || attemptID != want.RunAttemptID ||
			executionID != firstTemporalExecutionID || breakerEpoch != 1 {
			t.Fatalf("wrong current Attempt authority: generation=%d attempt=%s execution=%s breaker_epoch=%d want=%+v",
				generation, attemptID, executionID, breakerEpoch, want)
		}
		var count int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM runtime_run_attempt_authorities
			WHERE tenant_id=$1 AND run_id=$2::uuid
		`, receipt.TenantID, receipt.RunID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("authority ledger rows=%d, want one generation", count)
		}
	}

	assertAuthority(first)

	// A later Turn in the same Temporal execution reuses the same current
	// Attempt; it must not append a new authority generation.
	second, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if second.RunAttemptID != first.RunAttemptID || second.TurnID == first.TurnID {
		t.Fatalf("same execution did not retain its Attempt: first=%+v second=%+v", first, second)
	}
	assertAuthority(first)
}
