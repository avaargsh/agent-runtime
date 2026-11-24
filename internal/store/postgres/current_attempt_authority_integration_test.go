package postgres_test

import (
	"context"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

// A Temporal Attempt is not current merely because it is the only row in
// runtime_run_attempts. Runtime must commit an explicit generation-1
// authority fact in the same transaction before it creates any Decision Turn.
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
