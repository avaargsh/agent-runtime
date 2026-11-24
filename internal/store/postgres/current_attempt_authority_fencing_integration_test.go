package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

func TestDecisionAuthorityRejectsHistoricalAttemptAfterBreakerRecovery(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	principal := trustedSnapshot()
	principal.ActorID = principal.SubjectID
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{
		TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
		RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest,
	}
	checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, firstTemporalExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	oldAuthority, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID)
	if err != nil || oldAuthority.AttemptGeneration != 1 || oldAuthority.BreakerEpoch != 1 {
		t.Fatalf("initial Decision authority missing generation fence: %+v %v", oldAuthority, err)
	}
	oldReceipt := testContinuationReceipt(t, oldAuthority)

	current, err := store.GetRunBreaker(ctx, ref.TenantID, ref.RunID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := current.Trip("UNAUTHORIZED_EGRESS", "attempt-generation-trip", current.UpdatedAt.Add(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, current.Version, opened); err != nil {
		t.Fatal(err)
	}
	half, err := opened.BeginRecovery("attempt-generation-approval", opened.UpdatedAt.Add(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, opened.Version, half); err != nil {
		t.Fatal(err)
	}
	closed, err := half.CompleteRecovery("attempt-generation-approval",
		"evidence://attempt-generation-recovered", half.UpdatedAt.Add(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, half.Version, closed); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("historical Attempt retained Decision authority after breaker recovery: %v", err)
	}
	if _, err := store.AcceptDecisionContinuation(ctx, oldAuthority, oldReceipt); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("historical Decision receipt committed after breaker recovery: %v", err)
	}
	var generation, breakerEpoch int64
	var attemptID string
	if err := pool.QueryRow(ctx, `
		SELECT generation, attempt_id::text, breaker_epoch
		FROM runtime_current_attempts WHERE tenant_id=$1 AND run_id=$2::uuid
	`, ref.TenantID, ref.RunID).Scan(&generation, &attemptID, &breakerEpoch); err != nil {
		t.Fatal(err)
	}
	if generation != 1 || attemptID != oldAuthority.AttemptID || breakerEpoch != 1 {
		t.Fatalf("breaker recovery implicitly advanced current Attempt: generation=%d attempt=%s epoch=%d", generation, attemptID, breakerEpoch)
	}
	var acceptances, checkpoints int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_acceptances WHERE tenant_id=$1 AND run_id=$2::uuid", ref.TenantID, ref.RunID).Scan(&acceptances); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_checkpoints WHERE tenant_id=$1 AND run_id=$2::uuid", ref.TenantID, ref.RunID).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if acceptances != 0 || checkpoints != 1 {
		t.Fatalf("historical receipt/checkpoint mutated: acceptances=%d checkpoints=%d", acceptances, checkpoints)
	}
}
