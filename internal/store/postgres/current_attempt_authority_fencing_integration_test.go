package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
)

// This test seeds the durable result of a future, explicitly fenced
// generation-advance transaction. It verifies that all existing readers
// treat the highest committed generation as current and reject the old
// checkpoint/receipt; it does not implement or authorize continuation.
func TestDecisionAuthorityRejectsHistoricalAttemptAfterNewGeneration(t *testing.T) {
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
	opened, err := current.Trip("UNAUTHORIZED_EGRESS", "attempt-generation-trip", current.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, current.Version, opened); err != nil {
		t.Fatal(err)
	}
	half, err := opened.BeginRecovery("attempt-generation-approval", opened.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, opened.Version, half); err != nil {
		t.Fatal(err)
	}
	closed, err := half.CompleteRecovery("attempt-generation-approval",
		"evidence://attempt-generation-recovered", half.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, half.Version, closed); err != nil {
		t.Fatal(err)
	}

	newAttemptID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)
	`, ref.TenantID, ref.RunID, newAttemptID, ref.WorkflowID, secondTemporalExecutionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime_run_attempt_authorities
		(tenant_id,run_id,generation,run_attempt_id,temporal_execution_id,breaker_epoch)
		VALUES ($1,$2::uuid,2,$3::uuid,$4::uuid,$5)
	`, ref.TenantID, ref.RunID, newAttemptID, secondTemporalExecutionID, int64(closed.Epoch)); err != nil {
		t.Fatalf("seed next durable generation after newer CLOSED breaker epoch: %v", err)
	}

	if _, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("historical Attempt retained current Decision authority: %v", err)
	}
	if _, err := store.AcceptDecisionContinuation(ctx, oldAuthority, oldReceipt); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("historical Decision receipt committed under a newer Attempt generation: %v", err)
	}
	var acceptances, checkpoints int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_acceptances WHERE tenant_id=$1 AND run_id=$2::uuid",
		ref.TenantID, ref.RunID).Scan(&acceptances); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_checkpoints WHERE tenant_id=$1 AND run_id=$2::uuid",
		ref.TenantID, ref.RunID).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if acceptances != 0 || checkpoints != 1 || !strings.HasPrefix(oldAuthority.InputDigest, "sha256:") {
		t.Fatalf("historical receipt/checkpoint mutated: acceptances=%d checkpoints=%d authority=%+v",
			acceptances, checkpoints, oldAuthority)
	}
}
