package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func TestDecisionAuthorityRequiresCurrentCommittedTurn(t *testing.T) {
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
	const fake = "11111111-2222-4333-8444-555555555555"
	if _, err := store.GetDecisionAuthority(ctx, receipt.TenantID, receipt.RunID, fake); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("unprepared Run obtained authority: %v", err)
	}
	ref := run.AcceptedDecisionRef{TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
		RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest}
	checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, fake)
	if err != nil {
		t.Fatal(err)
	}
	got, err := postgres.New(pool).GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID)
	if err != nil || got.RunID != ref.RunID || got.RunIntentID != ref.RunIntentID ||
		got.RequestDigest != ref.RequestDigest || got.InvocationID != checkpoint.TurnID ||
		got.ExecutionID != checkpoint.ExecutionID || got.AttemptID != checkpoint.AttemptID ||
		got.InputDigest != checkpoint.InputDigest || got.SubjectID != principal.SubjectID ||
		got.ActorID != principal.ActorID || got.ProjectID != principal.ProjectID ||
		got.PolicyRevision != principal.PolicyRevision || got.ConfigDigest != principal.ConfigDigest ||
		got.AgentID != command.AgentID || got.AgentReleaseID != command.AgentReleaseID || got.SessionID != command.SessionID ||
		got.AttemptGeneration != 1 || got.BreakerEpoch != 1 || got.BreakerVersion != 1 ||
		got.Status != "RUNNING" || got.BreakerState != "CLOSED" {
		t.Fatalf("canonical durable binding unavailable: %+v %v", got, err)
	}
	for _, bad := range [][3]string{
		{"foreign", ref.RunID, checkpoint.TurnID},
		{ref.TenantID, fake, checkpoint.TurnID},
		{ref.TenantID, ref.RunID, fake},
	} {
		if _, err := store.GetDecisionAuthority(ctx, bad[0], bad[1], bad[2]); !errors.Is(err, run.ErrDecisionPreparationDenied) {
			t.Fatalf("foreign binding received authority: %v", err)
		}
	}
	breaker, err := store.GetRunBreaker(ctx, ref.TenantID, ref.RunID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := breaker.Trip("UNAUTHORIZED_EGRESS", "decision-authority-test", breaker.UpdatedAt.Add(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, breaker.Version, opened); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("opened breaker granted authority: %v", err)
	}
}

func TestDecisionAuthorityRejectsCancelledRun(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"errors"}`)
	principal := trustedSnapshot()
	principal.ActorID = principal.SubjectID
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
		RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest}
	checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, "11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CancelPreparedDecision(ctx, ref, checkpoint.ExecutionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("cancelled Run received Decision authority: %v", err)
	}
}
