package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func TestAcceptedDecisionCheckpointIsBusinessInputBoundAndDurable(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	principal := trustedSnapshot()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{
		TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
		RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest,
	}
	const execution = "11111111-2222-4333-8444-555555555555"
	first, err := store.PrepareAcceptedDecision(ctx, ref, execution)
	if err != nil || first.Phase != run.DecisionWaitingAuthority || first.RunID != receipt.RunID ||
		first.ExecutionID != execution || first.AttemptID == "" || first.TurnID == "" ||
		first.PolicyRevision != principal.PolicyRevision || first.ConfigDigest != principal.ConfigDigest ||
		first.InputDigest == "" {
		t.Fatalf("prepare checkpoint from committed business input: %+v %v", first, err)
	}
	// A worker can die after PostgreSQL commit but before Activity ACK.
	// Restart must recover the same checkpoint, not allocate a new Turn.
	replay, err := postgres.New(pool).PrepareAcceptedDecision(ctx, ref, execution)
	if err != nil || replay != first {
		t.Fatalf("checkpoint replay changed binding: %+v %v", replay, err)
	}
	if _, err := store.PrepareAcceptedDecision(ctx, ref, secondTemporalExecutionID); err == nil {
		t.Fatal("second Temporal execution claimed business checkpoint")
	}
	foreign := ref
	foreign.TenantID = "other-tenant"
	if _, err := store.PrepareAcceptedDecision(ctx, foreign, execution); err == nil {
		t.Fatal("foreign tenant read execution checkpoint")
	}
	wrong := ref
	wrong.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := store.PrepareAcceptedDecision(ctx, wrong, execution); err == nil {
		t.Fatal("wrong digest obtained checkpoint")
	}
	var rows, turns int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM runtime_decision_checkpoints), (SELECT count(*) FROM runtime_decision_turns)").Scan(&rows, &turns); err != nil || rows != 1 || turns != 1 {
		t.Fatalf("duplicate business state: %d/%d %v", rows, turns, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runtime_decision_checkpoints SET input_digest='sha256:'||repeat('b',64)"); err == nil {
		t.Fatal("checkpoint digest mutated")
	}
	if _, err := pool.Exec(ctx, "DELETE FROM runtime_decision_checkpoints"); err == nil {
		t.Fatal("checkpoint evidence deleted")
	}
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='CANCELLED',updated_at=clock_timestamp() WHERE run_id=$1::uuid", receipt.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareAcceptedDecision(ctx, ref, execution); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("cancelled Run resumed business work: %v", err)
	}
}

func TestAcceptedDecisionCheckpointRejectsInvalidObjectiveBeforeAllocatingTurn(t *testing.T) {
	for _, input := range []string{
		`{"objective":"deploy","service":"payments","signal":"latency"}`,
		`{"objective":"sre_incident_triage","service":"payments","signal":"latency","permit":"forged"}`,
		`{"objective":"sre_incident_triage","service":"payments","signal":"unknown"}`,
		`{"message":"legacy prompt is not a decision.v1 input"}`,
	} {
		t.Run(input, func(t *testing.T) {
			pool, store := newTestStore(t)
			ctx := context.Background()
			command := testIntent()
			command.Input = []byte(input)
			receipt, err := store.AcceptIntentWithPrincipal(ctx, command, trustedSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			ref := run.AcceptedDecisionRef{TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
				RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest}
			if _, err := store.PrepareAcceptedDecision(ctx, ref, "11111111-2222-4333-8444-555555555555"); !errors.Is(err, run.ErrDecisionPreparationDenied) {
				t.Fatalf("invalid business objective was accepted: %v", err)
			}
			var count int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns").Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid input allocated a decision turn: %d %v", count, err)
			}
		})
	}
}
