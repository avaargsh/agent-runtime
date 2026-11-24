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
		got.BreakerEpoch != 1 || got.BreakerVersion != 1 ||
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

  
// A CLOSED breaker at initial epoch but a later version is not valid
// generation-one execution authority. Privileged fixture SQL simulates a
// damaged breaker row; supported breaker transitions always advance epochs.
// Neither a fresh Decision authority nor a Continuation may be issued.
func TestDecisionAuthorityRejectsBreakerVersionDrift(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	principal := trustedSnapshot()
	principal.ActorID = principal.SubjectID
	accepted, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{
		TenantID: accepted.TenantID, RunID: accepted.RunID,
		WorkflowID: accepted.WorkflowID, RunIntentID: accepted.RunIntentID,
		RequestDigest: accepted.RequestDigest,
	}
	checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, firstTemporalExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID)
	if err != nil || initial.BreakerEpoch != 1 || initial.BreakerVersion != 1 {
		t.Fatalf("valid initial authority unavailable: %+v err=%v", initial, err)
	}

	if _, err := pool.Exec(ctx, `UPDATE runtime_circuit_breakers
		SET version=2,updated_at=clock_timestamp()
		WHERE scope_kind='RUN' AND scope_id=$1`, ref.RunID); err != nil {
		t.Fatal(err)
	}
	fresh, err := postgres.New(pool).GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID)
	if err == nil {
		t.Errorf("issued fresh Decision authority after breaker version drift: %+v", fresh)
		// RED on the old query: requesting a new receipt with that fresh
		// (but invalid) version can persist a new Continuation.
		receipt := testContinuationReceipt(t, fresh)
		if _, acceptErr := store.AcceptDecisionContinuation(ctx, fresh, receipt); acceptErr == nil {
			t.Error("accepted Continuation from version-drifted Decision authority")
		}
	} else if !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("unexpected rejection of stale Decision authority: %v", err)
	}
	// The original version-one authority must also fail against fresh state.
	if _, err := store.AcceptDecisionContinuation(ctx, initial, testContinuationReceipt(t, initial)); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("stale original continuation accepted: %v", err)
	}
	var attempts, pointers, checkpoints, acceptances, epoch, version int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM runtime_run_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
		(SELECT count(*) FROM runtime_current_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
		(SELECT count(*) FROM runtime_decision_checkpoints WHERE tenant_id=$1 AND run_id=$2::uuid),
		(SELECT count(*) FROM runtime_decision_acceptances WHERE tenant_id=$1 AND run_id=$2::uuid),
		(SELECT epoch FROM runtime_circuit_breakers WHERE scope_kind='RUN' AND scope_id=$2::text),
		(SELECT version FROM runtime_circuit_breakers WHERE scope_kind='RUN' AND scope_id=$2::text)
	`, ref.TenantID, ref.RunID).Scan(&attempts, &pointers, &checkpoints, &acceptances, &epoch, &version); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || pointers != 1 || checkpoints != 1 || acceptances != 0 || epoch != 1 || version != 2 {
		t.Fatalf("version drift changed durable execution evidence: attempts=%d pointers=%d checkpoints=%d acceptances=%d epoch=%d version=%d",
			attempts, pointers, checkpoints, acceptances, epoch, version)
	}
}
