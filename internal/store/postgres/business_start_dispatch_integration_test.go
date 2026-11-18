package postgres_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/activities"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/startdispatch"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

func TestBusinessStartDispatcherUsesRealCheckpointAndRecoversLostACK(t *testing.T) {
	if os.Getenv("RUNTIME_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("actual Temporal server and PG integration only")
	}
	pool, store := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{Version: "v1.10.0"}, LogLevel: "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	c := server.Client()
	w := worker.New(c, workflows.AcceptedDecisionQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(workflows.AcceptedDecision, workflow.RegisterOptions{Name: workflows.AcceptedDecisionWorkflow})
	w.RegisterActivity(&activities.DecisionPreparation{Store: store})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	lost := &lostStartACK{Client: c}
	first, err := startdispatch.DispatchAcceptedDecisionOnce(ctx, store, lost, "business-first", time.Minute, time.Millisecond)
	if err == nil || first.Delivered || lost.calls != 1 {
		t.Fatalf("lost business start ACK treated as success: %+v %v", first, err)
	}
	time.Sleep(20 * time.Millisecond)
	// A probe consumer must never adopt the business Workflow's history.
	wrong, err := startdispatch.DispatchOnce(ctx, store, lost, "wrong-profile", time.Minute, time.Millisecond)
	if !errors.Is(err, startdispatch.ErrExecutionConflict) || wrong.Delivered || lost.calls != 1 {
		t.Fatalf("probe consumer accepted unrelated business history: %+v %v", wrong, err)
	}
	time.Sleep(20 * time.Millisecond)
	second, err := startdispatch.DispatchAcceptedDecisionOnce(ctx, postgres.New(pool), lost, "business-recovered", time.Minute, time.Millisecond)
	if err != nil || !second.Delivered || second.RunID != receipt.RunID || lost.calls != 1 {
		t.Fatalf("business dispatcher replay created or accepted another execution: %+v %v", second, err)
	}
	var checkpoint run.DecisionCheckpoint
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		value, err := c.QueryWorkflow(ctx, receipt.WorkflowID, second.ExecutionID, workflows.AcceptedDecisionCheckpointQuery)
		if err == nil && value.Get(&checkpoint) == nil && checkpoint.Phase == run.DecisionWaitingAuthority {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if checkpoint.RunID != receipt.RunID || checkpoint.ExecutionID != second.ExecutionID ||
		checkpoint.Phase != run.DecisionWaitingAuthority || checkpoint.AttemptID == "" || checkpoint.TurnID == "" {
		t.Fatalf("actual business checkpoint did not preserve Run: %+v", checkpoint)
	}
	desc, err := c.DescribeWorkflowExecution(ctx, receipt.WorkflowID, second.ExecutionID)
	if err != nil || desc.GetWorkflowExecutionInfo().GetStatus() != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING {
		t.Fatal("business workflow completed at an authority boundary")
	}
	var status string
	var checkpoints, attempts, turns, delivered int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT status FROM runs WHERE run_id=$1::uuid),
		       (SELECT count(*) FROM runtime_decision_checkpoints),
		       (SELECT count(*) FROM runtime_run_attempts),
		       (SELECT count(*) FROM runtime_decision_turns),
		       (SELECT count(delivered_at) FROM runtime_outbox WHERE event_type='RUN_START_REQUESTED')
	`, receipt.RunID).Scan(&status, &checkpoints, &attempts, &turns, &delivered); err != nil ||
		status != "RUNNING" || checkpoints != 1 || attempts != 1 || turns != 1 || delivered != 1 {
		t.Fatalf("business preparation/Runtime status not atomically bound: %s %d/%d/%d/%d %v", status, checkpoints, attempts, turns, delivered, err)
	}
	if err := c.CancelWorkflow(ctx, receipt.WorkflowID, second.ExecutionID); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual business dispatcher recovered canonical Run %s at WAITING_AUTHORITY, no effect authorized", receipt.RunID)
}
