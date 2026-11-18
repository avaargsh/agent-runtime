package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/activities"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// Real Temporal + PostgreSQL behavior test. This isolated fixture uses
// synthetic Decision digests; a separate source-pinned test must prove the
// actual network adapter and independently authenticated Decision service.
func TestBusinessWorkflowConsumesFencedDecision(t *testing.T) {
	if os.Getenv("RUNTIME_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("real Temporal and PostgreSQL CI only")
	}
	pool, store := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"errors"}`)
	principal := trustedSnapshot()
	principal.ActorID = principal.SubjectID
	accepted, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{TenantID: accepted.TenantID, RunID: accepted.RunID, WorkflowID: accepted.WorkflowID,
		RunIntentID: accepted.RunIntentID, RequestDigest: accepted.RequestDigest}
	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{Version: "v1.10.0"},
		DBFilename: filepath.Join(t.TempDir(), "continuation.db"), LogLevel: "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	c := server.Client()
	defer c.Close()
	w := worker.New(c, workflows.AcceptedDecisionQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(workflows.AcceptedDecision, workflow.RegisterOptions{Name: workflows.AcceptedDecisionWorkflow})
	w.RegisterActivity(&activities.DecisionPreparation{Store: store})
	w.RegisterActivityWithOptions(func(ctx context.Context, cp run.DecisionCheckpoint) (run.DecisionCheckpoint, error) {
		a, err := store.GetDecisionAuthority(ctx, cp.TenantID, cp.RunID, cp.TurnID)
		if err != nil {
			return run.DecisionCheckpoint{}, err
		}
		receipt := testContinuationReceipt(t, a)
		if _, err := store.AcceptDecisionContinuation(ctx, a, receipt); err != nil {
			return run.DecisionCheckpoint{}, err
		}
		cp.Phase = "DECISION_ACCEPTED"
		return cp, nil
	}, activity.RegisterOptions{Name: "ContinueAcceptedDecision"})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	execution, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: ref.WorkflowID, TaskQueue: workflows.AcceptedDecisionQueue,
		WorkflowExecutionTimeout: time.Minute}, workflows.AcceptedDecisionWorkflow, ref)
	if err != nil {
		t.Fatal(err)
	}
	waitPhase := func(phase string) run.DecisionCheckpoint {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			var cp run.DecisionCheckpoint
			q, err := c.QueryWorkflow(ctx, ref.WorkflowID, execution.GetRunID(), workflows.AcceptedDecisionCheckpointQuery)
			if err == nil && q.Get(&cp) == nil && cp.Phase == phase {
				return cp
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("actual business Workflow never reached %s", phase)
		return run.DecisionCheckpoint{}
	}
	initial := waitPhase(run.DecisionWaitingAuthority)
	if err := c.SignalWorkflow(ctx, ref.WorkflowID, execution.GetRunID(), "decision-continuation-ready-v1", nil); err != nil {
		t.Fatal(err)
	}
	cp := waitPhase("DECISION_ACCEPTED")
	if cp.RunID != initial.RunID || cp.ExecutionID != initial.ExecutionID || cp.AttemptID != initial.AttemptID || cp.TurnID != initial.TurnID {
		t.Fatal("continuation changed canonical execution")
	}
	var facts int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_acceptances").Scan(&facts); err != nil || facts != 1 {
		t.Fatalf("no exact durable acceptance %d %v", facts, err)
	}
	if err := c.CancelWorkflow(ctx, ref.WorkflowID, execution.GetRunID()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Get(ctx, nil); err == nil {
		t.Fatal("continuation incorrectly completed business Run")
	}
	var lifecycle string
	if err := pool.QueryRow(ctx, "SELECT status FROM runs WHERE run_id=$1::uuid", ref.RunID).Scan(&lifecycle); err != nil || lifecycle != "CANCELLED" {
		t.Fatalf("pre-effect cancellation not reconciled: %s %v", lifecycle, err)
	}
}
