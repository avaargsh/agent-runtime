package postgres_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/startdispatch"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

type lostStartACK struct {
	client.Client
	calls int
}

func (c *lostStartACK) ExecuteWorkflow(ctx context.Context, options client.StartWorkflowOptions, wf interface{}, args ...interface{}) (client.WorkflowRun, error) {
	c.calls++
	_, err := c.Client.ExecuteWorkflow(ctx, options, wf, args...)
	if err != nil {
		return nil, err
	}
	return nil, errors.New("injected loss of committed Temporal start ACK")
}

func TestDevelopmentStartDispatcherRecoversCommittedWorkflowWithoutSecondStart(t *testing.T) {
	if os.Getenv("RUNTIME_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("real Temporal CLI dev-server CI only")
	}
	pool, store := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{Version: "v1.10.0"},
		LogLevel:       "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	c := server.Client()
	w := worker.New(c, startdispatch.DevelopmentQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(startdispatch.AdmissionProbe, workflow.RegisterOptions{Name: startdispatch.DevelopmentWorkflow})
	w.RegisterActivity(&startdispatch.ProbeActivities{Store: store})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	lost := &lostStartACK{Client: c}
	first, err := startdispatch.DispatchOnce(ctx, store, lost, "worker-one", time.Minute, time.Millisecond)
	if err == nil || first.Delivered || lost.calls != 1 {
		t.Fatalf("lost ACK was falsely acknowledged: %+v %v calls=%d", first, err, lost.calls)
	}
	time.Sleep(20 * time.Millisecond)
	second, err := startdispatch.DispatchOnce(ctx, postgres.New(pool), lost, "worker-two", time.Minute, time.Millisecond)
	if err != nil || !second.Delivered || lost.calls != 1 || second.RunID != receipt.RunID || second.ExecutionID == "" {
		t.Fatalf("recovery did not verify original execution: %+v %v calls=%d", second, err, lost.calls)
	}
	var result startdispatch.ProbeResult
	if err := c.GetWorkflow(ctx, receipt.WorkflowID, second.ExecutionID).Get(ctx, &result); err != nil {
		t.Fatal(err)
	}
	if result.RunID != receipt.RunID || result.ExecutionID != second.ExecutionID || result.AttemptID == "" || result.TurnID == "" {
		t.Fatalf("probe did not bind server execution to durable identity: %+v", result)
	}
	var delivered, attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT count(delivered_at), max(attempts) FROM runtime_outbox WHERE aggregate_id=$1::uuid AND event_type='RUN_START_REQUESTED'", receipt.RunID).Scan(&delivered, &attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid", receipt.TenantID, receipt.RunID).Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 || attempts != 2 || turns != 1 {
		t.Fatalf("delivery or turn cardinality is wrong: %d/%d/%d", delivered, attempts, turns)
	}
}

func unrelatedDevelopmentWorkflow(workflow.Context) error { return nil }

func TestDevelopmentStartDispatcherDoesNotAcknowledgeUnrelatedWorkflow(t *testing.T) {
	if os.Getenv("RUNTIME_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("real Temporal CLI dev-server CI only")
	}
	pool, store := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{Version: "v1.10.0"},
		LogLevel:       "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	c := server.Client()
	_, err = c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: receipt.WorkflowID, TaskQueue: startdispatch.DevelopmentQueue,
	}, unrelatedDevelopmentWorkflow)
	if err != nil {
		t.Fatal(err)
	}
	got, err := startdispatch.DispatchOnce(ctx, store, c, "worker", time.Minute, time.Millisecond)
	if err == nil || got.Delivered {
		t.Fatalf("unrelated Workflow was treated as accepted: %+v %v", got, err)
	}
	time.Sleep(20 * time.Millisecond)
	recovered, err := startdispatch.DispatchOnce(ctx, store, c, "worker-two", time.Minute, time.Millisecond)
	if !errors.Is(err, startdispatch.ErrExecutionConflict) || recovered.Delivered {
		t.Fatalf("recovery accepted unrelated start history: %+v %v", recovered, err)
	}
	var delivered int
	if err := pool.QueryRow(ctx, "SELECT count(delivered_at) FROM runtime_outbox WHERE aggregate_id=$1::uuid AND event_type='RUN_START_REQUESTED'", receipt.RunID).Scan(&delivered); err != nil || delivered != 0 {
		t.Fatalf("unrelated execution acknowledged durable event: %d %v", delivered, err)
	}
}
