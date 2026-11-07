package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// No model, tools, Decision or protected side effects are ever invoked by
// this test Workflow. This exercises only Temporal's durable ID semantics.
func temporalStartIdentityProbe(ctx workflow.Context) error {
	var done string
	workflow.GetSignalChannel(ctx, "finish").Receive(ctx, &done)
	if done != "verified" {
		return errors.New("unexpected test signal")
	}
	return nil
}

func TestTemporalStartLostACKAndServerWorkerRestartPreservesWorkflowIdentity(t *testing.T) {
	if os.Getenv("RUNTIME_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("real Temporal CLI dev-server CI only")
	}
	pool, store := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	receipt, err := store.AcceptIntent(ctx, testIntent())
	if err != nil {
		t.Fatal(err)
	}
	first, found, err := store.ClaimRuntimeStart(ctx, "temporal-worker-1", 2*time.Minute)
	if err != nil || !found || first.RunID != receipt.RunID || first.WorkflowID != receipt.WorkflowID {
		t.Fatalf("initial Outbox claim: %+v found=%v err=%v", first, found, err)
	}
	// Use the same SQLite history across actual Temporal Server processes.
	opts := testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{Version: "v1.10.0"},
		DBFilename: filepath.Join(t.TempDir(), "temporal-history.db"),
		LogLevel: "error",
	}
	server, err := testsuite.StartDevServer(ctx, opts)
	if err != nil {
		t.Fatalf("start pinned Temporal dev server: %v", err)
	}
	t.Cleanup(func() { _ = server.Stop() })
	c := server.Client()
	queue := "runtime-start-identity-probe"
	w := worker.New(c, queue, worker.Options{})
	w.RegisterWorkflow(temporalStartIdentityProbe)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	workflowOptions := client.StartWorkflowOptions{
		ID: first.WorkflowID,
		TaskQueue: queue,
		WorkflowIDReusePolicy: enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}
	execution, err := c.ExecuteWorkflow(ctx, workflowOptions, temporalStartIdentityProbe)
	if err != nil {
		t.Fatalf("first real Temporal start: %v", err)
	}
	temporalRunID := execution.GetRunID()
	if execution.GetID() != first.WorkflowID || temporalRunID == "" {
		t.Fatalf("Temporal changed canonical Workflow ID: %s %s", execution.GetID(), temporalRunID)
	}
	// Pretend Runtime died before persisting the Temporal start ACK. No
	// AcknowledgeRuntimeStart call occurs. A second worker claims this event.
	if _, err := pool.Exec(ctx,
		"UPDATE runtime_outbox SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE outbox_id=$1::uuid",
		first.OutboxID,
	); err != nil {
		t.Fatal(err)
	}
	second, found, err := postgres.New(pool).ClaimRuntimeStart(ctx, "temporal-worker-2", 2*time.Minute)
	if err != nil || !found || second.WorkflowID != first.WorkflowID || second.RunID != first.RunID {
		t.Fatalf("reclaimed Outbox changed canonical identity: %+v err=%v", second, err)
	}
	if err := store.AcknowledgeRuntimeStart(ctx, first); !errors.Is(err, postgres.ErrRuntimeStartLeaseLost) {
		t.Fatalf("stale worker acknowledged lost Temporal ACK: %v", err)
	}
	assertAlreadyStarted := func(c client.Client) {
		t.Helper()
		_, err := c.ExecuteWorkflow(ctx, workflowOptions, temporalStartIdentityProbe)
		var already *serviceerror.WorkflowExecutionAlreadyStarted
		if !errors.As(err, &already) {
			t.Fatalf("duplicate Temporal Start not rejected: %v", err)
		}
		description, err := c.DescribeWorkflowExecution(ctx, first.WorkflowID, "")
		if err != nil {
			t.Fatal(err)
		}
		if description.GetWorkflowExecutionInfo().GetExecution().GetRunId() != temporalRunID {
			t.Fatalf("duplicate Temporal execution created after lost ACK: %+v", description.GetWorkflowExecutionInfo())
		}
	}
	assertAlreadyStarted(c)

	// Stop both the actual Worker and Temporal Server. Restart with the same
	// SQLite history and reattach a new Worker before reconciling.
	w.Stop()
	c.Close()
	if err := server.Stop(); err != nil {
		t.Fatalf("stop Temporal server: %v", err)
	}
	server, err = testsuite.StartDevServer(ctx, opts)
	if err != nil {
		t.Fatalf("restart persisted Temporal server: %v", err)
	}
	c = server.Client()
	w = worker.New(c, queue, worker.Options{})
	w.RegisterWorkflow(temporalStartIdentityProbe)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	assertAlreadyStarted(c)
	if err := c.SignalWorkflow(ctx, first.WorkflowID, temporalRunID, "finish", "verified"); err != nil {
		t.Fatalf("restarted Worker did not receive existing history: %v", err)
	}
	if err := c.GetWorkflow(ctx, first.WorkflowID, temporalRunID).Get(ctx, nil); err != nil {
		t.Fatalf("recovered Workflow did not complete: %v", err)
	}
	// Completion must not free the Workflow ID for a second logical Run.
	assertAlreadyStarted(c)
	if err := store.AcknowledgeRuntimeStart(ctx, second); err != nil {
		t.Fatalf("verified single Workflow not ACKed to PostgreSQL: %v", err)
	}
	var runs, starts, delivered int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runs WHERE run_intent_id=$1::uuid", sampleIntentID).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		"SELECT count(*), count(delivered_at) FROM runtime_outbox WHERE aggregate_id=$1::uuid AND event_type='RUN_START_REQUESTED'",
		first.RunID,
	).Scan(&starts, &delivered); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || starts != 1 || delivered != 1 {
		t.Fatalf("duplicate Run/Outbox after Temporal restart: %d/%d/%d", runs, starts, delivered)
	}
}
