package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/startdispatch"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// This driver consumes the one already accepted ACP Run in an explicitly
// disposable external Runtime DB. Unlike the repo-local fixture, it must
// never call AcceptIntent, fabricate the principal, or seed a new Run.
func TestExternalACPAdmissionTemporalRecovery(t *testing.T) {
	if os.Getenv("RUNTIME_EXTERNAL_ACP_TEST") != "1" {
		t.Skip("only the pinned cross-repository Golden Path harness enables this")
	}
	required := func(name string) string {
		t.Helper()
		got := os.Getenv(name)
		if got == "" {
			t.Fatalf("external acceptance missing %s", name)
		}
		return got
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, required("RUNTIME_EXTERNAL_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := postgres.New(pool)
	tenant, intentID, digest := required("RUNTIME_EXTERNAL_TENANT"), required("RUNTIME_EXTERNAL_INTENT"), required("RUNTIME_EXTERNAL_DIGEST")
	runID := required("RUNTIME_EXTERNAL_RUN")
	receipt, err := store.LookupIntent(ctx, tenant, intentID, digest)
	if err != nil || receipt.RunID != runID || receipt.WorkflowID != "agent-run/v1/"+runID {
		t.Fatalf("ACP acceptance correlation missing: %+v %v", receipt, err)
	}
	principal, err := store.GetRunPrincipalSnapshot(ctx, tenant, runID)
	if err != nil || principal.SubjectID != required("RUNTIME_EXTERNAL_SUBJECT") ||
		principal.ActorID != required("RUNTIME_EXTERNAL_ACTOR") ||
		principal.PolicyRevision != required("RUNTIME_EXTERNAL_POLICY") {
		t.Fatalf("accepted principal missing or mismatched: %v", err)
	}
	var rows, pending, attempts int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM runs),
		       (SELECT count(*) FROM runtime_outbox WHERE event_type='RUN_START_REQUESTED' AND delivered_at IS NULL),
		       (SELECT count(*) FROM runtime_run_attempts)
	`).Scan(&rows, &pending, &attempts); err != nil || rows != 1 || pending != 1 || attempts != 0 {
		t.Fatalf("external harness requires one isolated, not-yet-executed ACP Run: %d/%d/%d %v", rows, pending, attempts, err)
	}
	options := testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{Version: "v1.10.0"},
		DBFilename:     filepath.Join(t.TempDir(), "external-acp-temporal.db"),
		LogLevel:       "error",
	}
	server, err := testsuite.StartDevServer(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Stop() })
	c := server.Client()
	// Start with no Worker. Temporal must commit the actual Workflow before
	// a Worker sees it. The existing fault injector loses the accepted ACK.
	lost := &lostStartACK{Client: c}
	first, err := startdispatch.DispatchOnce(ctx, store, lost, "external-first", time.Minute, time.Millisecond)
	if err == nil || first.Delivered || !first.Found || first.RunID != runID || lost.calls != 1 {
		t.Fatalf("external Run did not enter uncertain start: %+v %v", first, err)
	}
	desc, err := c.DescribeWorkflowExecution(ctx, receipt.WorkflowID, "")
	if err != nil {
		t.Fatal("Temporal did not commit external ACP Run")
	}
	executionID := desc.GetWorkflowExecutionInfo().GetExecution().GetRunId()
	if executionID == "" {
		t.Fatal("missing server-assigned execution")
	}
	c.Close()
	if err := server.Stop(); err != nil {
		t.Fatal(err)
	}
	server, err = testsuite.StartDevServer(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	c = server.Client()
	lost.Client = c
	w := worker.New(c, startdispatch.DevelopmentQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(startdispatch.AdmissionProbe, workflow.RegisterOptions{Name: startdispatch.DevelopmentWorkflow})
	w.RegisterActivity(&startdispatch.ProbeActivities{Store: postgres.New(pool)})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	second, err := startdispatch.DispatchOnce(ctx, postgres.New(pool), lost, "external-restarted", time.Minute, time.Millisecond)
	if err != nil || !second.Delivered || second.RunID != runID ||
		second.ExecutionID != executionID || lost.calls != 1 {
		t.Fatalf("external recovery created or accepted a second execution: %+v %v", second, err)
	}
	var result startdispatch.ProbeResult
	if err := c.GetWorkflow(ctx, receipt.WorkflowID, executionID).Get(ctx, &result); err != nil {
		t.Fatal(err)
	}
	if result.RunID != runID || result.ExecutionID != executionID || result.AttemptID == "" || result.TurnID == "" {
		t.Fatalf("Temporal result identity differs from accepted ACP Run: %+v", result)
	}
	again, err := startdispatch.DispatchOnce(ctx, store, c, "external-terminal", time.Minute, time.Second)
	if err != nil || again.Found {
		t.Fatalf("delivered start was re-claimed: %+v %v", again, err)
	}
	bound, err := store.GetOrCreateTemporalTurn(ctx, tenant, runID, receipt.WorkflowID, executionID, 1)
	if err != nil || bound.RunAttemptID != result.AttemptID || bound.TurnID != result.TurnID {
		t.Fatalf("persistent attempt/turn mismatch: %+v %v", bound, err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, tenant, runID, receipt.WorkflowID, secondTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalExecutionConflict) {
		t.Fatalf("different execution could claim this Run: %v", err)
	}
	var runs, starts, delivered, turns int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM runs),
		       (SELECT count(*) FROM runtime_outbox WHERE event_type='RUN_START_REQUESTED'),
		       (SELECT count(delivered_at) FROM runtime_outbox WHERE event_type='RUN_START_REQUESTED'),
		       (SELECT count(*) FROM runtime_decision_turns)
	`).Scan(&runs, &starts, &delivered, &turns); err != nil || runs != 1 || starts != 1 || delivered != 1 || turns != 1 {
		t.Fatalf("external chain duplicated durable work: %d/%d/%d/%d %v", runs, starts, delivered, turns, err)
	}
	t.Logf("external ACP Run %s, Workflow %s, Temporal execution %s, Attempt %s, Turn %s", runID, receipt.WorkflowID, executionID, result.AttemptID, result.TurnID)
}
