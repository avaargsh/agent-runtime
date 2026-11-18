package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/activities"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	"github.com/jackc/pgx/v5/pgxpool"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"
)

// The child deliberately blocks ONLY after the real PostgreSQL transaction
// has committed and before returning the Activity result. The parent uses
// SIGKILL, not a simulated error or a graceful shutdown.
func TestAcceptedDecisionCheckpointWorkerProcess(t *testing.T) {
	if os.Getenv("RUNTIME_CHECKPOINT_WORKER") != "1" {
		t.Skip("subprocess helper, enabled only by real Temporal test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dsn, schema := os.Getenv("TEST_DATABASE_URL"), os.Getenv("RUNTIME_CHECKPOINT_SCHEMA")
	addr, marker := os.Getenv("RUNTIME_CHECKPOINT_TEMPORAL"), os.Getenv("RUNTIME_CHECKPOINT_MARKER")
	if dsn == "" || schema == "" || addr == "" || marker == "" {
		t.Fatal("missing isolated subprocess configuration")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	c, err := client.Dial(client.Options{HostPort: addr})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	w := worker.New(c, workflows.AcceptedDecisionQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(workflows.AcceptedDecision, workflow.RegisterOptions{Name: workflows.AcceptedDecisionWorkflow})
	preparation := &activities.DecisionPreparation{Store: postgres.New(pool)}
	w.RegisterActivityWithOptions(func(ctx context.Context, ref run.AcceptedDecisionRef) (run.DecisionCheckpoint, error) {
		checkpoint, err := preparation.PrepareAcceptedDecision(ctx, ref)
		if err != nil {
			return run.DecisionCheckpoint{}, err
		}
		if err := os.WriteFile(marker, []byte(checkpoint.TurnID), 0600); err != nil {
			return run.DecisionCheckpoint{}, err
		}
		<-ctx.Done()
		return run.DecisionCheckpoint{}, ctx.Err()
	}, activity.RegisterOptions{Name: "PrepareAcceptedDecision"})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	<-ctx.Done()
	t.Fatal("checkpoint worker was not killed")
}

func TestAcceptedDecisionCheckpointSurvivesWorkerSIGKILL(t *testing.T) {
	if os.Getenv("RUNTIME_TEMPORAL_INTEGRATION") != "1" {
		t.Skip("real Temporal and PostgreSQL CI only")
	}
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Fatal("real Temporal test requires PostgreSQL")
	}
	pool, store := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	const canary = "payments-checkpoint-canary-not-in-history"
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"` + canary + `","signal":"latency"}`)
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{TenantID: receipt.TenantID, RunID: receipt.RunID,
		WorkflowID: receipt.WorkflowID, RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest}
	path := t.TempDir()
	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{Version: "v1.10.0"},
		DBFilename:     filepath.Join(path, "history.db"),
		LogLevel:       "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	c := server.Client()
	defer c.Close()
	execution, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                                       ref.WorkflowID,
		TaskQueue:                                workflows.AcceptedDecisionQueue,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowIDConflictPolicy:                 enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
		WorkflowExecutionTimeout:                 2 * time.Minute,
	}, workflows.AcceptedDecisionWorkflow, ref)
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "checkpoint-committed")
	child := exec.CommandContext(ctx, bin, "-test.run=^TestAcceptedDecisionCheckpointWorkerProcess$", "-test.v")
	child.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"TEST_DATABASE_URL=" + os.Getenv("TEST_DATABASE_URL"),
		"RUNTIME_CHECKPOINT_WORKER=1", "RUNTIME_CHECKPOINT_SCHEMA=" + pool.Config().ConnConfig.RuntimeParams["search_path"],
		"RUNTIME_CHECKPOINT_TEMPORAL=" + server.FrontendHostPort(), "RUNTIME_CHECKPOINT_MARKER=" + marker,
	}
	logFile, err := os.Create(filepath.Join(path, "worker.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	child.Stdout, child.Stderr = logFile, logFile
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	var turn []byte
	until := time.Now().Add(30 * time.Second)
	for time.Now().Before(until) {
		turn, err = os.ReadFile(marker)
		if err == nil && len(turn) != 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(turn) == 0 {
		t.Fatal("real Worker did not commit checkpoint before fault injection")
	}
	var committedAttempt, committedTurn, committedDigest string
	if err := pool.QueryRow(ctx, "SELECT attempt_id::text,turn_id::text,input_digest FROM runtime_decision_checkpoints WHERE run_id=$1::uuid", ref.RunID).
		Scan(&committedAttempt, &committedTurn, &committedDigest); err != nil || committedTurn != string(turn) {
		t.Fatalf("child marker was not backed by durable checkpoint: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	killErr := child.Wait()
	waited = true
	var exit *exec.ExitError
	if !errors.As(killErr, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("expected real SIGKILL: %v", killErr)
	}
	// The replacement worker uses actual Activity implementation, with no
	// fault hook. Temporal retries the same logical preparation after timeout.
	w := worker.New(c, workflows.AcceptedDecisionQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(workflows.AcceptedDecision, workflow.RegisterOptions{Name: workflows.AcceptedDecisionWorkflow})
	w.RegisterActivity(&activities.DecisionPreparation{Store: postgres.New(pool)})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	var result run.DecisionCheckpoint
	queryDeadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(queryDeadline) {
		value, err := c.QueryWorkflow(ctx, ref.WorkflowID, execution.GetRunID(), workflows.AcceptedDecisionCheckpointQuery)
		if err == nil && value.Get(&result) == nil && result.Phase == run.DecisionWaitingAuthority {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	desc, err := c.DescribeWorkflowExecution(ctx, ref.WorkflowID, execution.GetRunID())
	if err != nil || desc.GetWorkflowExecutionInfo().GetStatus() != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING {
		t.Fatalf("business Workflow did not remain paused at authority gate: %v", err)
	}
	if result.AcceptedDecisionRef != ref || result.AttemptID != committedAttempt || result.TurnID != committedTurn ||
		result.InputDigest != committedDigest || result.ExecutionID != execution.GetRunID() ||
		result.Phase != run.DecisionWaitingAuthority {
		t.Fatalf("crash recovery changed committed business checkpoint: %+v", result)
	}
	var checkpoints, turns, attempts int
	var status string
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM runtime_decision_checkpoints),
		       (SELECT count(*) FROM runtime_decision_turns),
		       (SELECT count(*) FROM runtime_run_attempts),
		       (SELECT status FROM runs WHERE run_id=$1::uuid)
	`, ref.RunID).Scan(&checkpoints, &turns, &attempts, &status); err != nil ||
		checkpoints != 1 || turns != 1 || attempts != 1 || status != "RUNNING" {
		t.Fatalf("recovery duplicated state or forged business success: %d/%d/%d/%s %v", checkpoints, turns, attempts, status, err)
	}
	history := c.GetWorkflowHistory(ctx, ref.WorkflowID, execution.GetRunID(), false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	for history.HasNext() {
		event, err := history.Next()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := proto.Marshal(event)
		if err != nil || bytes.Contains(encoded, []byte(canary)) {
			t.Fatal("raw business input escaped into Temporal history")
		}
	}
	if err := c.CancelWorkflow(ctx, ref.WorkflowID, execution.GetRunID()); err != nil {
		t.Fatal(err)
	}
	var canceled *temporal.CanceledError
	if err := c.GetWorkflow(ctx, ref.WorkflowID, execution.GetRunID()).Get(ctx, nil); !errors.As(err, &canceled) {
		t.Fatalf("paused workflow was not canceled without business success: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT status FROM runs WHERE run_id=$1::uuid", ref.RunID).Scan(&status); err != nil || status != "CANCELLED" {
		t.Fatalf("pre-effect Workflow cancellation did not reconcile Runtime lifecycle: %s %v", status, err)
	}
	t.Logf("SIGKILL recovered Run %s, Attempt %s, Turn %s, phase %s", ref.RunID, result.AttemptID, result.TurnID, result.Phase)
}
