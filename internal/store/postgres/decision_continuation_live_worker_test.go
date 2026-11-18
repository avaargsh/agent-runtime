package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/activities"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	"github.com/jackc/pgx/v5/pgxpool"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

func liveContinuationClient(t *testing.T, dir, keyPath string) *decision.ContinuationClient {
	t.Helper()
	origin, err := os.ReadFile(filepath.Join(dir, "origin"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(dir, "decision-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("missing test Decision CA")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "worker-cert.pem"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decision.NewContinuationClient(string(origin), "spiffe://example.org/decision-api", roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Only this isolated subprocess runs the actual Activity with a fault hook.
// It blocks after the committed CAS and before the Activity ACK, allowing the
// parent to kill the worker. No failure is simulated inside the repository.
func TestVerifiedDecisionContinuationWorkerProcess(t *testing.T) {
	if os.Getenv("RUNTIME_CONTINUATION_WORKER") != "1" {
		t.Skip("external live Decision recovery subprocess only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	required := func(name string) string {
		t.Helper()
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("missing isolated worker configuration %s", name)
		}
		return v
	}
	cfg, err := pgxpool.ParseConfig(required("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = required("RUNTIME_CONTINUATION_SCHEMA")
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	c, err := client.Dial(client.Options{HostPort: required("RUNTIME_CONTINUATION_TEMPORAL")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	store := postgres.New(pool)
	actual := &activities.DecisionContinuation{Store: store,
		Client: liveContinuationClient(t, required("RUNTIME_CONTINUATION_DIR"), required("RUNTIME_CONTINUATION_KEY"))}
	marker := required("RUNTIME_CONTINUATION_MARKER")
	w := worker.New(c, workflows.AcceptedDecisionQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(workflows.AcceptedDecision, workflow.RegisterOptions{Name: workflows.AcceptedDecisionWorkflow})
	w.RegisterActivity(&activities.DecisionPreparation{Store: store})
	w.RegisterActivityWithOptions(func(ctx context.Context, cp run.DecisionCheckpoint) (run.DecisionCheckpoint, error) {
		got, err := actual.ContinueAcceptedDecision(ctx, cp)
		if err != nil {
			return run.DecisionCheckpoint{}, err
		}
		if err := os.WriteFile(marker+".tmp", []byte(got.DecisionID), 0600); err != nil {
			return run.DecisionCheckpoint{}, err
		}
		if err := os.Rename(marker+".tmp", marker); err != nil {
			return run.DecisionCheckpoint{}, err
		}
		<-ctx.Done()
		return run.DecisionCheckpoint{}, ctx.Err()
	}, activity.RegisterOptions{Name: "ContinueAcceptedDecision"})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	<-ctx.Done()
	t.Fatal("continuation Worker was not killed")
}

func waitContinuationFixture(t *testing.T, ctx context.Context, path string, limit time.Duration) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		b, err := os.ReadFile(path)
		if err == nil && len(b) != 0 {
			return b
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("missing continuation fixture marker %s", filepath.Base(path))
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// The independently compiled Decision test owns its database and real
// source registries. Runtime owns its DB, private key and Temporal Worker;
// only public CSR/certificates and synchronization markers are exchanged.
func recoverLiveDecisionContinuation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, c client.Client,
	frontend string, cp run.DecisionCheckpoint, dsn, schema string, verify *exec.Cmd,
) (worker.Worker, run.DecisionCheckpoint, []byte) {
	t.Helper()
	dir, privateDir := t.TempDir(), t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := url.Parse("spiffe://example.org/runtime-worker")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{id}}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(privateDir, "worker-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "worker.csr"), csr, 0600); err != nil {
		t.Fatal(err)
	}
	verify.Env = append(verify.Env, "DECISION_LIVE_RUNTIME_CONTINUATION_DIR="+dir)
	var log bytes.Buffer
	verify.Stdout, verify.Stderr = &log, &log
	if err := verify.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = verify.Process.Kill()
			_ = verify.Wait()
			t.Logf("Decision process evidence on failure:\n%s", log.Bytes())
		}
	}()
	waitContinuationFixture(t, ctx, filepath.Join(dir, "origin"), 30*time.Second)
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(privateDir, "acceptance-committed")
	child := exec.CommandContext(ctx, bin, "-test.v", "-test.run=^TestVerifiedDecisionContinuationWorkerProcess$")
	child.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"TEST_DATABASE_URL=" + dsn,
		"RUNTIME_CONTINUATION_WORKER=1",
		"RUNTIME_CONTINUATION_SCHEMA=" + schema,
		"RUNTIME_CONTINUATION_TEMPORAL=" + frontend,
		"RUNTIME_CONTINUATION_DIR=" + dir,
		"RUNTIME_CONTINUATION_KEY=" + keyPath,
		"RUNTIME_CONTINUATION_MARKER=" + marker,
	}
	var workerLog bytes.Buffer
	child.Stdout, child.Stderr = &workerLog, &workerLog
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childWaited := false
	defer func() {
		if !childWaited {
			_ = child.Process.Kill()
			_ = child.Wait()
			t.Logf("worker process evidence on failure:\n%s", workerLog.Bytes())
		}
	}()
	if err := c.SignalWorkflow(ctx, cp.WorkflowID, cp.ExecutionID, workflows.AcceptedDecisionReadySignal, nil); err != nil {
		t.Fatal(err)
	}
	decisionID := string(waitContinuationFixture(t, ctx, marker, 35*time.Second))
	var durable run.DecisionContinuationReceipt
	var receipt []byte
	if err := pool.QueryRow(ctx, "SELECT receipt FROM runtime_decision_acceptances WHERE tenant_id=$1 AND run_id=$2::uuid", cp.TenantID, cp.RunID).Scan(&receipt); err != nil ||
		json.Unmarshal(receipt, &durable) != nil || durable.Validate() != nil ||
		durable.DecisionID != decisionID || durable.Authority.ExecutionID != cp.ExecutionID ||
		durable.Authority.AttemptID != cp.AttemptID || durable.Authority.TurnID != cp.TurnID {
		t.Fatalf("worker marker lacks exact committed acceptance: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	killErr := child.Wait()
	childWaited = true
	var exit *exec.ExitError
	if !errors.As(killErr, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("expected real continuation Worker SIGKILL: %v", killErr)
	}
	store := postgres.New(pool)
	actual := &activities.DecisionContinuation{Store: store, Client: liveContinuationClient(t, dir, keyPath)}
	w := worker.New(c, workflows.AcceptedDecisionQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(workflows.AcceptedDecision, workflow.RegisterOptions{Name: workflows.AcceptedDecisionWorkflow})
	w.RegisterActivity(&activities.DecisionPreparation{Store: store})
    // Record the real post-SIGKILL attempt result, not merely the Workflow
    // projection. Errors here are the evidence needed to fix lost-ACK recovery.
    w.RegisterActivityWithOptions(func(ctx context.Context, cp run.DecisionCheckpoint) (run.DecisionCheckpoint, error) {
        got, err := actual.ContinueAcceptedDecision(ctx, cp)
        if err != nil {
            t.Logf("TRACE recovered Decision Activity denied: %v", err)
        } else {
            t.Logf("TRACE recovered Decision Activity accepted: id=%s record=%s", got.DecisionID, got.RecordSHA256)
        }
        return got, err
    }, activity.RegisterOptions{Name: "ContinueAcceptedDecision"})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	success := false
	defer func() {
		if !success {
			w.Stop()
		}
	}()
	var result run.DecisionCheckpoint
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		q, err := c.QueryWorkflow(ctx, cp.WorkflowID, cp.ExecutionID, workflows.AcceptedDecisionCheckpointQuery)
		if err == nil && q.Get(&result) == nil && result.Phase == run.DecisionAccepted {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	original := result
	original.Phase = run.DecisionWaitingAuthority
	original.DecisionID, original.RecordSHA256, original.PlanHash = "", "", ""
	if original != cp || result.Phase != run.DecisionAccepted || result.DecisionID != durable.DecisionID ||
		result.RecordSHA256 != durable.RecordSHA256 || result.PlanHash != durable.PlanHash {
		t.Fatalf("real Worker recovery failed: %+v", result)
	}
	var count int
	var lifecycle string
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM runtime_decision_acceptances),status FROM runs WHERE run_id=$1::uuid", cp.RunID).Scan(&count, &lifecycle); err != nil ||
		count != 1 || lifecycle != "RUNNING" {
		t.Fatalf("continuation duplicated or completed Run: %d %s %v", count, lifecycle, err)
	}
	desc, err := c.DescribeWorkflowExecution(ctx, cp.WorkflowID, cp.ExecutionID)
	if err != nil || desc.GetWorkflowExecutionInfo().GetStatus() != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING {
		t.Fatal("nonterminal continuation completed canonical Workflow")
	}
	if err := os.WriteFile(filepath.Join(dir, "runtime-accepted"), []byte("accepted"), 0600); err != nil {
		t.Fatal(err)
	}
	waitContinuationFixture(t, ctx, filepath.Join(dir, "source-revoked"), 15*time.Second)
	// Even a recovered, committed historical result does not allow new
	// execution after a source revokes its authority.
	current, err := store.GetDecisionAuthority(ctx, cp.TenantID, cp.RunID, cp.TurnID)
	if err != nil || current != durable.Authority {
		t.Fatalf("current business authority changed unexpectedly: %v", err)
	}
	if _, err := actual.Client.Verify(ctx, current); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("revoked Evidence re-authorized accepted Decision: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runtime-denied"), []byte("denied"), 0600); err != nil {
		t.Fatal(err)
	}
	err = verify.Wait()
	waited = true
	if err != nil || !strings.Contains(log.String(), "--- PASS: TestExternalLiveDecisionCore ") {
		t.Fatalf("actual Decision subprocess did not complete: %v %s", err, log.Bytes())
	}
	t.Logf("actual Runtime continuation SIGKILL recovered Run %s Attempt %s Turn %s Decision %s DECISION_ACCEPTED; live source revocation denied", cp.RunID, cp.AttemptID, cp.TurnID, result.DecisionID)
	success = true
	return w, result, log.Bytes()
}
