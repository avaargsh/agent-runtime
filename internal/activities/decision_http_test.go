package activities

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

func TestRunWorkflowCancelsDecisionHTTPWhenBreakerOpens(t *testing.T) {
	requestStarted := make(chan struct{}, 2)
	requestContextDone := make(chan bool, 2)
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		requestStarted <- struct{}{}

		select {
		case <-r.Context().Done():
			requestContextDone <- true
		case <-time.After(3 * time.Second):
			requestContextDone <- false
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"protocol_version":"v0.1","invocation_id":"invocation-001","kind":"final_response","text":"late response"}`))
		}
	}))
	defer server.Close()

	closed := closedRunBreaker(t)
	opened, err := closed.Trip(
		"UNAUTHORIZED_EGRESS",
		"event-http-cancel",
		closed.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("trip Run breaker: %v", err)
	}

	store := &fakeBreakerStore{records: []breaker.Record{closed, opened}}
	activity := &Activities{
		Client: decision.Client{
			Endpoint: server.URL,
			HTTP:     &http.Client{Timeout: 5 * time.Second},
		},
		Breakers:     store,
		PollInterval: 5 * time.Millisecond,
	}

	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivity(activity)
	env.ExecuteWorkflow(workflows.Run, activityTurn())

	workflowErr := env.GetWorkflowError()
	if workflowErr == nil {
		t.Fatal("Run workflow succeeded after the Run breaker opened")
	}

	var applicationErr *temporal.ApplicationError
	if !errors.As(workflowErr, &applicationErr) {
		t.Fatalf("workflow error = %T (%v), want Temporal ApplicationError", workflowErr, workflowErr)
	}
	if applicationErr.Type() != "RUN_BREAKER_BLOCKED" {
		t.Fatalf("application error type = %q, want RUN_BREAKER_BLOCKED", applicationErr.Type())
	}
	if !applicationErr.NonRetryable() {
		t.Fatal("Run breaker application error must be non-retryable")
	}

	select {
	case <-requestStarted:
	default:
		t.Fatal("Decision HTTP request never reached the remote plugin")
	}
	select {
	case cancelled := <-requestContextDone:
		if !cancelled {
			t.Fatal("remote Decision handler completed without observing request cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("remote Decision handler did not observe request cancellation")
	}

	if got := requestCount.Load(); got != 1 {
		t.Fatalf("remote Decision HTTP request count = %d, want exactly 1 (no retry)", got)
	}
	if got := store.callCount(); got != 2 {
		t.Fatalf("Run breaker lookups = %d, want exactly 2 (preflight + in-flight watcher)", got)
	}
}
