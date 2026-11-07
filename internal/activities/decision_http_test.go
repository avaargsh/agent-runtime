package activities

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/dataprotection"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

type requestGatedBreakerStore struct {
	closed         breaker.Record
	opened         breaker.Record
	requestReached <-chan struct{}
	lookups        atomic.Int32
}

func (s *requestGatedBreakerStore) GetRunBreaker(ctx context.Context, _, _ string) (breaker.Record, error) {
	if err := ctx.Err(); err != nil {
		return breaker.Record{}, err
	}
	if s.lookups.Add(1) == 1 {
		return s.closed, nil
	}
	select {
	case <-s.requestReached:
		return s.opened, nil
	default:
		return s.closed, nil
	}
}

type testDecisionProtector struct{}

func (testDecisionProtector) ProtectOutbound(_ context.Context, _ dataprotection.Scope, _ string, payload []byte) ([]byte, error) {
	return append([]byte(nil), payload...), nil
}

func (testDecisionProtector) RestoreInbound(_ context.Context, _ dataprotection.Scope, _, _ string, payload []byte) ([]byte, error) {
	return append([]byte(nil), payload...), nil
}

func TestRunWorkflowCancelsDecisionHTTPWhenBreakerOpens(t *testing.T) {
	requestReached := make(chan struct{})
	requestContextDone := make(chan bool, 2)
	var requestCount atomic.Int32
	var requestOnce sync.Once

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		requestOnce.Do(func() { close(requestReached) })

		select {
		case <-r.Context().Done():
			requestContextDone <- true
		case <-time.After(3 * time.Second):
			requestContextDone <- false
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"protocol_version":"v0.1","invocation_id":"invocation-001","kind":"final_response","text":"late response"}`))
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
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

	store := &requestGatedBreakerStore{closed: closed, opened: opened, requestReached: requestReached}
	activity := &Activities{
		Client: decision.Client{
			Endpoint:  server.URL,
			Protector: testDecisionProtector{},
			HTTP:      &http.Client{Timeout: 5 * time.Second, Transport: server.Client().Transport},
		},
		Breakers:     store,
		Runs:         testRunIdentityReader(),
		Principals:   testPrincipalReader(),
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
	case <-requestReached:
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
	if got := store.lookups.Load(); got < 2 {
		t.Fatalf("Run breaker lookups = %d, want preflight plus in-flight polling", got)
	}
}

func TestDecisionHTTPNeverSentWithoutPersistedPrincipalSnapshot(t *testing.T) {
	var httpRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"protocol_version":"v0.1","invocation_id":"invocation-001","kind":"final_response","text":"ok"}`))
	}))
	defer server.Close()
	for _, tc := range []struct {
		name       string
		principals RunPrincipalReader
	}{
		{"no principal reader", nil},
		{"repository unavailable", &principalFixtureReader{err: errors.New("PostgreSQL principal read unavailable")}},
		{"invalid stored principal", &principalFixtureReader{snapshot: run.PrincipalSnapshot{Version: "acp-principal/v1", SubjectID: "spoofed"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := Activities{
				Client: decision.Client{Endpoint: server.URL, Protector: testDecisionProtector{}},
				Breakers: &fakeBreakerStore{records: []breaker.Record{closedRunBreaker(t)}},
				Runs: testRunIdentityReader(),
				Principals: tc.principals,
			}
			if _, err := a.InvokeDecision(context.Background(), activityTurn()); err == nil {
				t.Fatal("unverified principal reached Decision HTTP")
			}
			if got := httpRequests.Load(); got != 0 {
				t.Fatalf("Decision HTTP egress observed without trusted principal: %d", got)
			}
		})
	}
}
