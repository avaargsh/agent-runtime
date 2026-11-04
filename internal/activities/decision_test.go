package activities

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/decision"
)

type fakeBreakerStore struct {
	mu       sync.Mutex
	records  []breaker.Record
	err      error
	calls    int
	onLookup func(int)
	tenantID string
	runID    string
}

func (s *fakeBreakerStore) GetRunBreaker(_ context.Context, tenantID, runID string) (breaker.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenantID = tenantID
	s.runID = runID
	s.calls++
	if s.onLookup != nil {
		s.onLookup(s.calls)
	}
	if s.err != nil {
		return breaker.Record{}, s.err
	}
	if len(s.records) == 0 {
		return breaker.Record{}, errors.New("breaker record missing")
	}
	if len(s.records) == 1 {
		return s.records[0], nil
	}
	index := s.calls - 1
	if index >= len(s.records) {
		index = len(s.records) - 1
	}
	return s.records[index], nil
}

func (s *fakeBreakerStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type fakeDecisionInvoker struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
}

func (f *fakeDecisionInvoker) Invoke(ctx context.Context, turn decision.Turn) (decision.Result, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.started != nil {
		close(f.started)
	}
	<-ctx.Done()
	return decision.Result{}, ctx.Err()
}

type immediateDecisionInvoker struct {
	calls int
}

func (f *immediateDecisionInvoker) Invoke(_ context.Context, turn decision.Turn) (decision.Result, error) {
	f.calls++
	return decision.Result{
		ProtocolVersion: turn.ProtocolVersion,
		InvocationID:    turn.InvocationID,
		Kind:            "final_response",
		Text:            "ok",
	}, nil
}

func (f *fakeDecisionInvoker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func activityTurn() decision.Turn {
	return decision.Turn{
		ProtocolVersion: "v0.1",
		InvocationID:    "invocation-001",
		TenantID:        "tenant-001",
		AgentID:         "agent-001",
		RunID:           "run-001",
		TurnID:          "turn-001",
		UserInput:       "hello",
	}
}

func closedRunBreaker(t *testing.T) breaker.Record {
	t.Helper()
	record, err := breaker.NewClosed(
		breaker.Scope{Kind: breaker.ScopeRun, ID: "run-001"},
		time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestInvokeDecisionRejectsOpenBreakerBeforeCallingClient(t *testing.T) {
	closed := closedRunBreaker(t)
	opened, err := closed.Trip("CREDENTIAL_EXFILTRATION", "event-001", closed.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeBreakerStore{records: []breaker.Record{opened}}
	client := &fakeDecisionInvoker{}
	activity := Activities{Client: client, Breakers: store}

	if _, err := activity.InvokeDecision(context.Background(), activityTurn()); err == nil {
		t.Fatal("InvokeDecision() succeeded with OPEN Run breaker")
	}
	if client.callCount() != 0 {
		t.Fatalf("Decision client called %d times, want 0", client.callCount())
	}
}

func TestInvokeDecisionCancelsInFlightRequestWhenBreakerOpens(t *testing.T) {
	closed := closedRunBreaker(t)
	opened, err := closed.Trip("UNAUTHORIZED_EGRESS", "event-002", closed.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeBreakerStore{records: []breaker.Record{closed, opened}}
	client := &fakeDecisionInvoker{started: make(chan struct{})}
	activity := Activities{
		Client:       client,
		Breakers:     store,
		PollInterval: time.Millisecond,
	}

	result := make(chan error, 1)
	go func() {
		_, err := activity.InvokeDecision(context.Background(), activityTurn())
		result <- err
	}()
	select {
	case <-client.started:
	case <-time.After(time.Second):
		t.Fatal("Decision request did not start")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("InvokeDecision() returned nil after breaker opened")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight Decision request was not cancelled after breaker OPEN")
	}
	if store.callCount() < 2 {
		t.Fatalf("breaker lookups = %d, want preflight and in-flight polling", store.callCount())
	}
}

func TestInvokeDecisionFailsClosedWhenBreakerStoreUnavailable(t *testing.T) {
	store := &fakeBreakerStore{err: errors.New("postgres unavailable")}
	client := &fakeDecisionInvoker{}
	activity := Activities{Client: client, Breakers: store}

	if _, err := activity.InvokeDecision(context.Background(), activityTurn()); err == nil {
		t.Fatal("InvokeDecision() succeeded while breaker state was unavailable")
	}
	if client.callCount() != 0 {
		t.Fatalf("Decision client called %d times after store failure, want 0", client.callCount())
	}
}

func TestInvokeDecisionFailsClosedWhenBreakerRecordIsMissing(t *testing.T) {
	store := &fakeBreakerStore{}
	client := &fakeDecisionInvoker{}
	activity := Activities{Client: client, Breakers: store}

	if _, err := activity.InvokeDecision(context.Background(), activityTurn()); err == nil {
		t.Fatal("InvokeDecision() succeeded without a durable Run breaker")
	}
	if client.callCount() != 0 {
		t.Fatalf("Decision client called %d times without a Run breaker, want 0", client.callCount())
	}
}

func TestInvokeDecisionUsesTenantBoundRunIdentity(t *testing.T) {
	store := &fakeBreakerStore{records: []breaker.Record{closedRunBreaker(t)}}
	client := &immediateDecisionInvoker{}
	activity := Activities{Client: client, Breakers: store}

	_, err := activity.InvokeDecision(context.Background(), activityTurn())
	if err != nil {
		t.Fatalf("InvokeDecision() error = %v", err)
	}
	if store.tenantID != "tenant-001" || store.runID != "run-001" {
		t.Fatalf("breaker lookup identity = (%q,%q), want (tenant-001,run-001)", store.tenantID, store.runID)
	}
	if client.calls != 1 {
		t.Fatalf("Decision client calls = %d, want 1", client.calls)
	}
}

type stopAwareBreakerStore struct {
	record      breaker.Record
	pollStarted chan struct{}
	calls       int
}

func (s *stopAwareBreakerStore) GetRunBreaker(ctx context.Context, tenantID, runID string) (breaker.Record, error) {
	s.calls++
	if s.calls == 1 {
		return s.record, nil
	}
	close(s.pollStarted)
	<-ctx.Done()
	return breaker.Record{}, ctx.Err()
}

type waitForPollInvoker struct {
	pollStarted <-chan struct{}
}

func (i waitForPollInvoker) Invoke(_ context.Context, turn decision.Turn) (decision.Result, error) {
	<-i.pollStarted
	return decision.Result{
		ProtocolVersion: turn.ProtocolVersion,
		InvocationID:    turn.InvocationID,
		Kind:            "final_response",
		Text:            "completed before watcher shutdown",
	}, nil
}

func TestInvokeDecisionIgnoresWatcherQueryCancelledByNormalCompletion(t *testing.T) {
	store := &stopAwareBreakerStore{
		record:      closedRunBreaker(t),
		pollStarted: make(chan struct{}),
	}
	activity := Activities{
		Client:       waitForPollInvoker{pollStarted: store.pollStarted},
		Breakers:     store,
		PollInterval: time.Millisecond,
	}

	result, err := activity.InvokeDecision(context.Background(), activityTurn())
	if err != nil {
		t.Fatalf("normal completion was converted into breaker failure: %v", err)
	}
	if result.Text != "completed before watcher shutdown" {
		t.Fatalf("result text = %q", result.Text)
	}
}
