package activities

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"go.temporal.io/sdk/temporal"
)

// A Decision plugin can return before the first periodic breaker poll.
// Changing the breaker DURING the invocation must still invalidate the result.
type flipBreakerBeforeReturn struct {
	store *fakeBreakerStore
	next  breaker.Record
}

func (f flipBreakerBeforeReturn) Invoke(_ context.Context, turn decision.Turn) (decision.Result, error) {
	f.store.mu.Lock()
	f.store.records = []breaker.Record{f.next}
	f.store.mu.Unlock()
	return decision.Result{
		ProtocolVersion: turn.ProtocolVersion,
		InvocationID:    turn.InvocationID,
		Kind:            "final_response",
		Text:            "returned before polling",
	}, nil
}

func TestInvokeDecisionRejectsBreakerTripBeforeFirstPoll(t *testing.T) {
	closed := closedRunBreaker(t)
	opened, err := closed.Trip("UNAUTHORIZED_EGRESS", "event-fast-trip", closed.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeBreakerStore{records: []breaker.Record{closed}}
	activity := Activities{
		Breakers: store,
		Client: flipBreakerBeforeReturn{store: store, next: opened},
		PollInterval: time.Hour,
	}
	_, err = activity.InvokeDecision(context.Background(), activityTurn())
	var appErr *temporal.ApplicationError
	if !errors.As(err, &appErr) || appErr.Type() != "RUN_BREAKER_BLOCKED" || !appErr.NonRetryable() {
		t.Fatalf("post-invocation breaker trip accepted, got %v (want non-retryable RUN_BREAKER_BLOCKED)", err)
	}
	if calls := store.callCount(); calls < 2 {
		t.Fatalf("breaker state checked only %d time(s), want preflight and post-invocation", calls)
	}
}

type loseBreakerStoreOnReturn struct {
	store *fakeBreakerStore
}

func (f loseBreakerStoreOnReturn) Invoke(_ context.Context, turn decision.Turn) (decision.Result, error) {
	f.store.mu.Lock()
	f.store.err = errors.New("post-invocation database unavailable")
	f.store.mu.Unlock()
	return decision.Result{
		ProtocolVersion: turn.ProtocolVersion,
		InvocationID:    turn.InvocationID,
		Kind:            "final_response",
		Text:            "ready",
	}, nil
}

func TestInvokeDecisionFailsClosedWhenPostInvocationBreakerReadFails(t *testing.T) {
	store := &fakeBreakerStore{records: []breaker.Record{closedRunBreaker(t)}}
	activity := Activities{
		Breakers: store,
		Client: loseBreakerStoreOnReturn{store: store},
		PollInterval: time.Hour,
	}
	_, err := activity.InvokeDecision(context.Background(), activityTurn())
	var appErr *temporal.ApplicationError
	if !errors.As(err, &appErr) || appErr.Type() != "RUN_BREAKER_BLOCKED" || !appErr.NonRetryable() {
		t.Fatalf("post-invocation breaker read outage accepted, got %v (want RUN_BREAKER_BLOCKED)", err)
	}
}
