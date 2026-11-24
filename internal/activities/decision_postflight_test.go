package activities

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/run"
	"go.temporal.io/sdk/temporal"
)

// A Decision plugin can return before the first periodic breaker poll.
// Changing the breaker DURING the invocation must still invalidate the result.
type flipBreakerBeforeReturn struct {
	store *fakeBreakerStore
	next  breaker.Record
}

func (f flipBreakerBeforeReturn) Invoke(_ context.Context, turn decision.Turn, _ run.Identity) (decision.Result, error) {
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
		Breakers:      store,
		Client:        flipBreakerBeforeReturn{store: store, next: opened},
		Runs:          testRunIdentityReader(),
		Principals:    testPrincipalReader(),
		Execution:     &fixedTemporalExecutionResolver{execution: temporalTestExecution()},
		TemporalTurns: &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
		PollInterval:  time.Hour,
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

func (f loseBreakerStoreOnReturn) Invoke(_ context.Context, turn decision.Turn, _ run.Identity) (decision.Result, error) {
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
		Breakers:      store,
		Client:        loseBreakerStoreOnReturn{store: store},
		Runs:          testRunIdentityReader(),
		Principals:    testPrincipalReader(),
		Execution:     &fixedTemporalExecutionResolver{execution: temporalTestExecution()},
		TemporalTurns: &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
		PollInterval:  time.Hour,
	}
	_, err := activity.InvokeDecision(context.Background(), activityTurn())
	var appErr *temporal.ApplicationError
	if !errors.As(err, &appErr) || appErr.Type() != "RUN_BREAKER_BLOCKED" || !appErr.NonRetryable() {
		t.Fatalf("post-invocation breaker read outage accepted, got %v (want RUN_BREAKER_BLOCKED)", err)
	}
}

// The persisted Temporal Turn is bound to breaker epoch/version one. A later
// recovery must not silently rebase that stale Turn onto the new breaker
// epoch, even though HALF_OPEN permits read-only probes in a newly admitted
// recovery flow. Until an explicit epoch-bound continuation exists, the
// original Turn loses authority on every breaker transition.
func TestInvokeDecisionRejectsBreakerRecoveryForStaleTemporalTurn(t *testing.T) {
	closed := closedRunBreaker(t)
	opened, err := closed.Trip("UNAUTHORIZED_EGRESS", "event-stale-turn", closed.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := opened.BeginRecovery("approval-stale-turn", opened.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != breaker.StateHalfOpen || recovered.Epoch == uint64(temporalTestTurnIdentity().BreakerEpoch) {
		t.Fatalf("fixture did not advance breaker beyond the bound Turn: %+v", recovered)
	}

	store := &fakeBreakerStore{records: []breaker.Record{recovered}}
	client := &immediateDecisionInvoker{}
	activity := Activities{
		Client: client, Breakers: store, Runs: testRunIdentityReader(), Principals: testPrincipalReader(),
		Execution:     &fixedTemporalExecutionResolver{execution: temporalTestExecution()},
		TemporalTurns: &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
	}
	if _, err := activity.InvokeDecision(context.Background(), activityTurn()); err == nil {
		t.Fatal("stale epoch-one Turn was silently reauthorized by the newer HALF_OPEN breaker epoch")
	}
	if client.calls != 0 || store.callCount() != 1 {
		t.Fatalf("stale Turn reached Decision egress or performed extra reads: client=%d breaker_reads=%d",
			client.calls, store.callCount())
	}
}

// A privileged version-only catalog drift is also outside the generation-one
// contract. Record.Check validates state/epoch but does not bind version;
// the Activity must preserve the version-one fence established at Turn bind.
func TestInvokeDecisionRejectsBreakerVersionDriftAfterTemporalTurnBinding(t *testing.T) {
	drifted := closedRunBreaker(t)
	drifted.Version = 2

	store := &fakeBreakerStore{records: []breaker.Record{drifted}}
	client := &immediateDecisionInvoker{}
	activity := Activities{
		Client: client, Breakers: store, Runs: testRunIdentityReader(), Principals: testPrincipalReader(),
		Execution:     &fixedTemporalExecutionResolver{execution: temporalTestExecution()},
		TemporalTurns: &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
	}
	if _, err := activity.InvokeDecision(context.Background(), activityTurn()); err == nil {
		t.Fatal("epoch-one Turn was accepted after breaker version drift")
	}
	if client.calls != 0 || store.callCount() != 1 {
		t.Fatalf("version-drifted Turn reached Decision egress or performed extra reads: client=%d breaker_reads=%d",
			client.calls, store.callCount())
	}
}

// The breaker may change after preflight but before a fast Decision response,
// beating the periodic watcher. The postflight read must still be pinned to
// the persisted Turn's original version and reject the returned result.
func TestInvokeDecisionRejectsBreakerVersionDriftBeforeFirstPoll(t *testing.T) {
	closed := closedRunBreaker(t)
	drifted := closed
	drifted.Version = 2
	store := &fakeBreakerStore{records: []breaker.Record{closed}}
	activity := Activities{
		Breakers: store,
		Client:   flipBreakerBeforeReturn{store: store, next: drifted},
		Runs:     testRunIdentityReader(), Principals: testPrincipalReader(),
		Execution:     &fixedTemporalExecutionResolver{execution: temporalTestExecution()},
		TemporalTurns: &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
		PollInterval:  time.Hour,
	}
	_, err := activity.InvokeDecision(context.Background(), activityTurn())
	var appErr *temporal.ApplicationError
	if !errors.As(err, &appErr) || appErr.Type() != "RUN_BREAKER_BLOCKED" || !appErr.NonRetryable() {
		t.Fatalf("post-preflight breaker version drift accepted, got %v (want non-retryable RUN_BREAKER_BLOCKED)", err)
	}
	if calls := store.callCount(); calls < 2 {
		t.Fatalf("breaker state checked only %d time(s), want preflight and postflight", calls)
	}
}

// The generation-one Turn was admitted only while the RUN breaker was CLOSED.
// A direct state-only catalog drift to HALF_OPEN can preserve epoch/version 1;
// Record.Check intentionally allows read-only probes in HALF_OPEN, but that
// must not let this already-bound Turn masquerade as a newly admitted probe.
func TestInvokeDecisionRejectsHalfOpenStateWithoutNewBreakerFence(t *testing.T) {
	halfOpen := closedRunBreaker(t)
	halfOpen.State = breaker.StateHalfOpen
	halfOpen.ReasonCode = "RECOVERY_IN_PROGRESS"
	halfOpen.TriggerEventID = "event-state-only-drift"
	halfOpen.OpenedAt = halfOpen.UpdatedAt
	halfOpen.RecoveryApprovalID = "approval-state-only-drift"
	halfOpen.UpdatedAt = halfOpen.UpdatedAt.Add(time.Second)
	if err := halfOpen.Validate(); err != nil {
		t.Fatalf("invalid state-only drift fixture: %v", err)
	}
	if halfOpen.Epoch != 1 || halfOpen.Version != 1 {
		t.Fatalf("fixture unexpectedly advanced breaker fence: %+v", halfOpen)
	}

	store := &fakeBreakerStore{records: []breaker.Record{halfOpen}}
	client := &immediateDecisionInvoker{}
	activity := Activities{
		Client: client, Breakers: store, Runs: testRunIdentityReader(), Principals: testPrincipalReader(),
		Execution:     &fixedTemporalExecutionResolver{execution: temporalTestExecution()},
		TemporalTurns: &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
	}
	if _, err := activity.InvokeDecision(context.Background(), activityTurn()); err == nil {
		t.Fatal("old CLOSED-bound Turn was accepted as a HALF_OPEN read-only probe without a new authority")
	}
	if client.calls != 0 || store.callCount() != 1 {
		t.Fatalf("state-drifted Turn reached Decision egress or performed extra reads: client=%d breaker_reads=%d",
			client.calls, store.callCount())
	}
}
