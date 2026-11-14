package activities

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/securitycontext"
)

const (
	temporalTestRunID       = "11111111-1111-4111-8111-111111111111"
	temporalTestExecutionID = "22222222-2222-4222-8222-222222222222"
	temporalTestAttemptID   = "33333333-3333-4333-8333-333333333333"
	temporalTestTurnID      = "44444444-4444-4444-8444-444444444444"
)

type fixedTemporalExecutionResolver struct {
	execution TemporalExecution
	err       error
	calls     int
}

func (r *fixedTemporalExecutionResolver) Resolve(_ context.Context) (TemporalExecution, error) {
	if r == nil {
		return TemporalExecution{}, ErrTemporalExecutionUnavailable
	}
	r.calls++
	return r.execution, r.err
}

type fixedTemporalTurnWriter struct {
	identity  run.TemporalTurnIdentity
	err       error
	calls     int
	tenantID  string
	runID     string
	workflow  string
	execution string
	turnIndex int32
}

func (w *fixedTemporalTurnWriter) GetOrCreateTemporalTurn(
	_ context.Context, tenantID, runID, workflowID, executionID string, turnIndex int32,
) (run.TemporalTurnIdentity, error) {
	if w == nil {
		return run.TemporalTurnIdentity{}, errors.New("Temporal turn writer unavailable")
	}
	w.calls++
	w.tenantID, w.runID, w.workflow = tenantID, runID, workflowID
	w.execution, w.turnIndex = executionID, turnIndex
	return w.identity, w.err
}

type identityCapturingInvoker struct {
	calls    int
	turn     decision.Turn
	identity run.Identity
	security securitycontext.Context
	hasSec   bool
}

func (i *identityCapturingInvoker) Invoke(ctx context.Context, turn decision.Turn, identity run.Identity) (decision.Result, error) {
	i.calls++
	i.turn, i.identity = turn, identity
	i.security, i.hasSec = securitycontext.FromContext(ctx)
	return decision.Result{
		ProtocolVersion: turn.ProtocolVersion,
		InvocationID:    turn.InvocationID,
		Kind:            "final_response",
		Text:            "ok",
	}, nil
}

func temporalTestIdentityReader() *fakeRunIdentityReader {
	return &fakeRunIdentityReader{identity: run.Identity{
		RunID: temporalTestRunID, TenantID: "tenant-001", AgentID: "agent-001",
		AgentReleaseID: "release-001", SessionID: "session-001",
	}}
}

func temporalTestExecution() TemporalExecution {
	return TemporalExecution{
		WorkflowID:  run.ACPWorkflowPrefix + temporalTestRunID,
		ExecutionID: temporalTestExecutionID,
	}
}

func temporalTestTurnIdentity() run.TemporalTurnIdentity {
	return run.TemporalTurnIdentity{
		TenantID: "tenant-001", RunID: temporalTestRunID,
		WorkflowID:          run.ACPWorkflowPrefix + temporalTestRunID,
		TemporalExecutionID: temporalTestExecutionID,
		RunAttemptID:        temporalTestAttemptID,
		TurnID:              temporalTestTurnID,
		InvocationID:        temporalTestTurnID,
		TurnIndex:           1,
	}
}

func temporalTestBreaker(t *testing.T) breaker.Record {
	t.Helper()
	record, err := breaker.NewClosed(
		breaker.Scope{Kind: breaker.ScopeRun, ID: temporalTestRunID},
		closedRunBreaker(t).UpdatedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestInvokeDecisionBindsTemporalServerExecutionAndReplacesWorkflowIDs(t *testing.T) {
	invoker := &identityCapturingInvoker{}
	execution := &fixedTemporalExecutionResolver{execution: temporalTestExecution()}
	turns := &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()}
	activity := Activities{
		Client:        invoker,
		Breakers:      &fakeBreakerStore{records: []breaker.Record{temporalTestBreaker(t)}},
		Runs:          temporalTestIdentityReader(),
		Principals:    testPrincipalReader(),
		Execution:     execution,
		TemporalTurns: turns,
	}

	turn := activityTurn()
	turn.RunID = temporalTestRunID
	turn.TurnID = "workflow-forged-turn"
	turn.InvocationID = "workflow-forged-invocation"
	if _, err := activity.InvokeDecision(context.Background(), turn); err != nil {
		t.Fatalf("InvokeDecision() error = %v", err)
	}
	if execution.calls != 1 || turns.calls != 1 {
		t.Fatalf("execution/turn resolution calls = %d/%d, want 1/1", execution.calls, turns.calls)
	}
	if turns.tenantID != "tenant-001" || turns.runID != temporalTestRunID ||
		turns.workflow != run.ACPWorkflowPrefix+temporalTestRunID ||
		turns.execution != temporalTestExecutionID || turns.turnIndex != 1 {
		t.Fatalf("Temporal identity was not bound to the persisted Run and server execution: %+v", turns)
	}
	if invoker.calls != 1 || invoker.turn.TurnID != temporalTestTurnID ||
		invoker.turn.InvocationID != temporalTestTurnID {
		t.Fatalf("Decision received caller-controlled turn identity: %+v", invoker)
	}
	if !invoker.hasSec {
		t.Fatal("Decision did not receive a trusted SecurityContext")
	}
	claims := invoker.security.Claims()
	if claims.TenantID != "tenant-001" || claims.SubjectID != "subject-1" ||
		claims.ActorID != "actor-1" || claims.AgentID != "agent-001" ||
		claims.AgentReleaseID != "release-001" || claims.SessionID != "session-001" ||
		claims.RunID != temporalTestRunID || claims.RunAttemptID != temporalTestAttemptID ||
		claims.TurnID != temporalTestTurnID || claims.PolicyRevision != "policy-1" {
		t.Fatalf("Decision SecurityContext did not combine persisted principal and server-owned execution IDs: %+v", claims)
	}
}

func TestInvokeDecisionRejectsTemporalWorkflowMismatchBeforeEgress(t *testing.T) {
	invoker := &identityCapturingInvoker{}
	execution := &fixedTemporalExecutionResolver{execution: TemporalExecution{
		WorkflowID:  "agent-run/v1/some-other-run",
		ExecutionID: temporalTestExecutionID,
	}}
	turns := &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()}
	breakers := &fakeBreakerStore{records: []breaker.Record{temporalTestBreaker(t)}}
	activity := Activities{
		Client: invoker, Breakers: breakers, Runs: temporalTestIdentityReader(),
		Principals: testPrincipalReader(), Execution: execution, TemporalTurns: turns,
	}
	turn := activityTurn()
	turn.RunID = temporalTestRunID
	if _, err := activity.InvokeDecision(context.Background(), turn); err == nil {
		t.Fatal("accepted a Temporal Workflow ID that differs from the persisted Runtime Run")
	}
	if turns.calls != 0 || breakers.callCount() != 0 || invoker.calls != 0 {
		t.Fatalf("mismatched Workflow reached persistence/breaker/Decision: turns=%d breaker=%d invoker=%d",
			turns.calls, breakers.callCount(), invoker.calls)
	}
}

func TestInvokeDecisionFailsClosedWhenTemporalExecutionOrTurnPersistenceIsUnavailable(t *testing.T) {
	cases := []struct {
		name      string
		execution *fixedTemporalExecutionResolver
		turns     *fixedTemporalTurnWriter
	}{
		{
			name:  "missing execution resolver",
			turns: &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
		},
		{
			name:      "execution metadata unavailable",
			execution: &fixedTemporalExecutionResolver{err: errors.New("Temporal activity metadata unavailable")},
			turns:     &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
		},
		{
			name:      "turn persistence unavailable",
			execution: &fixedTemporalExecutionResolver{execution: temporalTestExecution()},
			turns:     &fixedTemporalTurnWriter{err: errors.New("PostgreSQL unavailable")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invoker := &identityCapturingInvoker{}
			breakers := &fakeBreakerStore{records: []breaker.Record{temporalTestBreaker(t)}}
			activity := Activities{
				Client: invoker, Breakers: breakers, Runs: temporalTestIdentityReader(),
				Principals: testPrincipalReader(), Execution: tc.execution, TemporalTurns: tc.turns,
			}
			turn := activityTurn()
			turn.RunID = temporalTestRunID
			_, err := activity.InvokeDecision(context.Background(), turn)
			if err == nil {
				t.Fatal("Decision proceeded without server-bound Temporal execution identity")
			}
			if invoker.calls != 0 || breakers.callCount() != 0 {
				t.Fatalf("failure reached breaker/Decision: breaker=%d invoker=%d", breakers.callCount(), invoker.calls)
			}
		})
	}
}
