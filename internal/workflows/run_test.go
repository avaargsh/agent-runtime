package workflows

import (
	"testing"

	"github.com/avaargsh/agent-runtime/internal/activities"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

func sampleTurn() decision.Turn {
	return decision.Turn{
		ProtocolVersion: "v0.1",
		InvocationID:   "inv-1",
		TenantID:       "tenant-1",
		AgentID:        "agent-1",
		RunID:          "run-1",
		TurnID:         "turn-1",
		UserInput:      "hello",
	}
}

func TestRunWorkflow(t *testing.T) {
	s := &testsuite.WorkflowTestSuite{}
	env := s.NewTestWorkflowEnvironment()
	turn := sampleTurn()
	want := decision.Result{ProtocolVersion: "v0.1", InvocationID: "inv-1", Kind: "final", Text: "ok"}
	env.RegisterActivity(&activities.Activities{})
	env.OnActivity("InvokeDecision", mock.Anything, turn).Return(want, nil)

	env.ExecuteWorkflow(Run, turn)
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var got decision.Result
	if err := env.GetWorkflowResult(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("result mismatch: got %+v want %+v", got, want)
	}
	env.AssertExpectations(t)
}

func TestRunRejectsInvalidInput(t *testing.T) {
	s := &testsuite.WorkflowTestSuite{}
	env := s.NewTestWorkflowEnvironment()
	turn := sampleTurn()
	turn.ProtocolVersion = "unknown"
	env.ExecuteWorkflow(Run, turn)
	if env.GetWorkflowError() == nil {
		t.Fatal("workflow accepted unsupported protocol version")
	}
}

func TestRunRejectsMismatchedActivityResult(t *testing.T) {
	s := &testsuite.WorkflowTestSuite{}
	env := s.NewTestWorkflowEnvironment()
	turn := sampleTurn()
	bad := decision.Result{ProtocolVersion: "v0.1", InvocationID: "another", Kind: "final", Text: "ok"}
	env.RegisterActivity(&activities.Activities{})
	env.OnActivity("InvokeDecision", mock.Anything, turn).Return(bad, nil)
	env.ExecuteWorkflow(Run, turn)
	if env.GetWorkflowError() == nil {
		t.Fatal("workflow accepted mismatched invocation result")
	}
	env.AssertExpectations(t)
}
