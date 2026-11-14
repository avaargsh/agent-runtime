package workflows

import (
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/activities"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

func sampleTurn() decision.Turn {
	return decision.Turn{
		ProtocolVersion: "v0.1",
		InvocationID:    "inv-1",
		TenantID:        "tenant-1",
		AgentID:         "agent-1",
		RunID:           "run-1",
		TurnID:          "turn-1",
		UserInput:       "hello",
	}
}

func TestRunWorkflow(t *testing.T) {
	s := &testsuite.WorkflowTestSuite{}
	env := s.NewTestWorkflowEnvironment()
	turn := sampleTurn()
	want := decision.Result{ProtocolVersion: "v0.1", InvocationID: "runtime-generated-invocation", Kind: "final_response", Text: "ok"}
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
	bad := decision.Result{ProtocolVersion: "unsupported", InvocationID: "another", Kind: "final_response", Text: "ok"}
	env.RegisterActivity(&activities.Activities{})
	env.OnActivity("InvokeDecision", mock.Anything, turn).Return(bad, nil)
	env.ExecuteWorkflow(Run, turn)
	if env.GetWorkflowError() == nil {
		t.Fatal("workflow accepted mismatched invocation result")
	}
	env.AssertExpectations(t)
}

func TestWorkflowIDIsCanonicalAndStable(t *testing.T) {
	first, err := WorkflowID("run-123")
	if err != nil {
		t.Fatal(err)
	}
	second, err := WorkflowID("run-123")
	if err != nil {
		t.Fatal(err)
	}
	if first != "agent-run/v1/run-123" || second != first {
		t.Fatalf("workflow id is not canonical/stable: %q %q", first, second)
	}
	other, err := WorkflowID("run-456")
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("different Runs must have different Workflow IDs")
	}
}

func TestWorkflowIDRejectsAmbiguousRunIDs(t *testing.T) {
	for _, runID := range []string{"", " ", " run-1", "run-1 ", "a/b", "a?b", "a#b", strings.Repeat("x", 257)} {
		if _, err := WorkflowID(runID); err == nil {
			t.Fatalf("accepted invalid run id %q", runID)
		}
	}
}
