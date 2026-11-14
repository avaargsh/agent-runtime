package activities

import (
	"context"
	"testing"
	"time"

	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

type serverExecutionProbe struct{}

func (serverExecutionProbe) ReadExecution(ctx context.Context) (TemporalExecution, error) {
	return (ServerTemporalExecutionResolver{}).Resolve(ctx)
}

func resolveServerExecutionWorkflow(ctx workflow.Context) (TemporalExecution, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Second,
	})
	var execution TemporalExecution
	err := workflow.ExecuteActivity(ctx, "ReadExecution").Get(ctx, &execution)
	return execution, err
}

func TestServerTemporalExecutionResolverReadsCurrentActivityMetadata(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	probe := serverExecutionProbe{}
	env.RegisterActivity(probe.ReadExecution)
	env.ExecuteWorkflow(resolveServerExecutionWorkflow)

	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow execution failed: %v", err)
	}
	var got TemporalExecution
	if err := env.GetWorkflowResult(&got); err != nil {
		t.Fatalf("read resolver result: %v", err)
	}
	if got.WorkflowID != "default-test-workflow-id" || got.ExecutionID != "default-test-run-id" {
		t.Fatalf("resolver returned %+v, want Temporal server activity identity (default-test-workflow-id, default-test-run-id)", got)
	}
}
