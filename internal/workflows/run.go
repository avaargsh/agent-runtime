package workflows

import (
	"time"

	"github.com/avaargsh/agent-runtime/internal/decision"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const Queue = "agent-runtime-v1"

func Run(ctx workflow.Context, turn decision.Turn) (decision.Result, error) {
	if err := turn.Validate(); err != nil {
		return decision.Result{}, err
	}
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 20 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
	}
	ctx = workflow.WithActivityOptions(ctx, options)
	var result decision.Result
	err := workflow.ExecuteActivity(ctx, "InvokeDecision", turn).Get(ctx, &result)
	if err != nil {
		return decision.Result{}, err
	}
	return result, result.ValidateEnvelope()
}
