package workflows

import (
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const (
	AcceptedDecisionWorkflow = "AcceptedDecisionV1"
	AcceptedDecisionQueue    = "runtime-accepted-decision-development-v1"
)

// AcceptedDecisionV1 is the reference-only first business stage of a
// decision.v1 Run. It deliberately stops at the authority gate; neither
// successful preparation nor workflow completion is business success.
// Do not dispatch production Start Outbox events to this development queue.
func AcceptedDecision(ctx workflow.Context, ref run.AcceptedDecisionRef) (run.DecisionCheckpoint, error) {
	if ref.Validate() != nil || workflow.GetInfo(ctx).WorkflowExecution.ID != ref.WorkflowID {
		return run.DecisionCheckpoint{}, temporal.NewNonRetryableApplicationError(
			"accepted Run correlation mismatch", "DECISION_PREPARATION_DENIED", nil)
	}
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout:    10 * time.Second,
		ScheduleToCloseTimeout: 45 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2,
			MaximumAttempts:    3,
		},
	})
	var checkpoint run.DecisionCheckpoint
	err := workflow.ExecuteActivity(ctx, "PrepareAcceptedDecision", ref).Get(ctx, &checkpoint)
	if err != nil {
		return run.DecisionCheckpoint{}, err
	}
	if checkpoint.AcceptedDecisionRef != ref || checkpoint.ExecutionID != workflow.GetInfo(ctx).WorkflowExecution.RunID ||
		checkpoint.Phase != run.DecisionWaitingAuthority || checkpoint.AttemptID == "" || checkpoint.TurnID == "" ||
		checkpoint.InputDigest == "" || checkpoint.PolicyRevision == "" || checkpoint.ConfigDigest == "" {
		return run.DecisionCheckpoint{}, temporal.NewNonRetryableApplicationError(
			"invalid committed decision checkpoint", "DECISION_PREPARATION_DENIED", nil)
	}
	return checkpoint, nil
}
