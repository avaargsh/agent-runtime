package workflows

import (
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const (
	AcceptedDecisionWorkflow        = "AcceptedDecisionV1"
	AcceptedDecisionQueue           = "runtime-accepted-decision-development-v1"
	AcceptedDecisionCheckpointQuery = "decision-checkpoint"
)

// AcceptedDecisionV1 is the reference-only first business stage of a
// decision.v1 Run. It remains durably paused at the authority gate. No
// signal or update can grant authority until a verified adapter is wired.
// Do not dispatch production Start Outbox events to this development queue.
func AcceptedDecision(ctx workflow.Context, ref run.AcceptedDecisionRef) (run.DecisionCheckpoint, error) {
	if ref.Validate() != nil || workflow.GetInfo(ctx).WorkflowExecution.ID != ref.WorkflowID {
		return run.DecisionCheckpoint{}, temporal.NewNonRetryableApplicationError(
			"accepted Run correlation mismatch", "DECISION_PREPARATION_DENIED", nil)
	}
	var checkpoint run.DecisionCheckpoint
	if err := workflow.SetQueryHandler(ctx, AcceptedDecisionCheckpointQuery, func() (run.DecisionCheckpoint, error) {
		return checkpoint, nil
	}); err != nil {
		return run.DecisionCheckpoint{}, err
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
	// This durable checkpoint is not a Decision continuation receipt or Guard Permit.
	// Do not complete the canonical Workflow ID with a nonterminal stage.
	// A future versioned, independently authorized continuation must resume
	// here; until then only cancellation or the execution deadline ends it.
	if err := workflow.Await(ctx, func() bool { return false }); err != nil {
		if temporal.IsCanceledError(err) {
			// The original context is canceled. Use a bounded disconnected
			// Activity to record the exact pre-effect cancellation before
			// reporting terminal cancellation to Temporal.
			detached, cancel := workflow.NewDisconnectedContext(ctx)
			defer cancel()
			if cleanupErr := workflow.ExecuteActivity(detached, "CancelPreparedDecision", ref).Get(detached, nil); cleanupErr != nil {
				return run.DecisionCheckpoint{}, temporal.NewNonRetryableApplicationError(
					"Runtime cancellation is not reconciled", "DECISION_CANCELLATION_UNCERTAIN", cleanupErr)
			}
		}
		return run.DecisionCheckpoint{}, err
	}
	return run.DecisionCheckpoint{}, temporal.NewNonRetryableApplicationError(
		"authority gate has no verified continuation", "DECISION_PREPARATION_DENIED", nil)
}
