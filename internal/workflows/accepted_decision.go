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
	AcceptedDecisionReadySignal = "decision-continuation-ready-v1"
)

// AcceptedDecisionV1 is the reference-only first business stage of a
// decision.v1 Run. A versioned wake hint only schedules a fresh authority
// read/CAS; no signal can grant authority or carry a DecisionRecord.
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
	// Existing histories without the version marker retain their original
	// waiting behavior. New development Runs may be woken by an operator
	// hint; the payload is discarded and never passed to the Activity.
	if workflow.GetVersion(ctx, "verified-decision-continuation-v1", workflow.DefaultVersion, 1) == 1 {
		wake := workflow.GetSignalChannel(ctx, AcceptedDecisionReadySignal)
		continuationCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 55 * time.Second,
			ScheduleToCloseTimeout: 115 * time.Second,
			RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, MaximumAttempts: 2},
		})
		for checkpoint.Phase == run.DecisionWaitingAuthority {
			err = workflow.Await(ctx, func() bool { return wake.Len() > 0 })
			if err != nil {
				break
			}
			wake.ReceiveAsync(nil)
			var accepted run.DecisionCheckpoint
			err = workflow.ExecuteActivity(continuationCtx, "ContinueAcceptedDecision", checkpoint).Get(ctx, &accepted)
			if err != nil {
				if ctx.Err() != nil {
					break
				}
				// Unavailable/revoked authority never releases the business
				// gate. A later wake may retry only the read and local CAS.
				continue
			}
			original := accepted
			original.Phase = run.DecisionWaitingAuthority
			original.DecisionID, original.RecordSHA256, original.PlanHash = "", "", ""
			if original != checkpoint || accepted.Phase != run.DecisionAccepted ||
				accepted.DecisionID == "" || len(accepted.RecordSHA256) != 64 || len(accepted.PlanHash) != 64 {
				continue
			}
			checkpoint = accepted
		}
	}
	// Even a committed Decision acceptance is not business success or a
	// protected-effect permit. Stay RUNNING until pre-effect cancellation
	// or a separately verified execution stage is implemented.
	if ctx.Err() == nil {
		err = workflow.Await(ctx, func() bool { return false })
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
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
