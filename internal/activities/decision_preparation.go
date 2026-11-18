package activities

import (
	"context"
	"errors"

	"github.com/avaargsh/agent-runtime/internal/run"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
)

type DecisionCheckpointStore interface {
	PrepareAcceptedDecision(context.Context, run.AcceptedDecisionRef, string) (run.DecisionCheckpoint, error)
}

type DecisionPreparation struct {
	Store DecisionCheckpointStore
}

// PrepareAcceptedDecision crosses only the local durable database boundary.
// Activity arguments carry references, not user input or principal claims.
// The repository resolves the committed business input and current local
// safety gate; no remote egress or protected operation is performed.
func (a *DecisionPreparation) PrepareAcceptedDecision(ctx context.Context, ref run.AcceptedDecisionRef) (run.DecisionCheckpoint, error) {
	deny := func() (run.DecisionCheckpoint, error) {
		return run.DecisionCheckpoint{}, temporal.NewNonRetryableApplicationError(
			"accepted decision preparation denied", "DECISION_PREPARATION_DENIED", nil)
	}
	if a == nil || a.Store == nil || ref.Validate() != nil || !activity.IsActivity(ctx) {
		return deny()
	}
	info := activity.GetInfo(ctx)
	if info.WorkflowExecution.ID != ref.WorkflowID || info.WorkflowExecution.RunID == "" ||
		info.WorkflowType.Name != "AcceptedDecisionV1" || info.TaskQueue != "runtime-accepted-decision-development-v1" {
		return deny()
	}
	checkpoint, err := a.Store.PrepareAcceptedDecision(ctx, ref, info.WorkflowExecution.RunID)
	if err != nil {
		if errors.Is(err, run.ErrRepositoryUnavailable) {
			return run.DecisionCheckpoint{}, run.ErrRepositoryUnavailable
		}
		return deny()
	}
	return checkpoint, nil
}
