package activities

import (
	"context"

	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/run"
	"go.temporal.io/sdk/activity"
)

type DecisionContinuationStore interface {
	GetDecisionAuthority(context.Context, string, string, string) (run.DecisionAuthority, error)
	AcceptDecisionContinuation(context.Context, run.DecisionAuthority, run.DecisionContinuationReceipt) (run.DecisionContinuationReceipt, error)
}

// DecisionContinuation has no public caller-controlled endpoint or verifier.
// Its worker-owned client is a real mTLS reference-only reader.
type DecisionContinuation struct {
	Store  DecisionContinuationStore
	Client *decision.ContinuationClient
}

// ContinueAcceptedDecision never accepts a receipt from Workflow history or
// a signal. It re-fetches current authority on every Activity attempt and
// commits the local CAS before returning reference-only output.
func (a *DecisionContinuation) ContinueAcceptedDecision(ctx context.Context, cp run.DecisionCheckpoint) (run.DecisionCheckpoint, error) {
	var empty run.DecisionCheckpoint
	if a == nil || a.Store == nil || a.Client == nil || !activity.IsActivity(ctx) ||
		cp.AcceptedDecisionRef.Validate() != nil || cp.Phase != run.DecisionWaitingAuthority ||
		cp.DecisionID != "" || cp.RecordSHA256 != "" || cp.PlanHash != "" {
		return empty, run.ErrDecisionPreparationDenied
	}
	info := activity.GetInfo(ctx)
	if info.WorkflowExecution.ID != cp.WorkflowID || info.WorkflowExecution.RunID != cp.ExecutionID ||
		info.WorkflowType.Name != "AcceptedDecisionV1" || info.TaskQueue != "runtime-accepted-decision-development-v1" {
		return empty, run.ErrDecisionPreparationDenied
	}
	expected, err := a.Store.GetDecisionAuthority(ctx, cp.TenantID, cp.RunID, cp.TurnID)
	if err != nil {
		return empty, err
	}
	if expected.Validate() != nil || expected.TenantID != cp.TenantID || expected.RunID != cp.RunID ||
		expected.RunIntentID != cp.RunIntentID || expected.RequestDigest != cp.RequestDigest ||
		expected.WorkflowID != cp.WorkflowID || expected.ExecutionID != cp.ExecutionID ||
		expected.AttemptID != cp.AttemptID || expected.TurnID != cp.TurnID ||
		expected.PolicyRevision != cp.PolicyRevision || expected.ConfigDigest != cp.ConfigDigest ||
		expected.InputDigest != cp.InputDigest {
		return empty, run.ErrDecisionPreparationDenied
	}
	receipt, err := a.Client.Verify(ctx, expected)
	if err != nil {
		return empty, err
	}
	persisted, err := a.Store.AcceptDecisionContinuation(ctx, expected, receipt)
	if err != nil {
		return empty, err
	}
	if persisted != receipt || persisted.Validate() != nil {
		return empty, run.ErrDecisionPreparationDenied
	}
	cp.Phase = run.DecisionAccepted
	cp.DecisionID, cp.RecordSHA256, cp.PlanHash = persisted.DecisionID, persisted.RecordSHA256, persisted.PlanHash
	return cp, nil
}
