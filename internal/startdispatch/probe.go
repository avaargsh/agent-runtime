package startdispatch

import (
	"context"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type ProbeResult struct {
	RunID       string
	ExecutionID string
	AttemptID   string
	TurnID      string
}

type probeStore interface {
	GetRunIdentity(context.Context, string) (run.Identity, error)
	GetRunPrincipalSnapshot(context.Context, string, string) (run.PrincipalSnapshot, error)
	GetOrCreateTemporalTurn(context.Context, string, string, string, string, int32) (run.TemporalTurnIdentity, error)
}

type ProbeActivities struct {
	Store probeStore
}

// AdmissionProbe verifies identity persistence only. The probe's completion
// does not mark a business Run successful, authorize model egress, or imply
// approval from a protected-action or independent evidence verifier.
func AdmissionProbe(ctx workflow.Context, input ProbeInput) (ProbeResult, error) {
	if err := input.validate(); err != nil {
		return ProbeResult{}, err
	}
	info := workflow.GetInfo(ctx)
	if info.WorkflowExecution.ID != input.WorkflowID {
		return ProbeResult{}, ErrExecutionConflict
	}
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	var result ProbeResult
	err := workflow.ExecuteActivity(ctx, "BindAdmissionProbe", input).Get(ctx, &result)
	return result, err
}

func (a *ProbeActivities) BindAdmissionProbe(ctx context.Context, input ProbeInput) (ProbeResult, error) {
	if a == nil || a.Store == nil {
		return ProbeResult{}, ErrInvalidConfig
	}
	if err := input.validate(); err != nil {
		return ProbeResult{}, err
	}
	info := activity.GetInfo(ctx)
	if info.WorkflowExecution.ID != input.WorkflowID || info.WorkflowExecution.RunID == "" ||
		info.WorkflowType.Name != DevelopmentWorkflow {
		return ProbeResult{}, ErrExecutionConflict
	}
	identity, err := a.Store.GetRunIdentity(ctx, input.RunID)
	if err != nil || identity.Validate() != nil || identity.TenantID != input.TenantID || identity.RunID != input.RunID {
		return ProbeResult{}, ErrExecutionConflict
	}
	principal, err := a.Store.GetRunPrincipalSnapshot(ctx, identity.TenantID, identity.RunID)
	if err != nil || principal.Validate() != nil {
		return ProbeResult{}, ErrExecutionConflict
	}
	bound, err := a.Store.GetOrCreateTemporalTurn(ctx, identity.TenantID, identity.RunID,
		info.WorkflowExecution.ID, info.WorkflowExecution.RunID, 1)
	if err != nil {
		return ProbeResult{}, err
	}
	if bound.Validate() != nil || bound.TenantID != identity.TenantID ||
		bound.RunID != identity.RunID || bound.WorkflowID != input.WorkflowID ||
		bound.TemporalExecutionID != info.WorkflowExecution.RunID || bound.TurnIndex != 1 {
		return ProbeResult{}, ErrExecutionConflict
	}
	return ProbeResult{RunID: bound.RunID, ExecutionID: bound.TemporalExecutionID,
		AttemptID: bound.RunAttemptID, TurnID: bound.TurnID}, nil
}
