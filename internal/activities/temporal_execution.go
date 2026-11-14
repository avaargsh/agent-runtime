package activities

import (
	"context"
	"errors"
	"strings"

	"github.com/avaargsh/agent-runtime/internal/run"
	temporalactivity "go.temporal.io/sdk/activity"
)

var (
	ErrTemporalExecutionUnavailable = errors.New("trusted Temporal Activity execution metadata unavailable")
	ErrTemporalIdentityMismatch     = errors.New("Temporal execution does not match the canonical Runtime Run")
)

type TemporalExecution struct {
	WorkflowID  string
	ExecutionID string
}

type TemporalExecutionResolver interface {
	Resolve(context.Context) (TemporalExecution, error)
}

type TemporalTurnWriter interface {
	GetOrCreateTemporalTurn(context.Context, string, string, string, string, int32) (run.TemporalTurnIdentity, error)
}

// ServerTemporalExecutionResolver reads server-issued execution identity from
// the current Temporal Activity context; it never trusts Workflow arguments.
type ServerTemporalExecutionResolver struct{}

func (ServerTemporalExecutionResolver) Resolve(ctx context.Context) (TemporalExecution, error) {
	if ctx == nil {
		return TemporalExecution{}, ErrTemporalExecutionUnavailable
	}
	info := temporalactivity.GetInfo(ctx)
	execution := TemporalExecution{
		WorkflowID:  info.WorkflowExecution.ID,
		ExecutionID: info.WorkflowExecution.RunID,
	}
	if execution.WorkflowID == "" || execution.ExecutionID == "" ||
		strings.TrimSpace(execution.WorkflowID) != execution.WorkflowID ||
		strings.TrimSpace(execution.ExecutionID) != execution.ExecutionID {
		return TemporalExecution{}, ErrTemporalExecutionUnavailable
	}
	return execution, nil
}
