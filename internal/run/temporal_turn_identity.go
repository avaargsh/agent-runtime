package run

import (
	"fmt"

	"github.com/google/uuid"
)

// TemporalTurnIdentity records a Runtime-owned Attempt and Decision Turn
// correlated with one server-assigned Temporal Workflow execution. Its IDs
// are persisted before use and never accepted from ACP, Workflow arguments
// or the Decision plugin.
type TemporalTurnIdentity struct {
	TenantID            string
	RunID               string
	WorkflowID          string
	TemporalExecutionID string
	RunAttemptID        string
	TurnID              string
	InvocationID        string
	TurnIndex           int32
}

func (i TemporalTurnIdentity) Validate() error {
	for _, value := range []string{i.RunID, i.TemporalExecutionID, i.RunAttemptID, i.TurnID, i.InvocationID} {
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return fmt.Errorf("%w: malformed Runtime execution identity", ErrInvalidIdentity)
		}
	}
	if i.TenantID == "" || len(i.TenantID) > 255 ||
		i.WorkflowID != ACPWorkflowPrefix+i.RunID ||
		i.InvocationID != i.TurnID || i.TurnIndex < 1 || i.TurnIndex > 10000 {
		return fmt.Errorf("%w: inconsistent Runtime execution binding", ErrInvalidIdentity)
	}
	return nil
}
