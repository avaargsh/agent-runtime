package run

import (
	"errors"

	"github.com/google/uuid"
)

const GuardExecutionAuthoritySchema = "runtime.guard-execution-authority.v1"

var ErrGuardExecutionAuthorityDenied = errors.New("Runtime Guard execution authority denied")

// GuardExecutionAuthority is a point-in-time, read-only projection of the
// canonical Runtime Run, current Attempt and current Turn. It is a necessary
// identity check only; it is not Approval, Risk, Permit or permission to
// perform a protected effect. Guard and the independently deployed Executor
// must revalidate their own effect-time fences.
type GuardExecutionAuthority struct {
	SchemaVersion       string `json:"schema_version"`
	TenantID            string `json:"tenant_id"`
	RunID               string `json:"run_id"`
	AgentID             string `json:"agent_id"`
	AgentReleaseID      string `json:"agent_release_id"`
	SessionID           string `json:"session_id"`
	WorkflowID          string `json:"workflow_id"`
	TemporalExecutionID string `json:"execution_id"`
	RunAttemptID        string `json:"run_attempt_id"`
	TurnID              string `json:"turn_id"`
	InvocationID        string `json:"invocation_id"`
	TurnIndex           int32  `json:"turn_index"`
	AttemptGeneration   int64  `json:"attempt_generation"`
	AttemptBreakerEpoch int64  `json:"attempt_breaker_epoch"`
	Status              string `json:"status"`
	BreakerState        string `json:"breaker_state"`
	BreakerEpoch        int64  `json:"breaker_epoch"`
	BreakerVersion      int64  `json:"breaker_version"`
}

// Validate accepts only the currently supported immutable generation-one
// execution contract. Any future Attempt transition or breaker recovery must
// introduce an explicit versioned authority contract; positive integers alone
// do not authorize a new generation.
func (a GuardExecutionAuthority) Validate() error {
	identity := Identity{
		TenantID: a.TenantID, RunID: a.RunID, AgentID: a.AgentID,
		AgentReleaseID: a.AgentReleaseID, SessionID: a.SessionID,
	}
	if a.SchemaVersion != GuardExecutionAuthoritySchema ||
		identity.Validate() != nil ||
		a.WorkflowID != ACPWorkflowPrefix+a.RunID ||
		a.Status != string(StatusRunning) ||
		a.BreakerState != "CLOSED" ||
		a.AttemptGeneration != 1 ||
		a.AttemptBreakerEpoch != 1 ||
		a.BreakerEpoch != a.AttemptBreakerEpoch ||
		a.BreakerVersion != 1 ||
		a.TurnIndex < 1 || a.TurnIndex > 10000 ||
		a.InvocationID != a.TurnID {
		return ErrGuardExecutionAuthorityDenied
	}
	for _, value := range []string{a.RunID, a.TemporalExecutionID, a.RunAttemptID, a.TurnID, a.InvocationID} {
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return ErrGuardExecutionAuthorityDenied
		}
	}
	return nil
}
