package run

import "github.com/google/uuid"

const DecisionAuthoritySchema = "runtime.decision-authority.v1"

// DecisionAuthority is a point-in-time observation of the Runtime-owned
// committed business Turn, not a capability, evidence attestation or permit.
// Its immutable input digest is the typed SRE input digest, not ACP's raw
// execution-input commitment.
type DecisionAuthority struct {
	SchemaVersion  string `json:"schema_version"`
	TenantID       string `json:"tenant_id"`
	RunID          string `json:"run_id"`
	RunIntentID    string `json:"run_intent_id"`
	RequestDigest  string `json:"request_digest"`
	WorkflowID     string `json:"workflow_id"`
	ExecutionID    string `json:"execution_id"`
	AttemptID         string `json:"attempt_id"`
	AttemptGeneration int64  `json:"attempt_generation"`
	TurnID            string `json:"turn_id"`
	InvocationID   string `json:"invocation_id"`
	AgentID        string `json:"agent_id"`
	AgentReleaseID string `json:"agent_release_id"`
	SessionID      string `json:"session_id"`
	ProjectID      string `json:"project_id"`
	SubjectID      string `json:"subject_id"`
	ActorID        string `json:"actor_id"`
	PolicyRevision string `json:"policy_revision"`
	ConfigDigest   string `json:"config_digest"`
	InputDigest    string `json:"input_digest"`
	Phase          string `json:"phase"`
	Status         string `json:"status"`
	BreakerState   string `json:"breaker_state"`
	BreakerEpoch   int64  `json:"breaker_epoch"`
	BreakerVersion int64  `json:"breaker_version"`
}

func (a DecisionAuthority) Validate() error {
	ref := AcceptedDecisionRef{TenantID: a.TenantID, RunID: a.RunID, WorkflowID: a.WorkflowID,
		RunIntentID: a.RunIntentID, RequestDigest: a.RequestDigest}
	if ref.Validate() != nil || a.SchemaVersion != DecisionAuthoritySchema ||
		a.Phase != DecisionWaitingAuthority || a.Status != string(StatusRunning) ||
		a.BreakerState != "CLOSED" || a.BreakerEpoch < 1 || a.BreakerVersion < 1 ||
		a.AttemptGeneration < 1 ||
		!sha256Digest.MatchString(a.ConfigDigest) || !sha256Digest.MatchString(a.InputDigest) ||
		a.InvocationID != a.TurnID {
		return ErrDecisionPreparationDenied
	}
	for _, value := range []string{a.ExecutionID, a.AttemptID, a.TurnID, a.InvocationID} {
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return ErrDecisionPreparationDenied
		}
	}
	for _, value := range []string{a.TenantID, a.AgentID, a.AgentReleaseID, a.SessionID, a.ProjectID,
		a.SubjectID, a.ActorID, a.PolicyRevision} {
		if !decisionService.MatchString(value) {
			return ErrDecisionPreparationDenied
		}
	}
	if a.SubjectID != a.ActorID {
		return ErrDecisionPreparationDenied
	}
	return nil
}
