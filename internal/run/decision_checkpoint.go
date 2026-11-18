package run

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/google/uuid"
)

const (
	DecisionWaitingAuthority = "WAITING_AUTHORITY"
	DecisionAccepted = "DECISION_ACCEPTED"
)

var ErrDecisionPreparationDenied = errors.New("accepted decision preparation denied")
var decisionService = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// AcceptedDecisionRef contains only correlation references. Never put the
// task body, bearer token or authority snapshot contents in workflow history.
type AcceptedDecisionRef struct {
	TenantID      string
	RunID         string
	WorkflowID    string
	RunIntentID   string
	RequestDigest string
}

func (r AcceptedDecisionRef) Validate() error {
	for _, value := range []string{r.RunID, r.RunIntentID} {
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return ErrDecisionPreparationDenied
		}
	}
	if r.WorkflowID != ACPWorkflowPrefix+r.RunID ||
		(IntentStartRequest{TenantID: r.TenantID, RunIntentID: r.RunIntentID, RequestDigest: r.RequestDigest}).ValidateLookup() != nil {
		return ErrDecisionPreparationDenied
	}
	return nil
}

// DecisionCheckpoint is a committed preparation fact, not a permit,
// DecisionRecord, business outcome, or independently verified result.
type DecisionCheckpoint struct {
	AcceptedDecisionRef
	ExecutionID    string
	AttemptID      string
	TurnID         string
	InputDigest    string
	PolicyRevision string
	ConfigDigest   string
	Phase          string
	DecisionID     string `json:",omitempty"`
	RecordSHA256   string `json:",omitempty"`
	PlanHash       string `json:",omitempty"`
}

// The current Go Decision Core input schema targets read-only SRE triage.
// This slice validates only that business input; context, capabilities,
// evidence, budget and live authority must be resolved separately.
type SREDecisionInput struct {
	Objective string `json:"objective"`
	Service   string `json:"service"`
	Signal    string `json:"signal"`
}

// DigestSREDecisionInput accepts only the exact three field names, each
// occurring once. The digest covers a stable typed representation, not a
// replacement for the ACP source request digest.
func DigestSREDecisionInput(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return "", ErrDecisionPreparationDenied
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return "", ErrDecisionPreparationDenied
	}
	var input SREDecisionInput
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return "", ErrDecisionPreparationDenied
		}
		seen[key] = true
		var value string
		if err := d.Decode(&value); err != nil {
			return "", ErrDecisionPreparationDenied
		}
		switch key {
		case "objective":
			input.Objective = value
		case "service":
			input.Service = value
		case "signal":
			input.Signal = value
		default:
			return "", ErrDecisionPreparationDenied
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 3 {
		return "", ErrDecisionPreparationDenied
	}
	if _, err := d.Token(); err != io.EOF {
		return "", ErrDecisionPreparationDenied
	}
	if input.Objective != "sre_incident_triage" || !decisionService.MatchString(input.Service) {
		return "", ErrDecisionPreparationDenied
	}
	switch input.Signal {
	case "latency", "errors", "saturation":
	default:
		return "", ErrDecisionPreparationDenied
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return "", ErrDecisionPreparationDenied
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
