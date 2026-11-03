package run

import (
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const ACPWorkflowPrefix = "agent-run/v1/"

var ErrIntentNotFound = errors.New("RunIntent absent in current committed RunStore snapshot; not an authoritative final not-found")
var sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// IntentStartRequest is an authenticated ACP-to-Runtime command, never an
// untrusted public user request. ACP supplies the persisted immutable digest.
// The Runtime must not infer it from a different local input schema.
type IntentStartRequest struct {
	TenantID       string
	RunIntentID    string
	RequestDigest  string
	AgentID        string
	AgentReleaseID string
	SessionID      string
	Input          []byte
}

type IntentReceipt struct {
	TenantID      string
	RunIntentID   string
	RequestDigest string
	RunID         string
	WorkflowID    string
	Created       bool
}

func (r IntentStartRequest) Validate() error {
	if _, err := uuid.Parse(r.RunIntentID); err != nil {
		return ErrInvalidRequest
	}
	if !sha256Digest.MatchString(r.RequestDigest) {
		return ErrInvalidRequest
	}
	for _, value := range []string{r.TenantID, r.AgentID, r.AgentReleaseID, r.SessionID} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 255 ||
			strings.ContainsAny(value, "\x00\r\n\t") {
			return ErrInvalidRequest
		}
	}
	if _, err := canonicalObject(r.Input); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

// CanonicalIntentInput normalizes bounded JSON for stable replay comparisons.
// Independent authenticated source validation belongs to the ACP adapter.
func CanonicalIntentInput(input []byte) ([]byte, error) {
	return canonicalObject(input)
}
