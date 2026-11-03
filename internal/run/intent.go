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

// ValidateLookup validates the immutable correlation scope needed for a
// read-only durable lookup. A lookup does not carry create-only Agent or input.
func (r IntentStartRequest) ValidateLookup() error {
	if _, err := uuid.Parse(r.RunIntentID); err != nil {
		return ErrInvalidRequest
	}
	if !sha256Digest.MatchString(r.RequestDigest) {
		return ErrInvalidRequest
	}
	if r.TenantID == "" || strings.TrimSpace(r.TenantID) != r.TenantID ||
		len(r.TenantID) > 255 || strings.ContainsAny(r.TenantID, "\x00\r\n\t") {
		return ErrInvalidRequest
	}
	return nil
}

// Validate enforces the full create-only ACP request contract. Missing input
// must never silently become an empty JSON object during Run acceptance.
func (r IntentStartRequest) Validate() error {
	if err := r.ValidateLookup(); err != nil {
		return err
	}
	for _, value := range []string{r.AgentID, r.AgentReleaseID, r.SessionID} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 255 ||
			strings.ContainsAny(value, "\x00\r\n\t") {
			return ErrInvalidRequest
		}
	}
	if len(r.Input) == 0 {
		return ErrInvalidRequest
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
