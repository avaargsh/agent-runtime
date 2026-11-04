package run

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	ErrRunNotFound    = errors.New("Runtime Run identity not found")
	ErrInvalidIdentity = errors.New("invalid Runtime Run identity")
)

// Identity is the canonical execution identity persisted by Runtime.
// Consumers must resolve it from the Runtime Run store; Workflow/plugin input
// is only a correlation hint and is never authoritative.
type Identity struct {
	RunID          string
	TenantID       string
	AgentID        string
	AgentReleaseID string
	SessionID      string
}

func (i Identity) Validate() error {
	fields := []struct {
		name  string
		value string
	}{
		{"run_id", i.RunID},
		{"tenant_id", i.TenantID},
		{"agent_id", i.AgentID},
		{"agent_release_id", i.AgentReleaseID},
		{"session_id", i.SessionID},
	}
	for _, field := range fields {
		if field.value == "" || strings.TrimSpace(field.value) != field.value ||
			len(field.value) > 255 || !utf8.ValidString(field.value) ||
			strings.ContainsRune(field.value, '\x00') {
			return fmt.Errorf("%w: %s", ErrInvalidIdentity, field.name)
		}
	}
	return nil
}
