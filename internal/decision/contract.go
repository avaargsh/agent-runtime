package decision

import (
	"errors"
	"strings"
	"unicode/utf8"
)

type Turn struct {
	ProtocolVersion string `json:"protocol_version"`
	InvocationID    string `json:"invocation_id"`
	TenantID        string `json:"tenant_id"`
	AgentID         string `json:"agent_id"`
	RunID           string `json:"run_id"`
	TurnID          string `json:"turn_id"`
	UserInput       string `json:"user_input"`
}

type Result struct {
	ProtocolVersion string `json:"protocol_version"`
	InvocationID    string `json:"invocation_id"`
	Kind            string `json:"kind"`
	Text            string `json:"text"`
}

func (t Turn) Validate() error {
	if t.ProtocolVersion != "v0.1" {
		return errors.New("unsupported protocol version")
	}
	for _, s := range []string{t.InvocationID, t.TenantID, t.AgentID, t.RunID, t.TurnID, t.UserInput} {
		if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || len(s) > 4096 {
			return errors.New("invalid decision turn field")
		}
	}
	return nil
}

func (r Result) ValidateEnvelope() error {
	if r.ProtocolVersion != "v0.1" || strings.TrimSpace(r.InvocationID) == "" ||
		strings.TrimSpace(r.InvocationID) != r.InvocationID || len(r.InvocationID) > 255 ||
		r.Kind != "final_response" || strings.TrimSpace(r.Text) == "" ||
		!utf8.ValidString(r.Text) || len(r.Text) > 8192 {
		return errors.New("invalid decision result")
	}
	return nil
}

func (r Result) Validate(t Turn) error {
	if err := r.ValidateEnvelope(); err != nil {
		return err
	}
	if r.InvocationID != t.InvocationID {
		return errors.New("decision result invocation does not match canonical turn")
	}
	return nil
}
