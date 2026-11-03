package run_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

func TestACPIntentCreationRejectsMissingInput(t *testing.T) {
	request := run.IntentStartRequest{
		TenantID: "tenant-1",
		RunIntentID: "11111111-1111-4111-8111-111111111111",
		RequestDigest: "sha256:" + strings.Repeat("a", 64),
		AgentID: "agent-1",
		AgentReleaseID: "release-1",
		SessionID: "session-1",
		Input: []byte(`{"message":"hello"}`),
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid explicit input was rejected: %v", err)
	}
	for _, missing := range [][]byte{nil, {}} {
		request.Input = missing
		if err := request.Validate(); !errors.Is(err, run.ErrInvalidRequest) {
			t.Fatalf("missing ACP input must fail closed, got %v", err)
		}
	}
}
