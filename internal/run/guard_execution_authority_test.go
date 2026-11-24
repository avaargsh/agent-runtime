package run

import (
	"errors"
	"testing"
)

func validGuardExecutionAuthority() GuardExecutionAuthority {
	const runID = "11111111-1111-4111-8111-111111111111"
	return GuardExecutionAuthority{
		SchemaVersion: GuardExecutionAuthoritySchema,
		TenantID: "tenant-1",
		RunID: runID,
		WorkflowID: ACPWorkflowPrefix + runID,
		TemporalExecutionID: "22222222-2222-4222-8222-222222222222",
		RunAttemptID: "33333333-3333-4333-8333-333333333333",
		TurnID: "44444444-4444-4444-8444-444444444444",
		InvocationID: "44444444-4444-4444-8444-444444444444",
		TurnIndex: 1,
		AgentID: "agent-1",
		AgentReleaseID: "release-1",
		SessionID: "session-1",
		Status: string(StatusRunning),
		AttemptGeneration: 1,
		AttemptBreakerEpoch: 1,
		BreakerState: "CLOSED",
		BreakerEpoch: 1,
		BreakerVersion: 1,
	}
}

func TestGuardExecutionAuthorityValidatesCanonicalCurrentBinding(t *testing.T) {
	if err := validGuardExecutionAuthority().Validate(); err != nil {
		t.Fatalf("valid current authority rejected: %v", err)
	}
}

func TestGuardExecutionAuthorityRejectsUnboundOrStaleFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*GuardExecutionAuthority)
	}{
		{"schema", func(a *GuardExecutionAuthority) { a.SchemaVersion = "runtime.guard-execution-authority.v2" }},
		{"workflow", func(a *GuardExecutionAuthority) { a.WorkflowID = "not-the-acp-workflow/" + a.RunID }},
		{"noncanonical run", func(a *GuardExecutionAuthority) { a.RunID = "11111111111141118111111111111111" }},
		{"noncanonical execution", func(a *GuardExecutionAuthority) { a.TemporalExecutionID = "22222222-2222-4222-8222-22222222222A" }},
		{"attempt missing", func(a *GuardExecutionAuthority) { a.RunAttemptID = "" }},
		{"turn mismatch", func(a *GuardExecutionAuthority) { a.InvocationID = "55555555-5555-4555-8555-555555555555" }},
		{"turn index", func(a *GuardExecutionAuthority) { a.TurnIndex = 0 }},
		{"terminal run", func(a *GuardExecutionAuthority) { a.Status = string(StatusCancelled) }},
		{"open breaker", func(a *GuardExecutionAuthority) { a.BreakerState = "OPEN" }},
		{"attempt generation", func(a *GuardExecutionAuthority) { a.AttemptGeneration = 2 }},
		{"attempt breaker epoch", func(a *GuardExecutionAuthority) { a.AttemptBreakerEpoch = 2 }},
		{"breaker epoch", func(a *GuardExecutionAuthority) { a.BreakerEpoch = 2 }},
		{"breaker version", func(a *GuardExecutionAuthority) { a.BreakerVersion = 2 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validGuardExecutionAuthority()
			tc.mutate(&got)
			if err := got.Validate(); !errors.Is(err, ErrGuardExecutionAuthorityDenied) {
				t.Fatalf("Validate() error = %v, want ErrGuardExecutionAuthorityDenied", err)
			}
		})
	}
}
