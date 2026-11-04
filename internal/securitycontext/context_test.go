package securitycontext

import (
	"context"
	"testing"
)

func validClaims() Claims {
	return Claims{
		TenantID:       "tenant-001",
		SubjectID:      "user-001",
		ActorID:        "actor-001",
		AgentID:        "agent-001",
		AgentReleaseID: "release-001",
		SessionID:      "session-001",
		RunID:          "run-001",
		RunAttemptID:   "attempt-001",
		TurnID:         "turn-001",
		PolicyRevision: "policy-rev-7",
	}
}

func TestNewContextPreservesCanonicalIdentityChain(t *testing.T) {
	got, err := New(validClaims())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got.TenantID() != "tenant-001" ||
		got.SubjectID() != "user-001" ||
		got.ActorID() != "actor-001" ||
		got.AgentID() != "agent-001" ||
		got.AgentReleaseID() != "release-001" ||
		got.SessionID() != "session-001" ||
		got.RunID() != "run-001" ||
		got.RunAttemptID() != "attempt-001" ||
		got.TurnID() != "turn-001" ||
		got.PolicyRevision() != "policy-rev-7" {
		t.Fatalf("New() returned an unexpected identity chain: %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestNewContextRejectsMissingOrMalformedIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Claims)
	}{
		{name: "missing tenant", mutate: func(c *Claims) { c.TenantID = "" }},
		{name: "missing actor", mutate: func(c *Claims) { c.ActorID = "" }},
		{name: "missing agent release", mutate: func(c *Claims) { c.AgentReleaseID = "" }},
		{name: "missing session", mutate: func(c *Claims) { c.SessionID = "" }},
		{name: "missing run attempt", mutate: func(c *Claims) { c.RunAttemptID = "" }},
		{name: "missing policy revision", mutate: func(c *Claims) { c.PolicyRevision = "" }},
		{name: "leading whitespace", mutate: func(c *Claims) { c.RunID = " run-001" }},
		{name: "embedded NUL", mutate: func(c *Claims) { c.SubjectID = "user\x00bad" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			tc.mutate(&claims)
			if got, err := New(claims); err == nil || got.Validate() == nil {
				t.Fatalf("New() = %+v, %v; want invalid context", got, err)
			}
		})
	}
}

func TestContextCannotBeRetrievedFromUnboundGoContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("FromContext(background) unexpectedly returned a SecurityContext")
	}
}

func TestWithContextAndFromContextRoundTrip(t *testing.T) {
	security, err := New(validClaims())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := WithContext(context.Background(), security)
	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext() did not find the bound SecurityContext")
	}
	if got.RunID() != security.RunID() || got.TenantID() != security.TenantID() {
		t.Fatalf("round-trip identity = (%s,%s), want (%s,%s)",
			got.TenantID(), got.RunID(), security.TenantID(), security.RunID())
	}
}
