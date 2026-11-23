package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/audit"
	"github.com/avaargsh/agent-runtime/internal/securitycontext"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// A proposal read is scoped to the canonical v3 Proposal row. Security audit
// facts (not the delivery outbox) are the only source for this read.
func TestProposalSecurityAuditReadScopesRunAndReturnsMetadataOnly(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	identity := proposalAuditIdentity(t, h.tenantID, h.runID, h.turnID)
	first := audit.Event{
		EventID: "proposal-audit-first", OccurredAt: time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC),
		Type: audit.EventToolCallStarted, Identity: identity, Source: "trusted-tool-adapter",
		ProposalID: proposal.ID, ToolCallID: "tool-1", Outcome: audit.OutcomeDispatched,
		Action:        "synthetic-secret-never-return-from-proposal-audit",
		PayloadDigest: proposalDigest,
	}
	second := first
	second.EventID = "proposal-audit-second"
	second.Type = audit.EventToolCallCompleted
	second.Outcome = audit.OutcomeSucceeded
	second.OccurredAt = first.OccurredAt.Add(time.Minute)
	// Insert in reverse order to prove stable, persisted chronological results.
	if err := h.store.Append(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Append(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Append(ctx, first); err != nil {
		t.Fatalf("idempotent audit replay: %v", err)
	}
	// A forged audit correlation with the same proposal ID but another Run
	// must never be returned by a canonical Run-scoped evidence lookup.
	forged := first
	forged.EventID = "proposal-audit-other-run"
	forged.Identity = proposalAuditIdentity(t, h.tenantID, "00000000-0000-4000-8000-000000000099", h.turnID)
	if err := h.store.Append(ctx, forged); err != nil {
		t.Fatal(err)
	}
	// A new Store instance mimics a process restart over the same durable DB.
	got, err := postgres.New(h.pool).ListProposalSecurityAudit(ctx, h.tenantID, h.runID, proposal.ID, 3)
	if err != nil {
		t.Fatalf("ListProposalSecurityAudit: %v", err)
	}
	if len(got) != 2 || got[0].EventID != first.EventID || got[1].EventID != second.EventID ||
		got[0].EventType != first.Type || got[1].EventType != second.Type ||
		got[0].PayloadDigest != proposalDigest || got[0].Source != first.Source {
		t.Fatalf("incorrect durable proposal audit metadata: %+v", got)
	}
	serialized, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "synthetic-secret-never-return") ||
		strings.Contains(string(serialized), "payload") && strings.Contains(string(serialized), "action") {
		t.Fatalf("proposal metadata read exposed audit payload: %s", serialized)
	}
	page, err := h.store.ListProposalSecurityAudit(ctx, h.tenantID, h.runID, proposal.ID, 1)
	if err != nil || len(page) != 1 || page[0].EventID != first.EventID {
		t.Fatalf("bounded oldest-first audit: records=%+v err=%v", page, err)
	}
}

func TestProposalSecurityAuditReadFailsClosedForScopeAndBounds(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant, runID, proposalID string
		limit                     int
		want                      error
	}{
		{h.tenantID, h.runID, proposal.ID, 0, postgres.ErrInvalidProposalAuditQuery},
		{h.tenantID, h.runID, proposal.ID, 101, postgres.ErrInvalidProposalAuditQuery},
		{h.tenantID + "\n", h.runID, proposal.ID, 10, postgres.ErrInvalidProposalAuditQuery},
		{h.tenantID, "not-a-uuid", proposal.ID, 10, postgres.ErrInvalidProposalAuditQuery},
		{"foreign-tenant", h.runID, proposal.ID, 10, postgres.ErrProposalNotFound},
		{h.tenantID, "00000000-0000-4000-8000-000000000099", proposal.ID, 10, postgres.ErrProposalNotFound},
		{h.tenantID, h.runID, "different-proposal", 10, postgres.ErrProposalNotFound},
	} {
		_, err := h.store.ListProposalSecurityAudit(ctx, tc.tenant, tc.runID, tc.proposalID, tc.limit)
		if !errors.Is(err, tc.want) {
			t.Errorf("scope tenant=%q run=%q proposal=%q limit=%d: got %v want %v",
				tc.tenant, tc.runID, tc.proposalID, tc.limit, err, tc.want)
		}
	}
}

func proposalAuditIdentity(t *testing.T, tenantID, runID, turnID string) securitycontext.Context {
	t.Helper()
	identity, err := securitycontext.New(securitycontext.Claims{
		TenantID: tenantID, SubjectID: "subject-alice", ActorID: "actor-alice",
		AgentID: "agent-alice", AgentReleaseID: "release-alice",
		SessionID: "session-alice", RunID: runID, RunAttemptID: "attempt-alice",
		TurnID: turnID, PolicyRevision: "policy-alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
