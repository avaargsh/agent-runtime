package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/executionsafety"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// Proposal transitions must outlive outbox delivery and keep their own
// immutable, tenant/Run scoped audit facts. This tests the actual v3 schema.
func TestProposalLifecycleAppendsIndependentSecurityAudit(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	prepared, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	conditions := proposalCommitConditions()
	committed, err := h.store.CommitProposal(ctx, h.tenantID, proposal.ID, conditions)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := h.store.CommitProposal(ctx, h.tenantID, proposal.ID, conditions)
	if err != nil || replayed.Version != committed.Version {
		t.Fatalf("idempotent Commit replay: got %+v err %v", replayed, err)
	}
	linked, err := h.store.LinkGuardOperation(ctx, executionsafety.GuardOperationLink{
		TenantID: h.tenantID, ProposalID: proposal.ID,
		GuardSubmissionKey: committed.GuardSubmissionKey,
		ActionRequestDigest: committed.ActionRequestDigest,
		OperationID: "guard-operation-audit-001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Version != 2 || committed.Version != 3 || linked.Version != 4 {
		t.Fatalf("invalid proposal transition versions: %d/%d/%d", prepared.Version, committed.Version, linked.Version)
	}
	// The archive is distinct from the delivery queue. A delivered outbox
	// message may be removed without erasing historical security evidence.
	if _, err := h.pool.Exec(ctx, `
		DELETE FROM runtime_execution_outbox
		WHERE tenant_id=$1 AND proposal_id=$2
	`, h.tenantID, proposal.ID); err != nil {
		t.Fatal(err)
	}
	facts, err := postgres.New(h.pool).ListProposalSecurityAudit(ctx, h.tenantID, h.runID, proposal.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PROPOSAL_CREATED", "PROPOSAL_PREPARED",
		"PROPOSAL_COMMIT_AUTHORIZED", "GUARD_OPERATION_LINKED",
	}
	if len(facts) != len(want) {
		t.Fatalf("lifecycle security audit count = %d, want %d: %+v", len(facts), len(want), facts)
	}
	for i, eventType := range want {
		if string(facts[i].EventType) != eventType ||
			facts[i].Source != "runtime-proposal-state" ||
			facts[i].PayloadDigest != proposalDigest {
			t.Errorf("event[%d] = %+v, want %s/redacted system metadata", i, facts[i], eventType)
		}
	}
	if facts[3].GuardOperationID != linked.GuardOperationID {
		t.Fatalf("Guard operation correlation missing from immutable audit: %+v", facts[3])
	}
	// Outbox JSON contains delivery details; the independent security audit
	// retains only safe correlation fields, never confirmation or Guard keys.
	var data string
	if err := h.pool.QueryRow(ctx, `
		SELECT payload::text FROM runtime_security_audit_events
		WHERE tenant_id=$1 AND run_id=$2 AND proposal_id=$3
		  AND event_type='PROPOSAL_COMMIT_AUTHORIZED'
	`, h.tenantID, h.runID, proposal.ID).Scan(&data); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"guard_submission_key", "confirmation_ref", "confirmation_actor_id",
		"tool_policy", "arguments", conditions.GuardSubmissionKey,
		conditions.Confirmation.EvidenceRef,
	} {
		if strings.Contains(data, forbidden) {
			t.Fatalf("security audit leaked protected submission detail %q in %s", forbidden, data)
		}
	}
}

func TestProposalLifecycleAuditFailureRollsBackPrepareAndOutbox(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	// Block only audit writes for the next transition. A state/Outbox
	// success with missing independent audit would be a broken commit boundary.
	if _, err := h.pool.Exec(ctx, `
		CREATE FUNCTION reject_proposal_prepared_audit() RETURNS trigger
		LANGUAGE plpgsql AS $block$
		BEGIN
			IF NEW.event_type = 'PROPOSAL_PREPARED' THEN
				RAISE EXCEPTION 'synthetic audit archive outage';
			END IF;
			RETURN NEW;
		END;
		$block$;
		CREATE TRIGGER reject_proposal_prepared_audit_insert
		BEFORE INSERT ON runtime_security_audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_proposal_prepared_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true); err == nil {
		t.Fatal("PrepareProposal succeeded while immutable security audit was unavailable")
	}
	got, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.State != executionsafety.ProposalProposed {
		t.Fatalf("Prepare committed despite failed audit archive: %+v", got)
	}
	var preparedOutbox int
	if err := h.pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_execution_outbox
		WHERE tenant_id=$1 AND proposal_id=$2
		  AND event_type='ToolProposalPrepared'
	`, h.tenantID, proposal.ID).Scan(&preparedOutbox); err != nil {
		t.Fatal(err)
	}
	if preparedOutbox != 0 {
		t.Fatalf("a failed security-audit transaction still emitted %d prepared outbox event(s)", preparedOutbox)
	}
}

func TestProposalSupersessionLeavesImmutableSecurityAudit(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	if err := h.store.AdvanceTurnIntent(
		ctx, h.tenantID, h.runID, h.turnID, 11, 12, true,
	); err != nil {
		t.Fatal(err)
	}
	got, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != executionsafety.ProposalSuperseded {
		t.Fatalf("old uncommitted Proposal was not superseded: %+v", got)
	}
	facts, err := h.store.ListProposalSecurityAudit(ctx, h.tenantID, h.runID, proposal.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 ||
		string(facts[0].EventType) != "PROPOSAL_CREATED" ||
		string(facts[1].EventType) != "PROPOSAL_SUPERSEDED" {
		t.Fatalf("superseded proposal lost independent lifecycle evidence: %+v", facts)
	}
}
