package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/executionsafety"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

const proposalDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func proposalPolicy() executionsafety.ToolPolicy {
	return executionsafety.ToolPolicy{
		CapabilityID:              "iam.role.update",
		CapabilityVersion:         "v1",
		PolicyDigest:              proposalDigest,
		EffectClass:               executionsafety.EffectReversibleWrite,
		Idempotent:                true,
		RequiresConfirmation:      true,
		RequiresApproval:          true,
		ApprovalPolicyRef:         "policy://iam-role-change/v1",
		CompensationCapabilityRef: "iam.role.revoke",
	}
}

func newProposalStore(t *testing.T, revision int64) (*pgxProposalHarness, executionsafety.Proposal) {
	t.Helper()
	pool, store := newTestStore(t)
	receipt, err := store.AcceptIntent(context.Background(), testIntent())
	if err != nil {
		t.Fatalf("accept RunIntent: %v", err)
	}
	h := &pgxProposalHarness{pool: pool, store: store, tenantID: receipt.TenantID, runID: receipt.RunID, turnID: "turn-alice-access"}
	if err := store.CreateTurnIntent(context.Background(), postgres.TurnIntent{
		TenantID: h.tenantID, RunID: h.runID, TurnID: h.turnID,
		Revision: revision, Complete: true,
	}); err != nil {
		t.Fatalf("create TurnIntent: %v", err)
	}
	proposal, err := executionsafety.NewProposal(executionsafety.ProposalInput{
		ID: "proposal-readonly", TenantID: h.tenantID, RunID: h.runID, TurnID: h.turnID,
		IntentRevision: revision, ArgumentsDigest: proposalDigest,
		ActionRequestDigest: proposalDigest, ToolPolicy: proposalPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, proposal
}

type pgxProposalHarness struct {
	pool     *pgxpool.Pool
	store    *postgres.Store
	tenantID string
	runID    string
	turnID   string
}

func proposalCommitConditions() executionsafety.CommitConditions {
	return executionsafety.CommitConditions{
		CapabilityAllowed:       true,
		RuntimeAdmissionAllowed: true,
		Confirmation: &executionsafety.UserConfirmation{
			ActorID:             "user-alice",
			EvidenceRef:         "evidence://confirmations/alice/read_only",
			ActionRequestDigest: proposalDigest,
		},
		GuardSubmissionKey:  "guard-submit-alice-readonly-1",
		ActionRequestDigest: proposalDigest,
	}
}

func TestProposalPostgresLifecycleIsDurableAndIdempotent(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()

	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	prepared, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true)
	if err != nil {
		t.Fatalf("PrepareProposal: %v", err)
	}
	if prepared.State != executionsafety.ProposalPrepared || prepared.Version != 2 {
		t.Fatalf("unexpected prepared proposal: %+v", prepared)
	}

	conditions := proposalCommitConditions()
	committed, err := h.store.CommitProposal(ctx, h.tenantID, proposal.ID, conditions)
	if err != nil {
		t.Fatalf("CommitProposal: %v", err)
	}
	if committed.State != executionsafety.ProposalCommitAuthorized || committed.Version != 3 {
		t.Fatalf("unexpected committed proposal: %+v", committed)
	}
	replayed, err := h.store.CommitProposal(ctx, h.tenantID, proposal.ID, conditions)
	if err != nil {
		t.Fatalf("idempotent CommitProposal replay: %v", err)
	}
	if replayed.Version != committed.Version || replayed.GuardSubmissionKey != committed.GuardSubmissionKey {
		t.Fatalf("Commit replay changed durable state: committed=%+v replay=%+v", committed, replayed)
	}

	linked, err := h.store.LinkGuardOperation(ctx, executionsafety.GuardOperationLink{
		TenantID: h.tenantID, ProposalID: proposal.ID,
		GuardSubmissionKey:  committed.GuardSubmissionKey,
		ActionRequestDigest: committed.ActionRequestDigest,
		OperationID:         "guard-operation-alice-001",
	})
	if err != nil {
		t.Fatalf("LinkGuardOperation: %v", err)
	}
	loaded, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	if linked.State != executionsafety.ProposalSubmittedToGuard ||
		loaded.State != executionsafety.ProposalSubmittedToGuard ||
		loaded.GuardOperationID != "guard-operation-alice-001" ||
		loaded.ConfirmationActorID != "user-alice" ||
		loaded.ConfirmationRef != "evidence://confirmations/alice/read_only" {
		t.Fatalf("durable proposal / Guard evidence mismatch: linked=%+v loaded=%+v", linked, loaded)
	}

	var events int
	if err := h.pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_execution_outbox
		WHERE tenant_id=$1 AND proposal_id=$2
	`, h.tenantID, proposal.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 4 {
		t.Fatalf("proposal event count=%d, want create/prepare/commit/Guard link (4)", events)
	}
}

func TestAdvanceTurnIntentSupersedesOldProposalAndBlocksCommit(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := h.store.AdvanceTurnIntent(ctx, h.tenantID, h.runID, h.turnID, 11, 12, true); err != nil {
		t.Fatalf("AdvanceTurnIntent: %v", err)
	}
	loaded, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != executionsafety.ProposalSuperseded || loaded.Version != 3 {
		t.Fatalf("old proposal was not superseded: %+v", loaded)
	}
	if _, err := h.store.CommitProposal(ctx, h.tenantID, proposal.ID, proposalCommitConditions()); !errors.Is(err, executionsafety.ErrInvalidTransition) {
		t.Fatalf("superseded proposal crossed Commit: %v", err)
	}
}

func TestCommitBeforeIntentCorrectionIsNeverSuperseded(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true); err != nil {
		t.Fatal(err)
	}
	committed, err := h.store.CommitProposal(ctx, h.tenantID, proposal.ID, proposalCommitConditions())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.AdvanceTurnIntent(ctx, h.tenantID, h.runID, h.turnID, 11, 12, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != executionsafety.ProposalCommitAuthorized ||
		loaded.State != executionsafety.ProposalCommitAuthorized ||
		loaded.GuardSubmissionKey == "" {
		t.Fatalf("correction erased or superseded a committed action: %+v", loaded)
	}
}

func TestCommitAndIntentCorrectionSerializeOnTurnRow(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var commitErr, advanceErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, commitErr = h.store.CommitProposal(ctx, h.tenantID, proposal.ID, proposalCommitConditions())
	}()
	go func() {
		defer wg.Done()
		<-start
		advanceErr = h.store.AdvanceTurnIntent(ctx, h.tenantID, h.runID, h.turnID, 11, 12, true)
	}()
	close(start)
	wg.Wait()

	if advanceErr != nil {
		t.Fatalf("Turn revision must advance exactly once: %v", advanceErr)
	}
	loaded, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	switch loaded.State {
	case executionsafety.ProposalSuperseded:
		if commitErr == nil || loaded.GuardSubmissionKey != "" {
			t.Fatalf("Commit succeeded after correction won the Turn lock: commitErr=%v proposal=%+v", commitErr, loaded)
		}
	case executionsafety.ProposalCommitAuthorized:
		if commitErr != nil || loaded.GuardSubmissionKey != proposalCommitConditions().GuardSubmissionKey {
			t.Fatalf("Commit did not win before correction: commitErr=%v proposal=%+v", commitErr, loaded)
		}
	default:
		t.Fatalf("unexpected state after serialized race: %+v (commit error=%v)", loaded, commitErr)
	}
}

func TestProposalCommitOutboxFailureRollsBackCommitBoundary(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true); err != nil {
		t.Fatal(err)
	}
	_, err := h.pool.Exec(ctx, `
		CREATE FUNCTION reject_proposal_commit_event() RETURNS trigger
		LANGUAGE plpgsql AS 'BEGIN
			IF NEW.event_type = ''ProposalCommitAuthorized'' THEN
				RAISE EXCEPTION ''forced proposal outbox failure'';
			END IF;
			RETURN NEW;
		END;'
	`)
	if err != nil {
		t.Fatalf("create fail trigger: %v", err)
	}
	_, err = h.pool.Exec(ctx, `
		CREATE TRIGGER reject_proposal_commit_event
		BEFORE INSERT ON runtime_execution_outbox
		FOR EACH ROW EXECUTE FUNCTION reject_proposal_commit_event()
	`)
	if err != nil {
		t.Fatalf("install fail trigger: %v", err)
	}
	if _, err := h.store.CommitProposal(ctx, h.tenantID, proposal.ID, proposalCommitConditions()); err == nil {
		t.Fatal("CommitProposal succeeded despite forced event failure")
	}
	loaded, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != executionsafety.ProposalPrepared || loaded.GuardSubmissionKey != "" {
		t.Fatalf("failed Commit left partial authorization: %+v", loaded)
	}
}

func TestAdvanceTurnOutboxFailureRollsBackRevisionAndSupersession(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true); err != nil {
		t.Fatal(err)
	}
	_, err := h.pool.Exec(ctx, `
		CREATE FUNCTION reject_turn_revision_event() RETURNS trigger
		LANGUAGE plpgsql AS 'BEGIN
			IF NEW.event_type = ''TurnIntentRevised'' THEN
				RAISE EXCEPTION ''forced Turn outbox failure'';
			END IF;
			RETURN NEW;
		END;'
	`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.pool.Exec(ctx, `
		CREATE TRIGGER reject_turn_revision_event
		BEFORE INSERT ON runtime_execution_outbox
		FOR EACH ROW EXECUTE FUNCTION reject_turn_revision_event()
	`)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.AdvanceTurnIntent(ctx, h.tenantID, h.runID, h.turnID, 11, 12, true); err == nil {
		t.Fatal("AdvanceTurnIntent succeeded despite failed event insert")
	}
	var revision int64
	if err := h.pool.QueryRow(ctx, `
		SELECT intent_revision FROM runtime_turn_intents
		WHERE tenant_id=$1 AND run_id=$2::uuid AND turn_id=$3
	`, h.tenantID, h.runID, h.turnID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	loaded, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revision != 11 || loaded.State != executionsafety.ProposalPrepared {
		t.Fatalf("failed Turn update left partial state: revision=%d proposal=%+v", revision, loaded)
	}
}

func TestCreateProposalReplayReturnsSupersededCanonicalProposal(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()

	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	if _, err := h.store.PrepareProposal(ctx, h.tenantID, proposal.ID, true); err != nil {
		t.Fatalf("PrepareProposal: %v", err)
	}
	if err := h.store.AdvanceTurnIntent(ctx, h.tenantID, h.runID, h.turnID, 11, 12, true); err != nil {
		t.Fatalf("AdvanceTurnIntent: %v", err)
	}

	// A create ACK may have been lost and retried after a later correction.
	// The replay must resolve the original identity, not fail on the now-stale
	// revision and not recreate or reset the Proposal.
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatalf("idempotent replay of superseded Proposal: %v", err)
	}
	loaded, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != executionsafety.ProposalSuperseded || loaded.Version != 3 {
		t.Fatalf("Proposal replay rewrote canonical lifecycle: %+v", loaded)
	}
	var proposalEvents int
	if err := h.pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_execution_outbox
		WHERE tenant_id=$1 AND proposal_id=$2
	`, h.tenantID, proposal.ID).Scan(&proposalEvents); err != nil {
		t.Fatal(err)
	}
	if proposalEvents != 3 {
		t.Fatalf("idempotent create replay appended a duplicate event: count=%d want=3", proposalEvents)
	}
}

func TestCreateProposalSameIdentityWithChangedDigestConflicts(t *testing.T) {
	h, proposal := newProposalStore(t, 11)
	ctx := context.Background()
	if err := h.store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}

	changed, err := executionsafety.NewProposal(executionsafety.ProposalInput{
		ID: proposal.ID, TenantID: proposal.TenantID, RunID: proposal.RunID, TurnID: proposal.TurnID,
		IntentRevision: proposal.IntentRevision, ArgumentsDigest: proposal.ArgumentsDigest,
		ActionRequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ToolPolicy: proposal.ToolPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.CreateProposal(ctx, changed); err == nil {
		t.Fatal("same Proposal identity accepted a changed ActionRequest digest")
	}
	loaded, err := h.store.GetProposal(ctx, h.tenantID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActionRequestDigest != proposal.ActionRequestDigest {
		t.Fatalf("changed digest replaced canonical Proposal: %+v", loaded)
	}
}
