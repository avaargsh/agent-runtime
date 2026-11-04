package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/executionsafety"
)

const (
	executionTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	executionTenant     = "tenant-execution"
	executionRun        = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	executionTurn       = "turn-alice-access"
)

func executionPolicy(role string) executionsafety.ToolPolicy {
	return executionsafety.ToolPolicy{
		CapabilityID:              "iam.role.set." + role,
		CapabilityVersion:         "v1",
		PolicyDigest:              executionTestDigest,
		EffectClass:               executionsafety.EffectReversibleWrite,
		Idempotent:                true,
		RequiresConfirmation:      true,
		RequiresApproval:          true,
		ApprovalPolicyRef:         "policy://iam-role-change/v1",
		CompensationCapabilityRef: "iam.role.revoke",
	}
}

func executionProposal(t *testing.T, id string, revision int64, role string) executionsafety.Proposal {
	t.Helper()
	requestDigest := strings.Replace(executionTestDigest, "aaaa", "baaa", 1)
	if role == "administrator" {
		requestDigest = strings.Replace(executionTestDigest, "aaaa", "caaa", 1)
	}
	proposal, err := executionsafety.NewProposal(executionsafety.ProposalInput{
		ID:                  id,
		TenantID:            executionTenant,
		RunID:               executionRun,
		TurnID:              executionTurn,
		IntentRevision:      revision,
		ArgumentsDigest:     executionTestDigest,
		ActionRequestDigest: requestDigest,
		ToolPolicy:          executionPolicy(role),
	})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func executionCommitConditions(proposal executionsafety.Proposal, key string) executionsafety.CommitConditions {
	return executionsafety.CommitConditions{
		IntentComplete:          true,
		CapabilityAllowed:       true,
		RuntimeAdmissionAllowed: true,
		Confirmation: &executionsafety.UserConfirmation{
			ActorID:             "user-alice",
			EvidenceRef:         "evidence://confirmation/alice/read-only",
			ActionRequestDigest: proposal.ActionRequestDigest,
		},
		GuardSubmissionKey:  key,
		ActionRequestDigest: proposal.ActionRequestDigest,
	}
}

func TestProposalPersistenceAliceCorrectionCommitAndEvidence(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()

	adminIntent := executionsafety.IntentRevision{
		TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
		Revision: 11, Digest: executionTestDigest, Complete: true,
	}
	if err := store.AdvanceIntentRevision(ctx, adminIntent); err != nil {
		t.Fatalf("persist initial intent: %v", err)
	}

	admin := executionProposal(t, "proposal-admin", 11, "administrator")
	if _, err := store.CreateProposal(ctx, admin); err != nil {
		t.Fatalf("persist admin proposal: %v", err)
	}
	preparedAdmin, err := store.PrepareProposal(ctx, executionTenant, admin.ID, admin.Version, true)
	if err != nil {
		t.Fatalf("prepare admin proposal: %v", err)
	}
	if preparedAdmin.State != executionsafety.ProposalPrepared {
		t.Fatalf("admin proposal state = %s, want PREPARED", preparedAdmin.State)
	}

	correctedIntent := executionsafety.IntentRevision{
		TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
		Revision: 12, Digest: strings.Replace(executionTestDigest, "aaaa", "daaa", 1), Complete: false,
	}
	if err := store.AdvanceIntentRevision(ctx, correctedIntent); err != nil {
		t.Fatalf("advance corrected intent: %v", err)
	}
	supersededAdmin, err := store.GetProposal(ctx, executionTenant, admin.ID)
	if err != nil {
		t.Fatalf("load superseded proposal: %v", err)
	}
	if supersededAdmin.State != executionsafety.ProposalSuperseded || supersededAdmin.GuardSubmissionKey != "" {
		t.Fatalf("stale admin proposal was not safely superseded: %+v", supersededAdmin)
	}

	readOnly := executionProposal(t, "proposal-readonly", 12, "read_only")
	if _, err := store.CreateProposal(ctx, readOnly); err != nil {
		t.Fatalf("persist corrected proposal: %v", err)
	}
	preparedReadOnly, err := store.PrepareProposal(ctx, executionTenant, readOnly.ID, readOnly.Version, true)
	if err != nil {
		t.Fatalf("prepare corrected proposal: %v", err)
	}

	conditions := executionCommitConditions(preparedReadOnly, "guard-key-alice-readonly")
	if _, err := store.CommitProposal(ctx, executionTenant, readOnly.ID, preparedReadOnly.Version, conditions); !errors.Is(err, executionsafety.ErrCommitNotAuthorized) {
		t.Fatalf("incomplete corrected intent must block Commit, got %v", err)
	}
	if err := store.AdvanceIntentRevision(ctx, executionsafety.IntentRevision{
		TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
		Revision: 12, Digest: correctedIntent.Digest, Complete: true,
	}); err != nil {
		t.Fatalf("mark corrected intent complete: %v", err)
	}

	committed, err := store.CommitProposal(ctx, executionTenant, readOnly.ID, preparedReadOnly.Version, conditions)
	if err != nil {
		t.Fatalf("commit read-only proposal: %v", err)
	}
	if committed.State != executionsafety.ProposalCommitAuthorized ||
		committed.GuardSubmissionKey != "guard-key-alice-readonly" ||
		committed.ConfirmationRef == "" {
		t.Fatalf("unexpected durable commit: %+v", committed)
	}

	// A lost Runtime ACK replays the same commit identity, not a new key.
	replayed, err := store.CommitProposal(ctx, executionTenant, readOnly.ID, preparedReadOnly.Version, conditions)
	if err != nil {
		t.Fatalf("idempotent commit replay: %v", err)
	}
	if replayed.Version != committed.Version || replayed.GuardSubmissionKey != committed.GuardSubmissionKey {
		t.Fatalf("commit replay changed durable identity: first=%+v replay=%+v", committed, replayed)
	}

	link := executionsafety.GuardOperationLink{
		TenantID: executionTenant, ProposalID: readOnly.ID,
		GuardSubmissionKey:  committed.GuardSubmissionKey,
		ActionRequestDigest: committed.ActionRequestDigest,
		OperationID:         "guard-operation-alice-readonly",
	}
	submitted, err := store.LinkGuardOperation(ctx, executionTenant, readOnly.ID, committed.Version, link)
	if err != nil {
		t.Fatalf("link Guard operation: %v", err)
	}
	if submitted.State != executionsafety.ProposalSubmittedToGuard ||
		submitted.GuardOperationID != link.OperationID {
		t.Fatalf("unexpected Guard operation link: %+v", submitted)
	}

	persisted, err := store.GetProposal(ctx, executionTenant, readOnly.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != submitted.State || persisted.Version != submitted.Version {
		t.Fatalf("fresh read differs from committed state: got %+v want %+v", persisted, submitted)
	}

	evidence, err := store.ListProposalEvidence(ctx, executionTenant, readOnly.ID)
	if err != nil {
		t.Fatalf("list proposal evidence: %v", err)
	}
	events := make(map[string]bool)
	for _, event := range evidence {
		events[event.EventType] = true
	}
	for _, eventType := range []string{
		"ToolProposalCreated", "ToolProposalPrepared",
		"ProposalCommitAuthorized", "GuardOperationLinked",
	} {
		if !events[eventType] {
			t.Errorf("missing persisted Evidence event %q", eventType)
		}
	}

	// The old admin proposal was superseded; its evidence remains append-only.
	adminEvidence, err := store.ListProposalEvidence(ctx, executionTenant, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	foundSuperseded := false
	for _, event := range adminEvidence {
		foundSuperseded = foundSuperseded || event.EventType == "ToolProposalSuperseded"
	}
	if !foundSuperseded {
		t.Fatal("supersession Evidence was not persisted")
	}

	var guardSubmitEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM execution_evidence WHERE tenant_id=$1 AND proposal_id=$2 AND event_type='ProposalCommitAuthorized'`, executionTenant, readOnly.ID).Scan(&guardSubmitEvents); err != nil {
		t.Fatal(err)
	}
	if guardSubmitEvents != 1 {
		t.Fatalf("commit Evidence event count = %d, want 1", guardSubmitEvents)
	}
}

func TestProposalCommitCannotWinAfterIntentCorrection(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()

	if err := store.AdvanceIntentRevision(ctx, executionsafety.IntentRevision{
		TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
		Revision: 20, Digest: executionTestDigest, Complete: true,
	}); err != nil {
		t.Fatal(err)
	}
	proposal := executionProposal(t, "proposal-stale-race", 20, "administrator")
	if _, err := store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	prepared, err := store.PrepareProposal(ctx, executionTenant, proposal.ID, proposal.Version, true)
	if err != nil {
		t.Fatal(err)
	}

	newDigest := strings.Replace(executionTestDigest, "aaaa", "eaaa", 1)
	if err := store.AdvanceIntentRevision(ctx, executionsafety.IntentRevision{
		TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
		Revision: 21, Digest: newDigest, Complete: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = store.CommitProposal(ctx, executionTenant, proposal.ID, prepared.Version, executionCommitConditions(prepared, "guard-key-stale"))
	if !errors.Is(err, executionsafety.ErrInvalidTransition) &&
		!errors.Is(err, executionsafety.ErrStaleIntent) &&
		!errors.Is(err, executionsafety.ErrVersionConflict) {
		t.Fatalf("stale proposal crossed Commit after correction: %v", err)
	}
	after, err := store.GetProposal(ctx, executionTenant, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != executionsafety.ProposalSuperseded || after.GuardSubmissionKey != "" {
		t.Fatalf("stale proposal was not kept out of Guard: %+v", after)
	}
}

func TestProposalCommitEnforcesUniqueGuardSubmissionKey(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	intent := executionsafety.IntentRevision{
		TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
		Revision: 1, Digest: executionTestDigest, Complete: true,
	}
	if err := store.AdvanceIntentRevision(ctx, intent); err != nil {
		t.Fatal(err)
	}

	first := executionProposal(t, "proposal-key-one", 1, "read_only")
	second := executionProposal(t, "proposal-key-two", 1, "administrator")
	for _, proposal := range []executionsafety.Proposal{first, second} {
		if _, err := store.CreateProposal(ctx, proposal); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PrepareProposal(ctx, executionTenant, proposal.ID, proposal.Version, true); err != nil {
			t.Fatal(err)
		}
	}
	firstPrepared, err := store.GetProposal(ctx, executionTenant, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	secondPrepared, err := store.GetProposal(ctx, executionTenant, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitProposal(ctx, executionTenant, first.ID, firstPrepared.Version,
		executionCommitConditions(firstPrepared, "guard-key-unique")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitProposal(ctx, executionTenant, second.ID, secondPrepared.Version,
		executionCommitConditions(secondPrepared, "guard-key-unique")); !errors.Is(err, executionsafety.ErrIdempotencyKeyConflict) {
		t.Fatalf("second proposal reused Guard key, expected conflict; got %v", err)
	}
}

func TestGuardOperationLinkRejectsCrossProposalOrDigestBinding(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	proposal := executionProposal(t, "proposal-guard-binding", 1, "read_only")
	if err := store.AdvanceIntentRevision(ctx, executionsafety.IntentRevision{
		TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
		Revision: 1, Digest: executionTestDigest, Complete: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	prepared, err := store.PrepareProposal(ctx, executionTenant, proposal.ID, proposal.Version, true)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := store.CommitProposal(ctx, executionTenant, proposal.ID, prepared.Version,
		executionCommitConditions(prepared, "guard-key-bind"))
	if err != nil {
		t.Fatal(err)
	}

	mismatch := executionsafety.GuardOperationLink{
		TenantID: executionTenant, ProposalID: proposal.ID,
		GuardSubmissionKey:  committed.GuardSubmissionKey,
		ActionRequestDigest: strings.Replace(committed.ActionRequestDigest, "b", "c", 1),
		OperationID:         "guard-operation-wrong-digest",
	}
	if _, err := store.LinkGuardOperation(ctx, executionTenant, proposal.ID, committed.Version, mismatch); !errors.Is(err, executionsafety.ErrIdempotencyKeyConflict) {
		t.Fatalf("mismatched Guard response advanced proposal: %v", err)
	}
}

func TestConcurrentIntentAdvanceAndProposalCommitHasOneSafeOutcome(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	if err := store.AdvanceIntentRevision(ctx, executionsafety.IntentRevision{
		TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
		Revision: 31, Digest: executionTestDigest, Complete: true,
	}); err != nil {
		t.Fatal(err)
	}
	proposal := executionProposal(t, "proposal-correction-race", 31, "administrator")
	if _, err := store.CreateProposal(ctx, proposal); err != nil {
		t.Fatal(err)
	}
	prepared, err := store.PrepareProposal(ctx, executionTenant, proposal.ID, proposal.Version, true)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := store.CommitProposal(ctx, executionTenant, proposal.ID, prepared.Version,
			executionCommitConditions(prepared, "guard-key-race"))
		errs <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		errs <- store.AdvanceIntentRevision(ctx, executionsafety.IntentRevision{
			TenantID: executionTenant, RunID: executionRun, TurnID: executionTurn,
			Revision: 32, Digest: strings.Replace(executionTestDigest, "aaaa", "faaa", 1), Complete: true,
		})
	}()
	close(start)
	wg.Wait()
	close(errs)
	var commitErr, correctionErr error
	for err := range errs {
		if err == nil {
			// The nil result is either a successful commit or correction. The
			// final persisted state below determines which outcome won.
			continue
		}
		if errors.Is(err, executionsafety.ErrCommitNotAuthorized) ||
			errors.Is(err, executionsafety.ErrStaleIntent) ||
			errors.Is(err, executionsafety.ErrInvalidTransition) {
			commitErr = err
		} else {
			correctionErr = err
		}
	}
	if correctionErr != nil {
		t.Fatalf("intent correction failed: %v", correctionErr)
	}
	current, err := store.GetProposal(ctx, executionTenant, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	switch current.State {
	case executionsafety.ProposalSuperseded:
		if commitErr == nil || current.GuardSubmissionKey != "" {
			t.Fatalf("correction won but stale commit was not rejected: err=%v proposal=%+v", commitErr, current)
		}
	case executionsafety.ProposalCommitAuthorized, executionsafety.ProposalSubmittedToGuard:
		if current.GuardSubmissionKey != "guard-key-race" {
			t.Fatalf("commit won without stable submission key: %+v", current)
		}
	default:
		t.Fatalf("unsafe outcome from concurrent correction/commit: %+v (revision advance / commit error=%v)", current, commitErr)
	}
}
