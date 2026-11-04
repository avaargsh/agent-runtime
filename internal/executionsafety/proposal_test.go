package executionsafety

import (
	"errors"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testPolicy() ToolPolicy {
	return ToolPolicy{
		CapabilityID:              "iam.role.update",
		CapabilityVersion:         "v1",
		PolicyDigest:              testDigest,
		EffectClass:               EffectReversibleWrite,
		Idempotent:                true,
		RequiresConfirmation:      true,
		RequiresApproval:          true,
		ApprovalPolicyRef:         "policy://iam-admin-change/v3",
		CompensationCapabilityRef: "iam.role.revoke",
	}
}

func testConfirmation(digest string) *UserConfirmation {
	return &UserConfirmation{
		ActorID:             "user-1",
		EvidenceRef:         "evidence://confirmations/confirm-1",
		ActionRequestDigest: digest,
	}
}

func testProposal(t *testing.T) Proposal {
	t.Helper()
	proposal, err := NewProposal(ProposalInput{
		ID:                  "proposal-1",
		TenantID:            "tenant-1",
		RunID:               "run-1",
		TurnID:              "turn-1",
		IntentRevision:      11,
		ArgumentsDigest:     testDigest,
		ActionRequestDigest: testDigest,
		ToolPolicy:          testPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func TestToolPolicyRequiresCompensationForReversibleWrite(t *testing.T) {
	policy := testPolicy()
	policy.CompensationCapabilityRef = ""
	if err := policy.Validate(); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("expected invalid policy, got %v", err)
	}
}

func TestToolPolicyRequiresApprovalPolicyReference(t *testing.T) {
	policy := testPolicy()
	policy.ApprovalPolicyRef = ""
	if err := policy.Validate(); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("expected missing approval policy to fail, got %v", err)
	}
}

func TestPrepareRejectsStaleIntentRevision(t *testing.T) {
	_, err := testProposal(t).Prepare(12, true)
	if !errors.Is(err, ErrStaleIntent) {
		t.Fatalf("expected stale intent, got %v", err)
	}
}

func TestPrepareRejectsCapabilityOutsideAllowList(t *testing.T) {
	_, err := testProposal(t).Prepare(11, false)
	if !errors.Is(err, ErrCommitNotAuthorized) {
		t.Fatalf("expected capability denial, got %v", err)
	}
}

func TestPrepareMovesProposalToPrepared(t *testing.T) {
	prepared, err := testProposal(t).Prepare(11, true)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != ProposalPrepared || prepared.Version != 2 {
		t.Fatalf("unexpected prepared proposal: %+v", prepared)
	}
}

func TestSupersedeIsAllowedOnlyBeforeCommitBoundary(t *testing.T) {
	prepared, err := testProposal(t).Prepare(11, true)
	if err != nil {
		t.Fatal(err)
	}
	superseded, err := prepared.Supersede(12)
	if err != nil {
		t.Fatal(err)
	}
	if superseded.State != ProposalSuperseded || superseded.Version != 3 {
		t.Fatalf("unexpected superseded proposal: %+v", superseded)
	}

	committed, err := prepared.AuthorizeCommit(CommitConditions{
		CurrentIntentRevision:   11,
		IntentComplete:          true,
		CapabilityAllowed:       true,
		RuntimeAdmissionAllowed: true,
		Confirmation:            testConfirmation(testDigest),
		GuardSubmissionKey:      "guard-key-1",
		ActionRequestDigest:     testDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := committed.Supersede(12); !errors.Is(err, ErrCommitBoundaryCrossed) {
		t.Fatalf("expected commit boundary to prevent local supersede, got %v", err)
	}
}

func TestCommitRequiresAllRuntimeAdmissionConditions(t *testing.T) {
	prepared, err := testProposal(t).Prepare(11, true)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		conditions CommitConditions
	}{
		{
			name:       "incomplete intent",
			conditions: CommitConditions{CurrentIntentRevision: 11, CapabilityAllowed: true, RuntimeAdmissionAllowed: true, Confirmation: testConfirmation(testDigest), GuardSubmissionKey: "guard-key-1"},
		},
		{
			name:       "stale revision",
			conditions: CommitConditions{CurrentIntentRevision: 12, IntentComplete: true, CapabilityAllowed: true, RuntimeAdmissionAllowed: true, Confirmation: testConfirmation(testDigest), GuardSubmissionKey: "guard-key-1"},
		},
		{
			name:       "capability revoked",
			conditions: CommitConditions{CurrentIntentRevision: 11, IntentComplete: true, CapabilityAllowed: false, RuntimeAdmissionAllowed: true, Confirmation: testConfirmation(testDigest), GuardSubmissionKey: "guard-key-1"},
		},
		{
			name:       "runtime admission denied",
			conditions: CommitConditions{CurrentIntentRevision: 11, IntentComplete: true, CapabilityAllowed: true, RuntimeAdmissionAllowed: false, Confirmation: testConfirmation(testDigest), GuardSubmissionKey: "guard-key-1"},
		},
		{
			name:       "confirmation missing",
			conditions: CommitConditions{CurrentIntentRevision: 11, IntentComplete: true, CapabilityAllowed: true, RuntimeAdmissionAllowed: true, UserConfirmed: false, GuardSubmissionKey: "guard-key-1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepared.AuthorizeCommit(tc.conditions)
			if !errors.Is(err, ErrCommitNotAuthorized) && !errors.Is(err, ErrStaleIntent) {
				t.Fatalf("expected admission denial/stale intent, got %v", err)
			}
		})
	}
}

func TestCommitReplayRequiresSameGuardSubmissionKey(t *testing.T) {
	prepared, err := testProposal(t).Prepare(11, true)
	if err != nil {
		t.Fatal(err)
	}
	conditions := CommitConditions{
		CurrentIntentRevision:   11,
		IntentComplete:          true,
		CapabilityAllowed:       true,
		RuntimeAdmissionAllowed: true,
		Confirmation:            testConfirmation(testDigest),
		GuardSubmissionKey:      "guard-key-1",
		ActionRequestDigest:     testDigest,
	}
	first, err := prepared.AuthorizeCommit(conditions)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := first.AuthorizeCommit(conditions)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Version != first.Version || replay.GuardSubmissionKey != first.GuardSubmissionKey {
		t.Fatalf("idempotent replay changed commit identity: first=%+v replay=%+v", first, replay)
	}
	conditions.GuardSubmissionKey = "guard-key-2"
	if _, err := first.AuthorizeCommit(conditions); !errors.Is(err, ErrIdempotencyKeyConflict) {
		t.Fatalf("expected changed key conflict, got %v", err)
	}
}

func TestMarkSubmittedToGuardRequiresReturnedOperationID(t *testing.T) {
	prepared, err := testProposal(t).Prepare(11, true)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := prepared.AuthorizeCommit(CommitConditions{
		CurrentIntentRevision:   11, IntentComplete: true, CapabilityAllowed: true,
		RuntimeAdmissionAllowed: true, Confirmation: testConfirmation(testDigest), GuardSubmissionKey: "guard-key-1",
		ActionRequestDigest:     testDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	link := GuardOperationLink{
		TenantID:            committed.TenantID,
		ProposalID:          committed.ID,
		GuardSubmissionKey:  committed.GuardSubmissionKey,
		ActionRequestDigest: committed.ActionRequestDigest,
	}
	if _, err := committed.MarkSubmittedToGuard(link); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("expected empty Guard operation id to fail, got %v", err)
	}
	link.OperationID = "guard-operation-1"
	submitted, err := committed.MarkSubmittedToGuard(link)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := submitted.MarkSubmittedToGuard(link)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Version != submitted.Version || replay.GuardOperationID != "guard-operation-1" {
		t.Fatalf("unexpected Guard submission replay: %+v", replay)
	}
	link.OperationID = "guard-operation-2"
	if _, err := submitted.MarkSubmittedToGuard(link); !errors.Is(err, ErrIdempotencyKeyConflict) {
		t.Fatalf("expected changed operation conflict, got %v", err)
	}
	link.OperationID = "guard-operation-1"
	link.ActionRequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := submitted.MarkSubmittedToGuard(link); !errors.Is(err, ErrIdempotencyKeyConflict) {
		t.Fatalf("expected mismatched response correlation to fail, got %v", err)
	}
}

func TestCommitRejectsConfirmationForDifferentActionRequest(t *testing.T) {
	prepared, err := testProposal(t).Prepare(11, true)
	if err != nil {
		t.Fatal(err)
	}
	conditions := CommitConditions{
		CurrentIntentRevision:   11,
		IntentComplete:          true,
		CapabilityAllowed:       true,
		RuntimeAdmissionAllowed: true,
		Confirmation:            testConfirmation("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		GuardSubmissionKey:      "guard-key-1",
		ActionRequestDigest:     testDigest,
	}
	if _, err := prepared.AuthorizeCommit(conditions); !errors.Is(err, ErrCommitNotAuthorized) {
		t.Fatalf("expected confirmation digest mismatch to deny commit, got %v", err)
	}
}

func TestIrreversibleWriteRequiresConfirmationOrApproval(t *testing.T) {
	policy := testPolicy()
	policy.EffectClass = EffectIrreversibleWrite
	policy.RequiresConfirmation = false
	policy.RequiresApproval = false
	policy.ApprovalPolicyRef = ""
	if err := policy.Validate(); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("expected unguarded irreversible write to fail, got %v", err)
	}
	policy.RequiresApproval = true
	policy.ApprovalPolicyRef = "policy://payments/critical/v1"
	if err := policy.Validate(); err != nil {
		t.Fatalf("expected approval-gated irreversible write to pass, got %v", err)
	}
}

func TestCommitReplayRequiresSameConfirmationEvidence(t *testing.T) {
	prepared, err := testProposal(t).Prepare(11, true)
	if err != nil {
		t.Fatal(err)
	}
	conditions := CommitConditions{
		CurrentIntentRevision:   11,
		IntentComplete:          true,
		CapabilityAllowed:       true,
		RuntimeAdmissionAllowed: true,
		Confirmation:            testConfirmation(testDigest),
		GuardSubmissionKey:      "guard-key-1",
		ActionRequestDigest:     testDigest,
	}
	committed, err := prepared.AuthorizeCommit(conditions)
	if err != nil {
		t.Fatal(err)
	}
	conditions.Confirmation.EvidenceRef = "evidence://confirmations/another-action"
	if _, err := committed.AuthorizeCommit(conditions); !errors.Is(err, ErrIdempotencyKeyConflict) {
		t.Fatalf("expected changed confirmation evidence to conflict, got %v", err)
	}
}
