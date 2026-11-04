package executionsafety

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

type fakeGuardStatus string

const (
	fakeGuardWaitingApproval fakeGuardStatus = "WAITING_APPROVAL"
	fakeGuardAuthorized      fakeGuardStatus = "AUTHORIZED"
	fakeGuardSucceeded       fakeGuardStatus = "SUCCEEDED"
)

type fakeGuardOperation struct {
	id            string
	submissionKey string
	requestDigest string
	proposalID    string
	desiredRole   string
	status        fakeGuardStatus
	approvalRef   string
	receiptRef    string
}

type fakeGuard struct {
	operations        map[string]*fakeGuardOperation
	submissionCalls   int
	createdOperations int
	executions        int
	effectiveRoles    map[string]string
	evidence          []string
}

func newFakeGuard() *fakeGuard {
	return &fakeGuard{
		operations:     make(map[string]*fakeGuardOperation),
		effectiveRoles: make(map[string]string),
	}
}

// Ensure models Guard's idempotent submission API: Guard creates operation IDs;
// the caller supplies one stable key and immutable request digest.
func (g *fakeGuard) Ensure(proposal Proposal, desiredRole string) (*fakeGuardOperation, error) {
	g.submissionCalls++
	if proposal.State != ProposalCommitAuthorized && proposal.State != ProposalSubmittedToGuard {
		return nil, fmt.Errorf("proposal has not crossed Runtime Commit Boundary")
	}
	if proposal.GuardSubmissionKey == "" {
		return nil, fmt.Errorf("missing persisted Guard submission key")
	}
	requestDigest := proposal.ActionRequestDigest
	if prior, ok := g.operations[proposal.GuardSubmissionKey]; ok {
		if prior.requestDigest != requestDigest {
			return nil, errors.New("IDEMPOTENCY_KEY_REUSED")
		}
		return prior, nil
	}

	op := &fakeGuardOperation{
		id:            "guard-operation-" + proposal.GuardSubmissionKey,
		submissionKey: proposal.GuardSubmissionKey,
		requestDigest: requestDigest,
		proposalID:    proposal.ID,
		desiredRole:   desiredRole,
		status:        fakeGuardWaitingApproval,
	}
	g.operations[proposal.GuardSubmissionKey] = op
	g.createdOperations++
	g.evidence = append(g.evidence, "guard-operation:"+op.id)
	return op, nil
}

func (g *fakeGuard) Approve(operationID, approvalRef string) error {
	for _, op := range g.operations {
		if op.id != operationID {
			continue
		}
		if op.status != fakeGuardWaitingApproval || approvalRef == "" {
			return errors.New("approval is not valid for this operation")
		}
		op.status = fakeGuardAuthorized
		op.approvalRef = approvalRef
		g.evidence = append(g.evidence, "approval:"+approvalRef)
		return nil
	}
	return errors.New("Guard operation not found")
}

// Execute represents a trusted Guard executor, not a Runtime provider call.
// It is callable only after Guard has authorized the operation.
func (g *fakeGuard) Execute(operationID, employee, trustedReceiptRef string) (string, error) {
	for _, op := range g.operations {
		if op.id != operationID {
			continue
		}
		if op.receiptRef != "" {
			return op.receiptRef, nil
		}
		if op.status != fakeGuardAuthorized || trustedReceiptRef == "" {
			return "", errors.New("Guard authorization / trusted receipt missing")
		}
		g.effectiveRoles[employee] = op.desiredRole
		op.status = fakeGuardSucceeded
		op.receiptRef = trustedReceiptRef
		g.executions++
		g.evidence = append(g.evidence, "receipt:"+trustedReceiptRef)
		g.evidence = append(g.evidence, "observation:"+employee+":"+op.desiredRole)
		return op.receiptRef, nil
	}
	return "", errors.New("Guard operation not found")
}

func newPermissionProposal(t *testing.T, id string, revision int64, desiredRole string) Proposal {
	t.Helper()
	policy := testPolicy()
	policy.CapabilityID = "iam.role.set." + desiredRole
	proposal, err := NewProposal(ProposalInput{
		ID:                  id,
		TenantID:            "tenant-acme",
		RunID:               "run-permissions",
		TurnID:              "turn-employee-access",
		IntentRevision:      revision,
		ArgumentsDigest:     testDigest,
		ActionRequestDigest: permissionRequestDigest(desiredRole),
		ToolPolicy:          policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func TestAlicePermissionCorrectionGoldenPath(t *testing.T) {
	guard := newFakeGuard()
	evidence := make([]string, 0, 8)

	// Turn revision 11: user asks for administrator access.
	adminProposal := newPermissionProposal(t, "proposal-admin", 11, "administrator")
	adminProposal, err := adminProposal.Prepare(11, true)
	if err != nil {
		t.Fatal(err)
	}

	// User corrects the intent before Commit: revision 12 requests read-only.
	evidence = append(evidence, "proposal-created:"+adminProposal.ID)
	adminProposal, err = adminProposal.Supersede(12)
	if err != nil {
		t.Fatal(err)
	}
	evidence = append(evidence, "proposal-superseded:"+adminProposal.ID)
	if adminProposal.State != ProposalSuperseded {
		t.Fatalf("old admin proposal was not superseded: %+v", adminProposal)
	}
	if guard.createdOperations != 0 {
		t.Fatal("superseded administrator proposal reached Guard")
	}

	// New proposal is bound to the corrected revision and is the only one committed.
	readOnlyProposal := newPermissionProposal(t, "proposal-readonly", 12, "read_only")
	readOnlyProposal, err = readOnlyProposal.Prepare(12, true)
	if err != nil {
		t.Fatal(err)
	}
	readOnlyProposal, err = readOnlyProposal.AuthorizeCommit(CommitConditions{
		CurrentIntentRevision:   12,
		IntentComplete:          true,
		CapabilityAllowed:       true,
		RuntimeAdmissionAllowed: true,
		Confirmation:            permissionConfirmation("read_only"),
		GuardSubmissionKey:      "gsk-alice-readonly-1",
		ActionRequestDigest:     permissionRequestDigest("read_only"),
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence = append(evidence, "commit-authorized:"+readOnlyProposal.ID)
	evidence = append(evidence, "user-confirmation:"+readOnlyProposal.ConfirmationRef)

	// First submission creates a Guard-owned operation; replay returns the same one.
	op, err := guard.Ensure(readOnlyProposal, "read_only")
	if err != nil {
		t.Fatal(err)
	}
	replayOp, err := guard.Ensure(readOnlyProposal, "read_only")
	if err != nil {
		t.Fatal(err)
	}
	if op.id != replayOp.id || guard.createdOperations != 1 {
		t.Fatalf("same key/digest did not resolve one operation: first=%+v replay=%+v created=%d", op, replayOp, guard.createdOperations)
	}
	readOnlyProposal, err = readOnlyProposal.MarkSubmittedToGuard(GuardOperationLink{
		TenantID:            readOnlyProposal.TenantID,
		ProposalID:          readOnlyProposal.ID,
		GuardSubmissionKey:  op.submissionKey,
		ActionRequestDigest: op.requestDigest,
		OperationID:         op.id,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence = append(evidence, "guard-operation-linked:"+readOnlyProposal.GuardOperationID)

	// No provider mutation is possible while Guard approval is pending.
	if _, err := guard.Execute(op.id, "alice", "receipt-before-approval"); err == nil {
		t.Fatal("trusted execution occurred before Guard approval")
	}
	if got := guard.effectiveRoles["alice"]; got != "" {
		t.Fatalf("unexpected role before approval: %q", got)
	}

	if err := guard.Approve(op.id, "approval-record-2026-11-04"); err != nil {
		t.Fatal(err)
	}
	receipt, err := guard.Execute(op.id, "alice", "trusted-receipt-001")
	if err != nil {
		t.Fatal(err)
	}
	// Replaying the same operation returns the same receipt and does not repeat the effect.
	replayedReceipt, err := guard.Execute(op.id, "alice", "trusted-receipt-001")
	if err != nil {
		t.Fatal(err)
	}
	if receipt != replayedReceipt || guard.executions != 1 {
		t.Fatalf("execution replay repeated the side effect: receipt=%q replay=%q executions=%d", receipt, replayedReceipt, guard.executions)
	}
	evidence = append(evidence, "receipt-linked:"+receipt)

	if got := guard.effectiveRoles["alice"]; got != "read_only" {
		t.Fatalf("expected Alice read_only, got %q", got)
	}
	if adminProposal.State != ProposalSuperseded {
		t.Fatalf("administrator proposal changed unexpectedly: %+v", adminProposal)
	}
	if readOnlyProposal.State != ProposalSubmittedToGuard || readOnlyProposal.IntentRevision != 12 {
		t.Fatalf("read-only proposal did not reach Guard from revision 12: %+v", readOnlyProposal)
	}
	if guard.createdOperations != 1 || guard.executions != 1 {
		t.Fatalf("unexpected Guard operation/effect counts: operations=%d executions=%d", guard.createdOperations, guard.executions)
	}

	for _, required := range []string{
		"proposal-superseded:proposal-admin",
		"commit-authorized:proposal-readonly",
		"user-confirmation:evidence://confirmations/alice/read_only",
		"guard-operation-linked:" + op.id,
		"approval:approval-record-2026-11-04",
		"receipt-linked:" + receipt,
		"receipt:" + receipt,
		"observation:alice:read_only",
	} {
		if !contains(evidence, required) && !contains(guard.evidence, required) {
			t.Errorf("missing Evidence entry %q", required)
		}
	}
}

func TestGuardSubmissionRejectsSameKeyWithChangedDigest(t *testing.T) {
	guard := newFakeGuard()
	proposal := newPermissionProposal(t, "proposal-readonly", 12, "read_only")
	prepared, err := proposal.Prepare(12, true)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := prepared.AuthorizeCommit(CommitConditions{
		CurrentIntentRevision:   12, IntentComplete: true, CapabilityAllowed: true,
		RuntimeAdmissionAllowed: true, GuardSubmissionKey: "gsk-one",
		ActionRequestDigest:     permissionRequestDigest("read_only"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Ensure(committed, "read_only"); err != nil {
		t.Fatal(err)
	}
	changedProposal := newPermissionProposal(t, "proposal-administrator", 12, "administrator")
	changedPrepared, err := changedProposal.Prepare(12, true)
	if err != nil {
		t.Fatal(err)
	}
	changedCommitted, err := changedPrepared.AuthorizeCommit(CommitConditions{
		CurrentIntentRevision:   12, IntentComplete: true, CapabilityAllowed: true,
		RuntimeAdmissionAllowed: true, GuardSubmissionKey: "gsk-one",
		ActionRequestDigest:     permissionRequestDigest("administrator"),
		Confirmation:            permissionConfirmation("administrator"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Ensure(changedCommitted, "administrator"); err == nil {
		t.Fatal("same Guard key accepted a changed ActionRequest digest")
	}
}

func permissionConfirmation(role string) *UserConfirmation {
	return &UserConfirmation{
		ActorID:             "user-alice",
		EvidenceRef:         "evidence://confirmations/alice/" + role,
		ActionRequestDigest: permissionRequestDigest(role),
	}
}

func permissionRequestDigest(role string) string {
	sum := sha256.Sum256([]byte("tenant=tenant-acme;subject=alice;role=" + role))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
