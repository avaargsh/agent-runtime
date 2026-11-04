package executionsafety

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidProposal        = errors.New("invalid proposal")
	ErrInvalidTransition      = errors.New("invalid proposal transition")
	ErrStaleIntent            = errors.New("proposal intent revision is stale")
	ErrCommitNotAuthorized    = errors.New("commit conditions are not satisfied")
	ErrCommitBoundaryCrossed  = errors.New("proposal has crossed the commit boundary")
	ErrIdempotencyKeyConflict = errors.New("guard submission key conflicts with prior commit")
)

type EffectClass string

const (
	EffectReadOnly          EffectClass = "READ_ONLY"
	EffectReversibleWrite   EffectClass = "REVERSIBLE_WRITE"
	EffectIrreversibleWrite EffectClass = "IRREVERSIBLE_WRITE"
)

// ToolPolicy is resolved from trusted AgentBundle/capability metadata.
// It must never be populated from plugin-controlled policy annotations.
type ToolPolicy struct {
	CapabilityID              string
	CapabilityVersion         string
	PolicyDigest              string
	EffectClass               EffectClass
	Idempotent                bool
	RequiresConfirmation      bool
	RequiresApproval          bool
	ApprovalPolicyRef         string
	CompensationCapabilityRef string
}

func (p ToolPolicy) Validate() error {
	for name, value := range map[string]string{
		"capabilityID":      p.CapabilityID,
		"capabilityVersion": p.CapabilityVersion,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !validDigest(p.PolicyDigest) {
		return fmt.Errorf("%w: policyDigest must be sha256 hex", ErrInvalidProposal)
	}

	switch p.EffectClass {
	case EffectReadOnly:
		if p.CompensationCapabilityRef != "" {
			return fmt.Errorf("%w: read-only capability cannot declare compensation", ErrInvalidProposal)
		}
	case EffectReversibleWrite:
		if err := validateIdentifier("compensationCapabilityRef", p.CompensationCapabilityRef); err != nil {
			return fmt.Errorf("%w: reversible write requires a compensation capability", ErrInvalidProposal)
		}
	case EffectIrreversibleWrite:
		// Irreversible effects are permitted only through their explicit trusted
		// policy; this model does not infer that a compensator exists.
	default:
		return fmt.Errorf("%w: unknown effect class %q", ErrInvalidProposal, p.EffectClass)
	}
	if p.RequiresApproval {
		if err := validateIdentifier("approvalPolicyRef", p.ApprovalPolicyRef); err != nil {
			return fmt.Errorf("%w: approval policy reference is required", ErrInvalidProposal)
		}
	}
	return nil
}

type ProposalState string

const (
	ProposalProposed         ProposalState = "PROPOSED"
	ProposalPrepared         ProposalState = "PREPARED"
	ProposalSuperseded       ProposalState = "SUPERSEDED"
	ProposalCancelled        ProposalState = "CANCELLED"
	ProposalCommitAuthorized ProposalState = "COMMIT_AUTHORIZED"
	ProposalSubmittedToGuard ProposalState = "SUBMITTED_TO_GUARD"
)

type ProposalInput struct {
	ID                  string
	TenantID            string
	RunID               string
	TurnID              string
	IntentRevision      int64
	ArgumentsDigest     string
	ActionRequestDigest string
	ToolPolicy          ToolPolicy
}

type Proposal struct {
	ID                  string
	TenantID            string
	RunID               string
	TurnID              string
	IntentRevision      int64
	ArgumentsDigest     string
	ActionRequestDigest string
	ToolPolicy          ToolPolicy
	State               ProposalState
	Version             int64
	GuardSubmissionKey  string
	GuardOperationID    string
}

func NewProposal(input ProposalInput) (Proposal, error) {
	for name, value := range map[string]string{
		"id":       input.ID,
		"tenantID": input.TenantID,
		"runID":    input.RunID,
		"turnID":   input.TurnID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return Proposal{}, err
		}
	}
	if input.IntentRevision < 1 {
		return Proposal{}, fmt.Errorf("%w: intent revision must be positive", ErrInvalidProposal)
	}
	if !validDigest(input.ArgumentsDigest) {
		return Proposal{}, fmt.Errorf("%w: argumentsDigest must be sha256 hex", ErrInvalidProposal)
	}
	if !validDigest(input.ActionRequestDigest) {
		return Proposal{}, fmt.Errorf("%w: actionRequestDigest must be sha256 hex", ErrInvalidProposal)
	}
	if err := input.ToolPolicy.Validate(); err != nil {
		return Proposal{}, err
	}

	return Proposal{
		ID:                  input.ID,
		TenantID:            input.TenantID,
		RunID:               input.RunID,
		TurnID:              input.TurnID,
		IntentRevision:      input.IntentRevision,
		ArgumentsDigest:     input.ArgumentsDigest,
		ActionRequestDigest: input.ActionRequestDigest,
		ToolPolicy:          input.ToolPolicy,
		State:               ProposalProposed,
		Version:             1,
	}, nil
}

// Prepare performs Runtime-side, side-effect-free admission. A true capability
// flag means the capability was resolved from trusted bundle metadata and
// matched against the active allow-list; it is not a plugin assertion.
func (p Proposal) Prepare(currentIntentRevision int64, capabilityAllowed bool) (Proposal, error) {
	if p.State != ProposalProposed {
		return Proposal{}, fmt.Errorf("%w: prepare from %s", ErrInvalidTransition, p.State)
	}
	if currentIntentRevision != p.IntentRevision {
		return Proposal{}, ErrStaleIntent
	}
	if !capabilityAllowed {
		return Proposal{}, fmt.Errorf("%w: capability is not in the active allow-list", ErrCommitNotAuthorized)
	}
	if err := p.ToolPolicy.Validate(); err != nil {
		return Proposal{}, err
	}
	p.State = ProposalPrepared
	p.Version++
	return p, nil
}

// Supersede invalidates a proposal after a newer user-intent revision arrives.
// It is deliberately unavailable after the Runtime Commit Boundary.
func (p Proposal) Supersede(newIntentRevision int64) (Proposal, error) {
	if p.State == ProposalCommitAuthorized || p.State == ProposalSubmittedToGuard {
		return Proposal{}, ErrCommitBoundaryCrossed
	}
	if p.State != ProposalProposed && p.State != ProposalPrepared {
		return Proposal{}, fmt.Errorf("%w: supersede from %s", ErrInvalidTransition, p.State)
	}
	if newIntentRevision <= p.IntentRevision {
		return Proposal{}, ErrStaleIntent
	}
	p.State = ProposalSuperseded
	p.Version++
	return p, nil
}

// Cancel is valid only before Commit. After Commit, cancellation must be
// requested through the owning authority and its operation must be reconciled.
func (p Proposal) Cancel() (Proposal, error) {
	if p.State == ProposalCommitAuthorized || p.State == ProposalSubmittedToGuard {
		return Proposal{}, ErrCommitBoundaryCrossed
	}
	if p.State != ProposalProposed && p.State != ProposalPrepared {
		return Proposal{}, fmt.Errorf("%w: cancel from %s", ErrInvalidTransition, p.State)
	}
	p.State = ProposalCancelled
	p.Version++
	return p, nil
}

type CommitConditions struct {
	CurrentIntentRevision   int64
	IntentComplete          bool
	CapabilityAllowed       bool
	RuntimeAdmissionAllowed bool
	UserConfirmed           bool
	GuardSubmissionKey      string
	ActionRequestDigest     string
}

// AuthorizeCommit crosses the Runtime Commit Boundary. For approval-gated
// actions this authorizes submission to EngageGuard, not external execution;
// Guard approval, Permit and trusted execution remain independent.
func (p Proposal) AuthorizeCommit(conditions CommitConditions) (Proposal, error) {
	if p.State == ProposalCommitAuthorized || p.State == ProposalSubmittedToGuard {
		if conditions.GuardSubmissionKey != p.GuardSubmissionKey ||
			conditions.ActionRequestDigest != p.ActionRequestDigest {
			return Proposal{}, ErrIdempotencyKeyConflict
		}
		return p, nil
	}
	if p.State != ProposalPrepared {
		return Proposal{}, fmt.Errorf("%w: commit from %s", ErrInvalidTransition, p.State)
	}
	if conditions.CurrentIntentRevision != p.IntentRevision {
		return Proposal{}, ErrStaleIntent
	}
	if !conditions.IntentComplete ||
		!conditions.CapabilityAllowed ||
		!conditions.RuntimeAdmissionAllowed ||
		(p.ToolPolicy.RequiresConfirmation && !conditions.UserConfirmed) {
		return Proposal{}, ErrCommitNotAuthorized
	}
	if err := validateIdentifier("guardSubmissionKey", conditions.GuardSubmissionKey); err != nil {
		return Proposal{}, err
	}
	if !validDigest(conditions.ActionRequestDigest) {
		return Proposal{}, fmt.Errorf("%w: actionRequestDigest must be sha256 hex", ErrInvalidProposal)
	}
	if conditions.ActionRequestDigest != p.ActionRequestDigest {
		return Proposal{}, ErrIdempotencyKeyConflict
	}

	p.GuardSubmissionKey = conditions.GuardSubmissionKey
	p.State = ProposalCommitAuthorized
	p.Version++
	return p, nil
}

// GuardOperationLink is constructed by the authenticated Guard adapter after
// validating the response. Correlation fields are copied from the exact request
// sent to Guard; OperationID is returned by Guard and is never Runtime-generated.
type GuardOperationLink struct {
	TenantID            string
	ProposalID          string
	GuardSubmissionKey  string
	ActionRequestDigest string
	OperationID         string
}

// MarkSubmittedToGuard links the authoritative Guard operation to the exact
// committed proposal. A response for another tenant, proposal, key or digest
// cannot advance this Proposal.
func (p Proposal) MarkSubmittedToGuard(link GuardOperationLink) (Proposal, error) {
	if p.State == ProposalSubmittedToGuard {
		if link.OperationID != p.GuardOperationID ||
			link.TenantID != p.TenantID ||
			link.ProposalID != p.ID ||
			link.GuardSubmissionKey != p.GuardSubmissionKey ||
			link.ActionRequestDigest != p.ActionRequestDigest {
			return Proposal{}, ErrIdempotencyKeyConflict
		}
		return p, nil
	}
	if p.State != ProposalCommitAuthorized {
		return Proposal{}, fmt.Errorf("%w: Guard submission from %s", ErrInvalidTransition, p.State)
	}
	if err := validateIdentifier("guardOperationID", link.OperationID); err != nil {
		return Proposal{}, err
	}
	if link.TenantID != p.TenantID ||
		link.ProposalID != p.ID ||
		link.GuardSubmissionKey != p.GuardSubmissionKey ||
		link.ActionRequestDigest != p.ActionRequestDigest {
		return Proposal{}, ErrIdempotencyKeyConflict
	}
	p.GuardOperationID = link.OperationID
	p.State = ProposalSubmittedToGuard
	p.Version++
	return p, nil
}

func validateIdentifier(name, value string) error {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 255 ||
		!utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%w: %s is empty or malformed", ErrInvalidProposal, name)
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
