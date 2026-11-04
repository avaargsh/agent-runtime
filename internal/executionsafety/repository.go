package executionsafety

import (
	"context"
	"encoding/json"
	"errors"
)

var (
	ErrNotFound              = errors.New("execution safety record not found")
	ErrVersionConflict       = errors.New("execution safety version conflict")
	ErrIntentRevisionConflict = errors.New("intent revision digest conflict")
)

type IntentRevision struct {
	TenantID string
	RunID    string
	TurnID   string
	Revision int64
	Digest   string
	Complete bool
}

// EvidenceRecord contains metadata and immutable references only. Raw secrets,
// Permit material and unrestricted tool arguments must never be persisted here.
type EvidenceRecord struct {
	EventID         string
	TenantID        string
	ProposalID      string
	EventType       string
	ProposalVersion int64
	IntentRevision  int64
	Payload         json.RawMessage
	CreatedAt       string
}

type Repository interface {
	AdvanceIntentRevision(context.Context, IntentRevision) error
	CreateProposal(context.Context, Proposal) (Proposal, error)
	PrepareProposal(context.Context, string, string, int64, bool) (Proposal, error)
	CommitProposal(context.Context, string, string, int64, CommitConditions) (Proposal, error)
	LinkGuardOperation(context.Context, string, string, int64, GuardOperationLink) (Proposal, error)
	GetProposal(context.Context, string, string) (Proposal, error)
	ListProposalEvidence(context.Context, string, string) ([]EvidenceRecord, error)
}
