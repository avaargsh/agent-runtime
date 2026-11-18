package run

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
)

const DecisionContinuationSchema = "decision.continuation.v1"

var continuationHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DecisionContinuationReceipt mirrors the authenticated Decision response.
// It is a point-in-time observation, not a signed transferable Permit.
// Only the trusted Runtime adapter may pass this to the local store.
type DecisionContinuationReceipt struct {
	SchemaVersion string            `json:"schema_version"`
	Authority     DecisionAuthority `json:"authority"`
	DecisionID    string            `json:"decision_id"`
	RecordSHA256  string            `json:"record_sha256"`
	PlanHash      string            `json:"plan_hash"`
}

func (r DecisionContinuationReceipt) Validate() error {
	if r.SchemaVersion != DecisionContinuationSchema || r.Authority.Validate() != nil ||
		!continuationHash.MatchString(r.RecordSHA256) || !continuationHash.MatchString(r.PlanHash) {
		return ErrDecisionPreparationDenied
	}
	identity, err := json.Marshal(struct{ TenantID, InvocationID string }{r.Authority.TenantID, r.Authority.InvocationID})
	if err != nil {
		return ErrDecisionPreparationDenied
	}
	hash := sha256.Sum256(identity)
	if r.DecisionID != "dec_"+hex.EncodeToString(hash[:]) {
		return ErrDecisionPreparationDenied
	}
	return nil
}
