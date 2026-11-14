package acp

import (
	"errors"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrClaimConflict = errors.New("conflicting Runtime ACP harness session creation claim")

// SessionClaim is a Runtime-owned immutable, pre-dispatch creation identity.
// A caller must derive tenant/release/policy/Attempt from trusted Runtime and
// control-plane authorities. This structure does not authenticate those claims.
type SessionClaim struct {
	TenantID          string
	RunID             string
	AttemptID         string
	HarnessInstanceID string
	AgentReleaseID    string
	PolicyRevision    string
	RequestDigest     string
	WorkingDir        string
}

type ClaimState string

const (
	ClaimPrepared  ClaimState = "PREPARED"
	ClaimUnknown   ClaimState = "UNKNOWN"
	ClaimConfirmed ClaimState = "CONFIRMED"
)

// SessionClaimRecord reports only persisted Runtime evidence. ClaimUnknown
// includes the time after committing a dispatch claim but BEFORE any network
// operation: a crashed worker must never infer that retry is safe.
type SessionClaimRecord struct {
	SessionClaim
	State          ClaimState
	AgentSessionID string
	Created        bool
}

func (c SessionClaim) Validate() error {
	if !validIdentifier(c.TenantID) || !validIdentifier(c.HarnessInstanceID) ||
		!validIdentifier(c.AgentReleaseID) || !validIdentifier(c.PolicyRevision) ||
		!canonicalUUID(c.RunID) || !canonicalUUID(c.AttemptID) ||
		len(c.RequestDigest) != len("sha256:")+64 ||
		!strings.HasPrefix(c.RequestDigest, "sha256:") ||
		!lowercaseHex(c.RequestDigest[len("sha256:"):]) ||
		len(c.WorkingDir) == 0 || len(c.WorkingDir) > 4096 ||
		!utf8.ValidString(c.WorkingDir) || strings.ContainsRune(c.WorkingDir, '\x00') ||
		!filepath.IsAbs(c.WorkingDir) || filepath.Clean(c.WorkingDir) != c.WorkingDir {
		return ErrBindingInvalid
	}
	return nil
}

func canonicalUUID(v string) bool {
	id, err := uuid.Parse(v)
	return err == nil && id.String() == v
}

func lowercaseHex(v string) bool {
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (r SessionClaimRecord) Matches(c SessionClaim) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if r.SessionClaim != c {
		return ErrClaimConflict
	}
	return nil
}
