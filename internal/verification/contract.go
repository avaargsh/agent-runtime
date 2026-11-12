// Package verification provides a pure, fail-closed assessment of evidence-bound
// checks against an externally authenticated and pinned verification manifest.
// It does not authenticate, execute, persist, or authorize a report.
package verification

import (
	"fmt"
	"strings"
	"unicode"
)

const Version = "verification/v1"

// These limits bound the work and memory consumed by unauthenticated report
// content before any future persistence or toolchain integration.
const (
	maxIdentityBytes   = 256
	maxCheckCount      = 256
	maxEvidenceCount   = 1024
	maxEvidenceURIBytes = 2048
	maxReasonBytes     = 1024
)

type CheckStatus string

const (
	CheckPassed       CheckStatus = "PASSED"
	CheckFailed       CheckStatus = "FAILED"
	CheckNotRun       CheckStatus = "NOT_RUN"
	CheckSkipped      CheckStatus = "SKIPPED"
	CheckInconclusive CheckStatus = "INCONCLUSIVE"
)

type Verdict string

const (
	VerdictPassed     Verdict = "PASSED"
	VerdictFailed     Verdict = "FAILED"
	VerdictIncomplete Verdict = "INCOMPLETE"
)

// Manifest must originate from a trusted, immutable policy snapshot. This
// package validates shape and matching identity, not its signature/authority.
type Manifest struct {
	SchemaVersion     string   `json:"schema_version"`
	TenantID          string   `json:"tenant_id"`
	RunID             string   `json:"run_id"`
	AttemptID         string   `json:"attempt_id"`
	SourceRevision    string   `json:"source_revision"`
	EnvironmentDigest string   `json:"environment_digest"`
	ManifestDigest    string   `json:"manifest_digest"`
	RequiredCheckIDs  []string `json:"required_check_ids"`
}

type EvidenceRef struct {
	ID     string `json:"id"`
	URI    string `json:"uri"`
	SHA256 string `json:"sha256"`
}

type Check struct {
	ID          string      `json:"id"`
	Status      CheckStatus `json:"status"`
	EvidenceIDs []string    `json:"evidence_ids,omitempty"`
	Reason      string      `json:"reason,omitempty"`
}

type Report struct {
	SchemaVersion     string        `json:"schema_version"`
	TenantID          string        `json:"tenant_id"`
	RunID             string        `json:"run_id"`
	AttemptID         string        `json:"attempt_id"`
	SourceRevision    string        `json:"source_revision"`
	EnvironmentDigest string        `json:"environment_digest"`
	ManifestDigest    string        `json:"manifest_digest"`
	Checks            []Check       `json:"checks"`
	Evidence          []EvidenceRef `json:"evidence"`
}

// Assessment is advisory data, not a release, merge, Permit, or execution
// authorization decision. MissingRequired retains the manifest's stable order.
type Assessment struct {
	Verdict         Verdict  `json:"verdict"`
	MissingRequired []string `json:"missing_required,omitempty"`
}

func nonBlank(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) == -1
}

func boundedNonBlank(s string, maxBytes int) bool {
	return len(s) <= maxBytes && nonBlank(s)
}

func sha256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, ch := range s {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// Assess validates the complete v1 wire contract and derives a conservative
// verdict. A missing check is incomplete, never an implicit success. A FAILED
// check must be backed by evidence rather than a bare model assertion.
func Assess(m Manifest, r Report) (Assessment, error) {
	var zero Assessment
	if m.SchemaVersion != Version || r.SchemaVersion != Version {
		return zero, fmt.Errorf("unsupported verification schema version")
	}
	if !boundedNonBlank(m.TenantID, maxIdentityBytes) ||
		!boundedNonBlank(m.RunID, maxIdentityBytes) ||
		!boundedNonBlank(m.AttemptID, maxIdentityBytes) ||
		!boundedNonBlank(m.SourceRevision, maxIdentityBytes) {
		return zero, fmt.Errorf("missing trusted manifest identity")
	}
	if !sha256Hex(m.EnvironmentDigest) || !sha256Hex(m.ManifestDigest) {
		return zero, fmt.Errorf("invalid trusted manifest digest")
	}
	if r.TenantID != m.TenantID || r.RunID != m.RunID ||
		r.AttemptID != m.AttemptID || r.SourceRevision != m.SourceRevision ||
		r.EnvironmentDigest != m.EnvironmentDigest || r.ManifestDigest != m.ManifestDigest {
		return zero, fmt.Errorf("verification report identity or manifest mismatch")
	}

	if len(m.RequiredCheckIDs) == 0 || len(m.RequiredCheckIDs) > maxCheckCount ||
		len(r.Checks) > maxCheckCount || len(r.Evidence) > maxEvidenceCount {
		return zero, fmt.Errorf("verification report exceeds supported check/evidence bounds")
	}
	required := make(map[string]struct{}, len(m.RequiredCheckIDs))
	for _, id := range m.RequiredCheckIDs {
		if !boundedNonBlank(id, maxIdentityBytes) {
			return zero, fmt.Errorf("blank required check id")
		}
		if _, duplicate := required[id]; duplicate {
			return zero, fmt.Errorf("duplicate required check id %q", id)
		}
		required[id] = struct{}{}
	}

	evidence := make(map[string]struct{}, len(r.Evidence))
	for _, e := range r.Evidence {
		if !boundedNonBlank(e.ID, maxIdentityBytes) ||
			!boundedNonBlank(e.URI, maxEvidenceURIBytes) || !sha256Hex(e.SHA256) {
			return zero, fmt.Errorf("malformed evidence reference")
		}
		if _, duplicate := evidence[e.ID]; duplicate {
			return zero, fmt.Errorf("duplicate evidence id %q", e.ID)
		}
		evidence[e.ID] = struct{}{}
	}

	observed := make(map[string]CheckStatus, len(r.Checks))
	failed := false
	incomplete := false
	for _, check := range r.Checks {
		if len(check.EvidenceIDs) > maxEvidenceCount ||
			(check.Reason != "" && !boundedNonBlank(check.Reason, maxReasonBytes)) {
			return zero, fmt.Errorf("check %q has oversized or malformed fields", check.ID)
		}
		if _, ok := required[check.ID]; !ok {
			return zero, fmt.Errorf("unknown or blank check id %q", check.ID)
		}
		if _, duplicate := observed[check.ID]; duplicate {
			return zero, fmt.Errorf("duplicate check id %q", check.ID)
		}
		switch check.Status {
		case CheckPassed, CheckFailed:
			if len(check.EvidenceIDs) == 0 {
				return zero, fmt.Errorf("check %q claims a result without evidence", check.ID)
			}
		case CheckNotRun, CheckSkipped, CheckInconclusive:
			incomplete = true
		default:
			return zero, fmt.Errorf("unsupported check status %q", check.Status)
		}
		if check.Status != CheckPassed && !nonBlank(check.Reason) {
			return zero, fmt.Errorf("non-passing check %q requires a reason", check.ID)
		}
		used := make(map[string]struct{}, len(check.EvidenceIDs))
		for _, id := range check.EvidenceIDs {
			if _, duplicate := used[id]; duplicate {
				return zero, fmt.Errorf("check %q references evidence %q twice", check.ID, id)
			}
			if _, exists := evidence[id]; !exists {
				return zero, fmt.Errorf("check %q references unknown evidence %q", check.ID, id)
			}
			used[id] = struct{}{}
		}
		if check.Status == CheckFailed {
			failed = true
		}
		observed[check.ID] = check.Status
	}

	result := Assessment{}
	for _, id := range m.RequiredCheckIDs {
		if _, seen := observed[id]; !seen {
			result.MissingRequired = append(result.MissingRequired, id)
		}
	}
	switch {
	case failed:
		result.Verdict = VerdictFailed
	case incomplete || len(result.MissingRequired) != 0:
		result.Verdict = VerdictIncomplete
	default:
		result.Verdict = VerdictPassed
	}
	return result, nil
}
