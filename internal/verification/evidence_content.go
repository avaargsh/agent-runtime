package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// AssessWithEvidenceContent runs the structural v1 assessment and verifies
// that the supplied bytes exactly match every EvidenceRef digest in the
// Report. The caller must fetch those bytes from its independently trusted
// artifact source and enforce transport/read-size limits before calling.
//
// A matching SHA-256 proves byte consistency only. It does not authenticate
// the Manifest, prove URI provenance, establish immutable storage, attest
// who executed a check, or authorize a release or protected action.
func AssessWithEvidenceContent(m Manifest, r Report, contentByEvidenceID map[string][]byte) (Assessment, error) {
	assessment, err := Assess(m, r)
	if err != nil {
		return Assessment{}, err
	}
	if len(contentByEvidenceID) != len(r.Evidence) {
		return Assessment{}, fmt.Errorf("evidence content set does not match report references")
	}
	for _, ref := range r.Evidence {
		content, ok := contentByEvidenceID[ref.ID]
		if !ok {
			return Assessment{}, fmt.Errorf("missing bytes for evidence %q", ref.ID)
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != ref.SHA256 {
			return Assessment{}, fmt.Errorf("evidence content digest mismatch for %q", ref.ID)
		}
	}
	return assessment, nil
}
