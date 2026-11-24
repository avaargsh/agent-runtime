package verification

import (
	"strings"
	"testing"
)

func TestAssessRejectsUntrustedDiagnosticPayloads(t *testing.T) {
	for _, size := range []int{32, 1 << 16} {
		payload := "UNTRUSTED_CANARY-" + strings.Repeat("x", size)
		for _, tc := range []struct {
			name   string
			mutate func(*Report)
		}{
			{"unknown-check", func(r *Report) { r.Checks[0].ID = payload }},
			{"malformed-check-fields", func(r *Report) {
				r.Checks[0].ID = payload
				r.Checks[0].Reason = strings.Repeat("x", maxReasonBytes+1)
			}},
			{"unknown-status", func(r *Report) { r.Checks[0].Status = CheckStatus(payload) }},
			{"unknown-evidence", func(r *Report) { r.Checks[0].EvidenceIDs = []string{payload} }},
			{"duplicate-evidence", func(r *Report) {
				r.Evidence[0].ID = "UNTRUSTED_CANARY"
				r.Evidence = append(r.Evidence, r.Evidence[0])
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				m, r := fixture()
				tc.mutate(&r)
				got, err := Assess(m, r)
				if err == nil || got.Verdict != "" || len(got.MissingRequired) != 0 {
					t.Fatal("untrusted report must fail without a verdict")
				}
				if len(err.Error()) > 512 || strings.Contains(err.Error(), "UNTRUSTED_CANARY") {
					t.Fatalf("untrusted diagnostic payload escaped: length=%d", len(err.Error()))
				}
			})
		}
	}
}
