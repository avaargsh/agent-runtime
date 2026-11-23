package verification

import "testing"

// A malformed UTF-8 identity or evidence identifier may be silently replaced
// with U+FFFD by a later JSON serializer, breaking exact source/manifest
// binding between services. The pure contract must fail closed first.
func TestAssessRejectsInvalidUTF8AcrossManifestAndReport(t *testing.T) {
	invalid := "bad-" + string([]byte{0xff}) + "-id"
	tests := []struct {
		name   string
		mutate func(*Manifest, *Report)
	}{
		{"tenant", func(m *Manifest, r *Report) {
			m.TenantID = invalid
			r.TenantID = invalid
		}},
		{"run", func(m *Manifest, r *Report) {
			m.RunID = invalid
			r.RunID = invalid
		}},
		{"attempt", func(m *Manifest, r *Report) {
			m.AttemptID = invalid
			r.AttemptID = invalid
		}},
		{"source", func(m *Manifest, r *Report) {
			m.SourceRevision = invalid
			r.SourceRevision = invalid
		}},
		{"required-check", func(m *Manifest, r *Report) {
			m.RequiredCheckIDs[0] = invalid
			r.Checks[0].ID = invalid
		}},
		{"evidence-id", func(_ *Manifest, r *Report) {
			r.Evidence[0].ID = invalid
			r.Checks[0].EvidenceIDs[0] = invalid
		}},
		{"evidence-uri", func(_ *Manifest, r *Report) {
			r.Evidence[0].URI = "artifact://verified/" + invalid
		}},
		{"failure-reason", func(_ *Manifest, r *Report) {
			r.Checks[0].Status = CheckFailed
			r.Checks[0].Reason = invalid
		}},
		{"optional-success-reason", func(_ *Manifest, r *Report) {
			r.Checks[0].Reason = invalid
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest, report := fixture()
			tc.mutate(&manifest, &report)
			assessment, err := Assess(manifest, report)
			if err == nil || assessment.Verdict != "" {
				t.Fatalf("invalid UTF-8 accepted: assessment=%+v err=%v", assessment, err)
			}
		})
	}
}

func TestAssessAcceptsValidMultibyteUTF8IdentityAndEvidence(t *testing.T) {
	manifest, report := fixture()
	manifest.TenantID = "客户-租户"
	report.TenantID = manifest.TenantID
	manifest.RequiredCheckIDs[0] = "构建验证"
	report.Checks[0].ID = manifest.RequiredCheckIDs[0]
	report.Evidence[0].URI = "artifact://verified/构建"
	assessment, err := Assess(manifest, report)
	if err != nil || assessment.Verdict != VerdictPassed {
		t.Fatalf("valid UTF-8 unexpectedly rejected: assessment=%+v err=%v", assessment, err)
	}
}
