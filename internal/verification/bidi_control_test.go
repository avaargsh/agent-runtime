package verification

import "testing"

// Unicode bidi formatting characters are valid UTF-8 but can render a
// different visual identity from the bytes used for authority/evidence
// matching. They must not be accepted in any v1 identity or report field.
func TestAssessRejectsBidiControlsInIdentityAndEvidence(t *testing.T) {
	tests := []struct {
		name string
		mutate func(*Manifest, *Report)
	}{
		{"tenant-override", func(m *Manifest, r *Report) {
			m.TenantID = "tenant-\u202eone"
			r.TenantID = m.TenantID
		}},
		{"run-isolate", func(m *Manifest, r *Report) {
			m.RunID = "run-\u2066one"
			r.RunID = m.RunID
		}},
		{"attempt-mark", func(m *Manifest, r *Report) {
			m.AttemptID = "attempt-\u200f1"
			r.AttemptID = m.AttemptID
		}},
		{"source-mark", func(m *Manifest, r *Report) {
			m.SourceRevision = "commit-\u061c123"
			r.SourceRevision = m.SourceRevision
		}},
		{"required-check", func(m *Manifest, r *Report) {
			m.RequiredCheckIDs[0] = "lint-\u202echeck"
			r.Checks[0].ID = m.RequiredCheckIDs[0]
		}},
		{"evidence-id", func(_ *Manifest, r *Report) {
			r.Evidence[0].ID = "lint-\u2067log"
			r.Checks[0].EvidenceIDs[0] = r.Evidence[0].ID
		}},
		{"evidence-uri", func(_ *Manifest, r *Report) {
			r.Evidence[0].URI = "artifact://verified/\u202elint"
		}},
		{"optional-success-reason", func(_ *Manifest, r *Report) {
			r.Checks[0].Reason = "ok-\u2069"
		}},
		{"failed-reason", func(_ *Manifest, r *Report) {
			r.Checks[0].Status = CheckFailed
			r.Checks[0].Reason = "failed-\u202a"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest, report := fixture()
			tc.mutate(&manifest, &report)
			got, err := Assess(manifest, report)
			if err == nil || got.Verdict != "" {
				t.Fatalf("bidi control accepted: assessment=%+v err=%v", got, err)
			}
		})
	}
}

func TestAssessPreservesValidArabicAndChineseWithoutBidiControls(t *testing.T) {
	manifest, report := fixture()
	manifest.TenantID = "عميل-客户"
	report.TenantID = manifest.TenantID
	manifest.RequiredCheckIDs[0] = "اختبار-验证"
	report.Checks[0].ID = manifest.RequiredCheckIDs[0]
	report.Evidence[0].URI = "artifact://verified/اختبار-构建"
	got, err := Assess(manifest, report)
	if err != nil || got.Verdict != VerdictPassed {
		t.Fatalf("ordinary multilingual report rejected: %+v err=%v", got, err)
	}
}
