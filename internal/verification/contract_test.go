package verification

import (
	"fmt"
	"strings"
	"testing"
)

func fixture() (Manifest, Report) {
	d := strings.Repeat("a", 64)
	manifest := Manifest{
		SchemaVersion:     Version,
		TenantID:          "tenant-1",
		RunID:             "run-1",
		AttemptID:         "attempt-1",
		SourceRevision:    "commit-123",
		EnvironmentDigest: d,
		ManifestDigest:    strings.Repeat("b", 64),
		RequiredCheckIDs:  []string{"lint", "unit"},
	}
	report := Report{
		SchemaVersion:     Version,
		TenantID:          manifest.TenantID,
		RunID:             manifest.RunID,
		AttemptID:         manifest.AttemptID,
		SourceRevision:    manifest.SourceRevision,
		EnvironmentDigest: manifest.EnvironmentDigest,
		ManifestDigest:    manifest.ManifestDigest,
		Evidence: []EvidenceRef{
			{ID: "lint-log", URI: "artifact://verified/lint", SHA256: strings.Repeat("c", 64)},
			{ID: "unit-log", URI: "artifact://verified/unit", SHA256: strings.Repeat("d", 64)},
		},
		Checks: []Check{
			{ID: "lint", Status: CheckPassed, EvidenceIDs: []string{"lint-log"}},
			{ID: "unit", Status: CheckPassed, EvidenceIDs: []string{"unit-log"}},
		},
	}
	return manifest, report
}

func TestAssessAllRequiredChecksWithEvidencePass(t *testing.T) {
	manifest, report := fixture()
	result, err := Assess(manifest, report)
	if err != nil {
		t.Fatalf("expected validated report: %v", err)
	}
	if result.Verdict != VerdictPassed || len(result.MissingRequired) != 0 {
		t.Fatalf("unexpected verdict: %#v", result)
	}
}

func TestAssessMissingRequiredCheckIsIncomplete(t *testing.T) {
	manifest, report := fixture()
	report.Checks = report.Checks[:1]
	result, err := Assess(manifest, report)
	if err != nil {
		t.Fatalf("missing checks must be visible as incomplete: %v", err)
	}
	if result.Verdict != VerdictIncomplete || len(result.MissingRequired) != 1 || result.MissingRequired[0] != "unit" {
		t.Fatalf("missing required check must block PASS: %#v", result)
	}
}

func TestAssessSkippedAndInconclusiveNeverPass(t *testing.T) {
	for _, status := range []CheckStatus{CheckNotRun, CheckSkipped, CheckInconclusive} {
		t.Run(string(status), func(t *testing.T) {
			manifest, report := fixture()
			report.Checks[1] = Check{ID: "unit", Status: status, Reason: "not independently verified"}
			result, err := Assess(manifest, report)
			if err != nil {
				t.Fatal(err)
			}
			if result.Verdict != VerdictIncomplete {
				t.Fatalf("%s must not pass: %#v", status, result)
			}
		})
	}
}

func TestAssessFailedCheckWithEvidenceProducesFailure(t *testing.T) {
	manifest, report := fixture()
	report.Checks[1].Status = CheckFailed
	report.Checks[1].Reason = "assertion failed"
	result, err := Assess(manifest, report)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictFailed {
		t.Fatalf("proof of failure must be reported: %#v", result)
	}
}

func TestAssessRejectsUntrustedOrMalformedResults(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest, *Report)
	}{
		{"tenant-mismatch", func(_ *Manifest, r *Report) { r.TenantID = "tenant-other" }},
		{"run-mismatch", func(_ *Manifest, r *Report) { r.RunID = "run-other" }},
		{"attempt-mismatch", func(_ *Manifest, r *Report) { r.AttemptID = "attempt-other" }},
		{"source-mismatch", func(_ *Manifest, r *Report) { r.SourceRevision = "commit-other" }},
		{"environment-mismatch", func(_ *Manifest, r *Report) { r.EnvironmentDigest = strings.Repeat("e", 64) }},
		{"manifest-mismatch", func(_ *Manifest, r *Report) { r.ManifestDigest = strings.Repeat("e", 64) }},
		{"invalid-version", func(_ *Manifest, r *Report) { r.SchemaVersion = "verification/v2" }},
		{"duplicate-required", func(m *Manifest, _ *Report) { m.RequiredCheckIDs = []string{"lint", "lint"} }},
		{"no-required", func(m *Manifest, _ *Report) { m.RequiredCheckIDs = nil }},
		{"duplicate-check", func(_ *Manifest, r *Report) { r.Checks = append(r.Checks, r.Checks[0]) }},
		{"unknown-check", func(_ *Manifest, r *Report) { r.Checks[1].ID = "deploy" }},
		{"unknown-status", func(_ *Manifest, r *Report) { r.Checks[1].Status = "FLAKY" }},
		{"missing-evidence", func(_ *Manifest, r *Report) { r.Checks[1].EvidenceIDs = nil }},
		{"dangling-evidence", func(_ *Manifest, r *Report) { r.Checks[1].EvidenceIDs = []string{"nonexistent"} }},
		{"duplicate-evidence", func(_ *Manifest, r *Report) { r.Evidence = append(r.Evidence, r.Evidence[0]) }},
		{"duplicate-check-ref", func(_ *Manifest, r *Report) { r.Checks[1].EvidenceIDs = []string{"unit-log", "unit-log"} }},
		{"missing-evidence-digest", func(_ *Manifest, r *Report) { r.Evidence[0].SHA256 = "" }},
		{"malformed-evidence-digest", func(_ *Manifest, r *Report) { r.Evidence[0].SHA256 = "not-a-digest" }},
		{"malformed-manifest-digest", func(m *Manifest, _ *Report) { m.ManifestDigest = "short" }},
		{"missing-failure-reason", func(_ *Manifest, r *Report) { r.Checks[1].Status = CheckFailed; r.Checks[1].Reason = "" }},
		{"missing-inconclusive-reason", func(_ *Manifest, r *Report) { r.Checks[1].Status = CheckInconclusive; r.Checks[1].Reason = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, report := fixture()
			tc.mutate(&manifest, &report)
			result, err := Assess(manifest, report)
			if err == nil {
				t.Fatalf("untrusted/malformed verification unexpectedly accepted: %#v", result)
			}
		})
	}
}

func TestAssessRejectsEmbeddedControlCharactersInIdentityAndEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest, *Report)
	}{
		{"source-revision-nul", func(m *Manifest, r *Report) {
			m.SourceRevision = "commit\x00rev"
			r.SourceRevision = m.SourceRevision
		}},
		{"tenant-newline", func(m *Manifest, r *Report) {
			m.TenantID = "tenant\nother"
			r.TenantID = m.TenantID
		}},
		{"required-check-id-nul", func(m *Manifest, r *Report) {
			m.RequiredCheckIDs[0] = "lint\x00other"
			r.Checks[0].ID = m.RequiredCheckIDs[0]
		}},
		{"evidence-id-nul", func(_ *Manifest, r *Report) {
			r.Evidence[0].ID = "lint\x00log"
			r.Checks[0].EvidenceIDs[0] = r.Evidence[0].ID
		}},
		{"evidence-uri-crlf", func(_ *Manifest, r *Report) {
			r.Evidence[0].URI = "artifact://verified/lint\r\nX-Forged: yes"
		}},
		{"reason-tab", func(_ *Manifest, r *Report) {
			r.Checks[0].Status = CheckFailed
			r.Checks[0].Reason = "error\tforged"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest, report := fixture()
			tc.mutate(&manifest, &report)
			assessment, err := Assess(manifest, report)
			if err == nil {
				t.Fatalf("embedded control character accepted: %+v", assessment)
			}
		})
	}
}

func TestAssessFailureTakesPrecedenceOverIncomplete(t *testing.T) {
	manifest, report := fixture()
	manifest.RequiredCheckIDs = append(manifest.RequiredCheckIDs, "integration")
	report.Checks[1].Status = CheckFailed
	report.Checks[1].Reason = "unit failure"
	result, err := Assess(manifest, report)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictFailed || len(result.MissingRequired) != 1 {
		t.Fatalf("report proven failure and uncovered checks separately: %#v", result)
	}
}

func TestAssessRejectsOversizedManifestAndReport(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest, *Report)
	}{
		{"oversized-tenant", func(m *Manifest, r *Report) {
			m.TenantID = strings.Repeat("x", 257)
			r.TenantID = m.TenantID
		}},
		{"oversized-source-revision", func(m *Manifest, r *Report) {
			m.SourceRevision = strings.Repeat("x", 257)
			r.SourceRevision = m.SourceRevision
		}},
		{"oversized-required-check-id", func(m *Manifest, r *Report) {
			m.RequiredCheckIDs[0] = strings.Repeat("x", 257)
			r.Checks[0].ID = m.RequiredCheckIDs[0]
		}},
		{"oversized-evidence-id", func(_ *Manifest, r *Report) {
			r.Evidence[0].ID = strings.Repeat("x", 257)
			r.Checks[0].EvidenceIDs[0] = r.Evidence[0].ID
		}},
		{"oversized-evidence-uri", func(_ *Manifest, r *Report) {
			r.Evidence[0].URI = "artifact://" + strings.Repeat("x", 2048)
		}},
		{"oversized-reason-even-when-passed", func(_ *Manifest, r *Report) {
			r.Checks[0].Reason = strings.Repeat("x", 1025)
		}},
		{"control-character-in-passed-reason", func(_ *Manifest, r *Report) {
			r.Checks[0].Reason = "passed\nforge"
		}},
		{"too-many-required-checks", func(m *Manifest, _ *Report) {
			for i := 0; i < 256; i++ {
				m.RequiredCheckIDs = append(m.RequiredCheckIDs, fmt.Sprintf("extra-%d", i))
			}
		}},
		{"too-many-reported-checks", func(_ *Manifest, r *Report) {
			for i := 0; i < 256; i++ {
				r.Checks = append(r.Checks, r.Checks[0])
			}
		}},
		{"too-many-evidence-references", func(_ *Manifest, r *Report) {
			for i := 0; i < 1024; i++ {
				r.Evidence = append(r.Evidence, EvidenceRef{
					ID: fmt.Sprintf("extra-%d", i),
					URI: "artifact://verified/extra",
					SHA256: strings.Repeat("a", 64),
				})
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, report := fixture()
			tc.mutate(&manifest, &report)
			assessment, err := Assess(manifest, report)
			if err == nil || assessment.Verdict != "" || len(assessment.MissingRequired) != 0 {
				t.Fatalf("oversized/malformed verification accepted: %+v err=%v", assessment, err)
			}
		})
	}
}
