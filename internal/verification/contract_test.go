package verification

import (
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
