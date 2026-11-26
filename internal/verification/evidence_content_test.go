package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func evidenceContentFixture() (Manifest, Report, map[string][]byte) {
	manifest, report := fixture()
	content := map[string][]byte{
		"lint-log": []byte("lint: passed\n"),
		"unit-log": {0x00, 0xff, 0x10, 0x80},
	}
	for i := range report.Evidence {
		sum := sha256.Sum256(content[report.Evidence[i].ID])
		report.Evidence[i].SHA256 = hex.EncodeToString(sum[:])
	}
	return manifest, report, content
}

func TestAssessWithEvidenceContentPassesOnlyAfterHashingEveryEvidenceRef(t *testing.T) {
	manifest, report, content := evidenceContentFixture()
	assessment, err := AssessWithEvidenceContent(manifest, report, content)
	if err != nil {
		t.Fatalf("valid evidence bytes rejected: %v", err)
	}
	if assessment.Verdict != VerdictPassed || len(assessment.MissingRequired) != 0 {
		t.Fatalf("unexpected content-verified assessment: %+v", assessment)
	}
}

func TestAssessWithEvidenceContentRejectsMissingBytesWithoutVerdict(t *testing.T) {
	manifest, report, content := evidenceContentFixture()
	delete(content, "unit-log")
	assessment, err := AssessWithEvidenceContent(manifest, report, content)
	if err == nil || assessment.Verdict != "" {
		t.Fatalf("missing evidence bytes produced a verdict: %+v err=%v", assessment, err)
	}
}

func TestAssessWithEvidenceContentRejectsTamperedBytesWithoutVerdict(t *testing.T) {
	manifest, report, content := evidenceContentFixture()
	content["unit-log"] = []byte("tampered test output")
	assessment, err := AssessWithEvidenceContent(manifest, report, content)
	if err == nil || assessment.Verdict != "" {
		t.Fatalf("tampered evidence bytes produced a verdict: %+v err=%v", assessment, err)
	}
}

func TestAssessWithEvidenceContentRejectsUnreferencedContent(t *testing.T) {
	manifest, report, content := evidenceContentFixture()
	content["untrusted-extra"] = []byte("not in the report")
	assessment, err := AssessWithEvidenceContent(manifest, report, content)
	if err == nil || assessment.Verdict != "" {
		t.Fatalf("unreferenced evidence bytes were silently accepted: %+v err=%v", assessment, err)
	}
}

func TestAssessWithEvidenceContentPreservesFailedVerdictAfterDigestVerification(t *testing.T) {
	manifest, report, content := evidenceContentFixture()
	report.Checks[1].Status = CheckFailed
	report.Checks[1].Reason = "assertion failed"
	assessment, err := AssessWithEvidenceContent(manifest, report, content)
	if err != nil {
		t.Fatalf("valid failure evidence rejected: %v", err)
	}
	if assessment.Verdict != VerdictFailed {
		t.Fatalf("digest verification changed the semantic verdict: %+v", assessment)
	}
}
