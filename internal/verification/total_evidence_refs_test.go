package verification

import (
	"fmt"
	"strings"
	"testing"
)

func aggregateEvidenceFixture(totalReferences int) (Manifest, Report) {
	manifest, report := fixture()
	evidenceCount := maxEvidenceCount
	checkCount := (totalReferences + evidenceCount - 1) / evidenceCount

	manifest.RequiredCheckIDs = make([]string, checkCount)
	report.Checks = make([]Check, checkCount)
	report.Evidence = make([]EvidenceRef, evidenceCount)

	evidenceIDs := make([]string, evidenceCount)
	for i := 0; i < evidenceCount; i++ {
		id := fmt.Sprintf("evidence-%04d", i)
		evidenceIDs[i] = id
		report.Evidence[i] = EvidenceRef{
			ID:     id,
			URI:    "artifact://verified/" + id,
			SHA256: strings.Repeat("a", 64),
		}
	}

	remaining := totalReferences
	for i := 0; i < checkCount; i++ {
		checkID := fmt.Sprintf("check-%d", i)
		manifest.RequiredCheckIDs[i] = checkID
		referenceCount := remaining
		if referenceCount > evidenceCount {
			referenceCount = evidenceCount
		}
		report.Checks[i] = Check{
			ID:          checkID,
			Status:      CheckPassed,
			EvidenceIDs: append([]string(nil), evidenceIDs[:referenceCount]...),
		}
		remaining -= referenceCount
	}
	return manifest, report
}

func TestAssessAcceptsAggregateEvidenceReferencesAtLimit(t *testing.T) {
	manifest, report := aggregateEvidenceFixture(maxTotalEvidenceRefs)
	assessment, err := Assess(manifest, report)
	if err != nil {
		t.Fatalf("Assess rejected the aggregate reference limit: %v", err)
	}
	if assessment.Verdict != VerdictPassed {
		t.Fatalf("Assess verdict = %q, want %q", assessment.Verdict, VerdictPassed)
	}
}

func TestAssessRejectsExcessiveAggregateEvidenceReferences(t *testing.T) {
	manifest, report := aggregateEvidenceFixture(maxTotalEvidenceRefs + 1)
	assessment, err := Assess(manifest, report)
	if err == nil {
		t.Fatalf("Assess accepted %d aggregate evidence references: %+v", maxTotalEvidenceRefs+1, assessment)
	}
	if assessment.Verdict != "" || len(assessment.MissingRequired) != 0 {
		t.Fatalf("rejected report returned a partial verdict: %+v", assessment)
	}
}
