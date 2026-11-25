package verification

import (
	"fmt"
	"strings"
	"testing"
)

func TestAssessRejectsExcessiveAggregateEvidenceReferences(t *testing.T) {
	manifest, report := fixture()
	const evidenceCount = 1024
	const checkCount = 5

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

	for i := 0; i < checkCount; i++ {
		checkID := fmt.Sprintf("check-%d", i)
		manifest.RequiredCheckIDs[i] = checkID
		report.Checks[i] = Check{
			ID:     checkID,
			Status: CheckPassed,
		}
		if i < 4 {
			report.Checks[i].EvidenceIDs = append([]string(nil), evidenceIDs...)
			continue
		}
		// 4*1024 + 1 = 4097 aggregate references. Every reference is
		// valid and unique within its Check; the same evidence may support
		// more than one independent check.
		report.Checks[i].EvidenceIDs = []string{evidenceIDs[0]}
	}

	assessment, err := Assess(manifest, report)
	if err == nil {
		t.Fatalf("Assess accepted %d aggregate evidence references: %+v", 4*evidenceCount+1, assessment)
	}
	if assessment.Verdict != "" || len(assessment.MissingRequired) != 0 {
		t.Fatalf("rejected report returned a partial verdict: %+v", assessment)
	}
}
