package workflows

import (
	"errors"
	"strings"
)

const workflowIDPrefix = "agent-run/v1/"

// WorkflowID returns the single canonical Temporal Workflow ID for a Runtime-owned Run.
// Runtime creates runID once per accepted run_intent_id and reuses it across retries.
func WorkflowID(runID string) (string, error) {
	if runID == "" || runID != strings.TrimSpace(runID) || len(runID) > 256 ||
		strings.ContainsAny(runID, "/?#") {
		return "", errors.New("invalid canonical run id")
	}
	return workflowIDPrefix + runID, nil
}
