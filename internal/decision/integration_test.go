package decision

import (
	"context"
	"os"
	"testing"
)

// This test is opt-in so ordinary tests remain hermetic.
// Run the Python plugin and set DECISION_INTEGRATION_URL to its local endpoint.
func TestPythonDecisionPlugin(t *testing.T) {
	endpoint := os.Getenv("DECISION_INTEGRATION_URL")
	if endpoint == "" {
		t.Skip("set DECISION_INTEGRATION_URL for real Python contract test")
	}
	result, err := (Client{Endpoint: endpoint}).Invoke(context.Background(), sample())
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != "Accepted: hello" {
		t.Fatalf("unexpected plugin text: %q", result.Text)
	}
}
