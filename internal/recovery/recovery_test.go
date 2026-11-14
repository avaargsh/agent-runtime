package recovery

import "testing"

func TestGuardOperationNextStep(t *testing.T) {
	cases := []struct {
		name            string
		state           OperationState
		receiptVerified bool
		expected        NextStep
	}{
		{"new", StateRequested, false, StepWait},
		{"approval pending", StateWaitingApproval, false, StepWait},
		{"claimed", StateClaimed, false, StepWait},
		{"dispatching", StateDispatching, false, StepWait},
		{"unknown", StateUnknown, false, StepReconcile},
		{"reconciling", StateReconciling, false, StepReconcile},
		{"manual review", StateManualReview, false, StepManualReview},
		{"succeeded with receipt", StateSucceeded, true, StepContinue},
		{"succeeded without receipt", StateSucceeded, false, StepReconcile},
		{"failure confirmed", StateFailedConfirmed, false, StepStop},
		{"denied", StateRejected, false, StepStop},
		{"undefined", OperationState("COMPLETED_MAYBE"), false, StepStop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GuardOperationNextStep(tc.state, tc.receiptVerified)
			if got != tc.expected {
				t.Fatalf("state %q: got %q, want %q", tc.state, got, tc.expected)
			}
		})
	}
}

func TestLostAckResubmissionCannotChangeIntent(t *testing.T) {
	cases := []struct {
		name      string
		existing  EnsureRecord
		candidate EnsureRequest
		expected  EnsureDecision
	}{
		{"same persisted intent", EnsureRecord{
			Key: "guard-key-001", RequestDigest: "sha256:abc", State: StateRequested,
		}, EnsureRequest{Key: "guard-key-001", RequestDigest: "sha256:abc"}, EnsureResubmit},
		{"changed payload", EnsureRecord{
			Key: "guard-key-001", RequestDigest: "sha256:abc", State: StateRequested,
		}, EnsureRequest{Key: "guard-key-001", RequestDigest: "sha256:def"}, EnsureReject},
		{"changed key", EnsureRecord{
			Key: "guard-key-001", RequestDigest: "sha256:abc", State: StateRequested,
		}, EnsureRequest{Key: "guard-key-002", RequestDigest: "sha256:abc"}, EnsureReject},
		{"unknown blocks re-submit", EnsureRecord{
			Key: "guard-key-001", RequestDigest: "sha256:abc", State: StateUnknown,
		}, EnsureRequest{Key: "guard-key-001", RequestDigest: "sha256:abc"}, EnsureQueryOnly},
		{"reconciling blocks re-submit", EnsureRecord{
			Key: "guard-key-001", RequestDigest: "sha256:abc", State: StateReconciling,
		}, EnsureRequest{Key: "guard-key-001", RequestDigest: "sha256:abc"}, EnsureQueryOnly},
		{"claimed blocks re-submit", EnsureRecord{
			Key: "guard-key-001", RequestDigest: "sha256:abc", State: StateClaimed,
		}, EnsureRequest{Key: "guard-key-001", RequestDigest: "sha256:abc"}, EnsureQueryOnly},
		{"manual review blocks re-submit", EnsureRecord{
			Key: "guard-key-001", RequestDigest: "sha256:abc", State: StateManualReview,
		}, EnsureRequest{Key: "guard-key-001", RequestDigest: "sha256:abc"}, EnsureQueryOnly},
		{"missing persisted key", EnsureRecord{
			Key: "", RequestDigest: "sha256:abc", State: StateRequested,
		}, EnsureRequest{Key: "guard-key-001", RequestDigest: "sha256:abc"}, EnsureReject},
		{"unknown state never permits resubmit", EnsureRecord{
			Key: "guard-key-001", RequestDigest: "sha256:abc", State: OperationState("UNRECOGNIZED"),
		}, EnsureRequest{Key: "guard-key-001", RequestDigest: "sha256:abc"}, EnsureReject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecideEnsureRetry(tc.existing, tc.candidate)
			if got != tc.expected {
				t.Fatalf("got %q, want %q", got, tc.expected)
			}
		})
	}
}
