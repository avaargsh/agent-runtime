package run

// GuardRunSafetySnapshot is a read-only, tenant-scoped projection of Runtime's
// persisted Run identity, lifecycle state and RUN circuit-breaker fencing
// version. It is a necessary precondition for Guard admission, never a
// sufficient authorization: Decision/Plan/Step, policy, capability, current
// Turn revision and binding must still be checked by their authorities.
type GuardRunSafetySnapshot struct {
	Identity       Identity
	Status         Status
	BreakerState   string
	BreakerEpoch   uint64
	BreakerVersion uint64
}

// EligibleForGuardSubmission only indicates that the Run's *local* safety
// preconditions are currently satisfied. It grants neither Approval nor
// Permit and is not safe for use as an external action execution decision.
// A later breaker transition can invalidate the snapshot.
func (s GuardRunSafetySnapshot) EligibleForGuardSubmission() bool {
	return s.Identity.Validate() == nil &&
		s.Status == StatusRunning &&
		s.BreakerState == "CLOSED" &&
		s.BreakerEpoch > 0 &&
		s.BreakerVersion > 0
}
