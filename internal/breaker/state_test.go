package breaker

import (
	"errors"
	"testing"
	"time"
)

func runScope() Scope {
	return Scope{Kind: ScopeRun, ID: "run-001"}
}

func testTime() time.Time {
	return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
}

func TestNewClosedAndTripFencePriorWorkers(t *testing.T) {
	now := testTime()
	closed, err := NewClosed(runScope(), now)
	if err != nil {
		t.Fatalf("NewClosed() error = %v", err)
	}
	if closed.State != StateClosed || closed.Epoch == 0 {
		t.Fatalf("NewClosed() = %+v, want CLOSED with non-zero epoch", closed)
	}

	opened, err := closed.Trip("CREDENTIAL_EXFILTRATION", "event-001", now.Add(time.Second))
	if err != nil {
		t.Fatalf("Trip() error = %v", err)
	}
	if opened.State != StateOpen || opened.Epoch <= closed.Epoch || opened.Version <= closed.Version {
		t.Fatalf("Trip() = %+v, want OPEN with advanced fencing/version", opened)
	}
	if err := opened.Check(closed.Epoch, EffectReadOnly); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("Check(old epoch) error = %v, want ErrStaleEpoch", err)
	}
	if err := opened.Check(opened.Epoch, EffectReadOnly); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("Check(OPEN) error = %v, want ErrBreakerOpen", err)
	}
}

func TestTripIsIdempotentWhileAlreadyOpen(t *testing.T) {
	closed, _ := NewClosed(runScope(), testTime())
	opened, err := closed.Trip("UNAUTHORIZED_EGRESS", "event-001", testTime().Add(time.Second))
	if err != nil {
		t.Fatalf("Trip() error = %v", err)
	}
	repeated, err := opened.Trip("SECOND_TRIGGER", "event-002", testTime().Add(2*time.Second))
	if err != nil {
		t.Fatalf("repeated Trip() error = %v", err)
	}
	if repeated.Epoch != opened.Epoch || repeated.Version != opened.Version ||
		repeated.ReasonCode != opened.ReasonCode || repeated.TriggerEventID != opened.TriggerEventID {
		t.Fatalf("repeated Trip() changed active incident: got %+v, want %+v", repeated, opened)
	}
}

func TestRecoveryRequiresApprovalAndReadOnlyHalfOpenProbe(t *testing.T) {
	now := testTime()
	closed, _ := NewClosed(runScope(), now)
	opened, _ := closed.Trip("POLICY_BYPASS", "event-001", now.Add(time.Second))

	if got, err := opened.BeginRecovery("", now.Add(2*time.Second)); err == nil || got.State != StateOpen {
		t.Fatalf("BeginRecovery(empty) = %+v, %v; want rejection", got, err)
	}

	halfOpen, err := opened.BeginRecovery("approval-001", now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("BeginRecovery() error = %v", err)
	}
	if halfOpen.State != StateHalfOpen || halfOpen.Epoch <= opened.Epoch {
		t.Fatalf("BeginRecovery() = %+v, want HALF_OPEN with advanced epoch", halfOpen)
	}
	if err := halfOpen.Check(halfOpen.Epoch, EffectReadOnly); err != nil {
		t.Fatalf("HALF_OPEN read-only Check() error = %v", err)
	}
	if err := halfOpen.Check(halfOpen.Epoch, EffectReversibleWrite); !errors.Is(err, ErrReadOnlyProbeOnly) {
		t.Fatalf("HALF_OPEN write Check() error = %v, want ErrReadOnlyProbeOnly", err)
	}
	if _, err := halfOpen.CompleteRecovery("wrong-approval", "evidence-001", now.Add(4*time.Second)); !errors.Is(err, ErrApprovalMismatch) {
		t.Fatalf("CompleteRecovery(wrong approval) error = %v, want ErrApprovalMismatch", err)
	}
	if _, err := halfOpen.CompleteRecovery("approval-001", "", now.Add(4*time.Second)); err == nil {
		t.Fatal("CompleteRecovery(empty evidence) error = nil, want rejection")
	}
	recovered, err := halfOpen.CompleteRecovery("approval-001", "evidence-001", now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("CompleteRecovery() error = %v", err)
	}
	if recovered.State != StateClosed || recovered.Epoch <= halfOpen.Epoch ||
		recovered.LastRecoveryEvidenceRef != "evidence-001" {
		t.Fatalf("CompleteRecovery() = %+v, want CLOSED with recovery evidence", recovered)
	}
	if err := recovered.Check(recovered.Epoch, EffectIrreversibleWrite); err != nil {
		t.Fatalf("CLOSED should not block policy-authorized operation: %v", err)
	}
	if err := recovered.Check(halfOpen.Epoch, EffectReadOnly); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("old HALF_OPEN worker check error = %v, want ErrStaleEpoch", err)
	}
}

func TestCriticalTripFromHalfOpenReturnsToOpenAndAdvancesEpoch(t *testing.T) {
	closed, _ := NewClosed(runScope(), testTime())
	opened, _ := closed.Trip("INITIAL_TRIGGER", "event-001", testTime().Add(time.Second))
	halfOpen, _ := opened.BeginRecovery("approval-001", testTime().Add(2*time.Second))

	reopened, err := halfOpen.Trip("PROBE_FAILED", "event-002", testTime().Add(3*time.Second))
	if err != nil {
		t.Fatalf("Trip() from HALF_OPEN error = %v", err)
	}
	if reopened.State != StateOpen || reopened.Epoch <= halfOpen.Epoch ||
		reopened.TriggerEventID != "event-002" {
		t.Fatalf("Trip() from HALF_OPEN = %+v, want new OPEN incident", reopened)
	}
}

func TestNewClosedRejectsInvalidScopeAndTime(t *testing.T) {
	for _, scope := range []Scope{
		{Kind: ScopeRun, ID: ""},
		{Kind: ScopeKind("UNKNOWN"), ID: "run-001"},
		{Kind: ScopeTenant, ID: " tenant-001"},
	} {
		if got, err := NewClosed(scope, testTime()); err == nil || got.State != "" {
			t.Fatalf("NewClosed(%+v) = %+v, %v; want rejection", scope, got, err)
		}
	}
	if got, err := NewClosed(runScope(), time.Time{}); err == nil || got.State != "" {
		t.Fatalf("NewClosed(zero time) = %+v, %v; want rejection", got, err)
	}
}
