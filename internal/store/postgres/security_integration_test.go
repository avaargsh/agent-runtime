package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/audit"
	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/securitycontext"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func securityAuditEvent() audit.Event {
	identity, _ := securitycontext.New(securitycontext.Claims{
		TenantID:       "tenant-security-1",
		SubjectID:      "user-security-1",
		ActorID:        "actor-security-1",
		AgentID:        "agent-security-1",
		AgentReleaseID: "release-security-1",
		SessionID:      "session-security-1",
		RunID:          "run-security-1",
		RunAttemptID:   "attempt-security-1",
		TurnID:         "turn-security-1",
		PolicyRevision: "policy-security-1",
	})
	return audit.Event{
		EventID:       "event-security-001",
		OccurredAt:    time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Type:          audit.EventToolCallStarted,
		Identity:      identity,
		Source:        "trusted-tool-adapter",
		TraceID:       "trace-security-001",
		Action:        "shell.execute",
		Resource:      "workspace/project",
		ProposalID:    "proposal-security-001",
		ToolCallID:    "tool-call-security-001",
		Outcome:       audit.OutcomeDispatched,
		PayloadDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func TestSecurityAuditAppendIsIdempotentAndAppendOnly(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	event := securityAuditEvent()

	if err := store.Append(ctx, event); err != nil {
		t.Fatalf("first Append() error = %v", err)
	}
	if err := store.Append(ctx, event); err != nil {
		t.Fatalf("idempotent Append() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_security_audit_events
		WHERE tenant_id=$1 AND event_id=$2
	`, event.Identity.TenantID(), event.EventID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit event count = %d, want 1 after replay", count)
	}

	changed := event
	changed.Source = "different-trusted-adapter"
	if err := store.Append(ctx, changed); !errors.Is(err, postgres.ErrAuditEventConflict) {
		t.Fatalf("reused event ID with changed content error = %v, want ErrAuditEventConflict", err)
	}

	for _, statement := range []string{
		`UPDATE runtime_security_audit_events SET source='tampered' WHERE tenant_id=$1 AND event_id=$2`,
		`DELETE FROM runtime_security_audit_events WHERE tenant_id=$1 AND event_id=$2`,
	} {
		if _, err := pool.Exec(ctx, statement, event.Identity.TenantID(), event.EventID); err == nil {
			t.Fatalf("audit mutation unexpectedly succeeded: %s", statement)
		}
	}

	var source, runID, proposalID, toolCallID, traceID string
	if err := pool.QueryRow(ctx, `
		SELECT source, run_id, proposal_id, tool_call_id, trace_id
		FROM runtime_security_audit_events
		WHERE tenant_id=$1 AND event_id=$2
	`, event.Identity.TenantID(), event.EventID).Scan(&source, &runID, &proposalID, &toolCallID, &traceID); err != nil {
		t.Fatal(err)
	}
	if source != event.Source || runID != event.Identity.RunID() ||
		proposalID != event.ProposalID || toolCallID != event.ToolCallID || traceID != event.TraceID {
		t.Fatalf("stored audit correlation mismatch: source=%q run=%q proposal=%q tool=%q trace=%q",
			source, runID, proposalID, toolCallID, traceID)
	}
}

func TestCircuitBreakerPostgresCreateTransitionAndStaleWriterConflict(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 4, 13, 0, 0, 0, time.UTC)
	scope := breaker.Scope{Kind: breaker.ScopeRun, ID: "run-breaker-001"}

	initial, err := breaker.NewClosed(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, 0, initial); err != nil {
		t.Fatalf("create breaker record: %v", err)
	}
	loaded, err := store.GetBreaker(ctx, scope)
	if err != nil {
		t.Fatalf("GetBreaker() after create: %v", err)
	}
	if loaded.State != breaker.StateClosed || loaded.Version != 1 || loaded.Epoch != 1 {
		t.Fatalf("unexpected initial breaker record: %+v", loaded)
	}

	staleSnapshot := loaded
	opened, err := loaded.Trip("CREDENTIAL_EXFILTRATION", "event-security-002", now.Add(time.Second))
	if err != nil {
		t.Fatalf("Trip(): %v", err)
	}
	if err := store.CompareAndSwapBreaker(ctx, loaded.Version, opened); err != nil {
		t.Fatalf("persist OPEN transition: %v", err)
	}

	staleWrite, err := staleSnapshot.Trip("POLICY_BYPASS", "event-security-003", now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("stale snapshot Trip(): %v", err)
	}
	if err := store.CompareAndSwapBreaker(ctx, staleSnapshot.Version, staleWrite); !errors.Is(err, postgres.ErrBreakerVersionConflict) {
		t.Fatalf("stale breaker write error = %v, want ErrBreakerVersionConflict", err)
	}

	persisted, err := store.GetBreaker(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != breaker.StateOpen || persisted.Epoch != opened.Epoch ||
		persisted.TriggerEventID != "event-security-002" || persisted.Version != opened.Version {
		t.Fatalf("stale writer overwrote canonical breaker: %+v", persisted)
	}

	halfOpen, err := persisted.BeginRecovery("approval-security-001", now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("BeginRecovery(): %v", err)
	}
	if err := store.CompareAndSwapBreaker(ctx, persisted.Version, halfOpen); err != nil {
		t.Fatalf("persist HALF_OPEN transition: %v", err)
	}

	recovered, err := halfOpen.CompleteRecovery(
		"approval-security-001", "evidence://security/recovery-001", now.Add(4*time.Second),
	)
	if err != nil {
		t.Fatalf("CompleteRecovery(): %v", err)
	}
	if err := store.CompareAndSwapBreaker(ctx, halfOpen.Version, recovered); err != nil {
		t.Fatalf("persist CLOSED recovery: %v", err)
	}

	final, err := store.GetBreaker(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != breaker.StateClosed || final.Epoch != recovered.Epoch ||
		final.Version != recovered.Version || final.LastRecoveryEvidenceRef != "evidence://security/recovery-001" {
		t.Fatalf("recovered breaker did not persist approval evidence: %+v", final)
	}
}

func TestCircuitBreakerPostgresTenantAndAgentScopesAreIndependent(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 4, 14, 0, 0, 0, time.UTC)
	for _, scope := range []breaker.Scope{
		{Kind: breaker.ScopeTenant, ID: "tenant-001"},
		{Kind: breaker.ScopeAgentInstance, ID: "agent-instance-001"},
	} {
		record, err := breaker.NewClosed(scope, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CompareAndSwapBreaker(ctx, 0, record); err != nil {
			t.Fatalf("create %s breaker: %v", scope.Kind, err)
		}
		loaded, err := store.GetBreaker(ctx, scope)
		if err != nil {
			t.Fatalf("load %s breaker: %v", scope.Kind, err)
		}
		if loaded.Scope != scope {
			t.Fatalf("loaded scope = %+v, want %+v", loaded.Scope, scope)
		}
	}
}

func TestTransitionBreakerWithAuditIsAtomicAndIdempotent(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 4, 15, 0, 0, 0, time.UTC)
	scope := breaker.Scope{Kind: breaker.ScopeRun, ID: "run-security-1"}

	initial, err := breaker.NewClosed(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, 0, initial); err != nil {
		t.Fatalf("create breaker: %v", err)
	}
	opened, err := initial.Trip("CREDENTIAL_EXFILTRATION", "event-trigger-1", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	event := securityAuditEvent()
	event.EventID = "event-breaker-trip-atomic"
	event.Type = audit.EventBreakerTripped
	event.OccurredAt = now.Add(time.Second)
	event.ReasonCode = "CREDENTIAL_EXFILTRATION"
	event.Action = "breaker.trip"
	event.Outcome = audit.OutcomeDenied
	event.BreakerEpoch = opened.Epoch

	if err := store.TransitionBreakerWithAudit(ctx, initial.Version, opened, event); err != nil {
		t.Fatalf("atomic breaker transition: %v", err)
	}
	// Replaying the same command after a lost acknowledgement must be harmless.
	if err := store.TransitionBreakerWithAudit(ctx, initial.Version, opened, event); err != nil {
		t.Fatalf("idempotent transition replay: %v", err)
	}

	persisted, err := store.GetBreaker(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != breaker.StateOpen || persisted.Epoch != opened.Epoch || persisted.Version != opened.Version {
		t.Fatalf("persisted breaker = %+v, want %+v", persisted, opened)
	}
	var count int
	if err := store.poolQueryCountForTest(ctx, event.Identity.TenantID(), event.EventID, &count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit row count = %d, want 1", count)
	}
}

func TestTransitionBreakerWithAuditRollsBackStateWhenAuditAppendFails(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 4, 16, 0, 0, 0, time.UTC)
	scope := breaker.Scope{Kind: breaker.ScopeRun, ID: "run-security-1"}

	initial, err := breaker.NewClosed(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, 0, initial); err != nil {
		t.Fatalf("create breaker: %v", err)
	}
	opened, err := initial.Trip("POLICY_BYPASS", "event-trigger-2", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	event := securityAuditEvent()
	event.EventID = "event-breaker-trip-fail"
	event.Type = audit.EventBreakerTripped
	event.OccurredAt = now.Add(time.Second)
	event.ReasonCode = "POLICY_BYPASS"
	event.Action = "breaker.trip"
	event.Outcome = audit.OutcomeDenied
	event.BreakerEpoch = opened.Epoch

	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION reject_security_audit_event() RETURNS trigger
		LANGUAGE plpgsql AS 'BEGIN
			IF NEW.event_id = ''event-breaker-trip-fail'' THEN
				RAISE EXCEPTION ''forced audit append failure'';
			END IF;
			RETURN NEW;
		END;'
	`); err != nil {
		t.Fatalf("create audit failure function: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TRIGGER reject_security_audit_event
		BEFORE INSERT ON runtime_security_audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_security_audit_event()
	`); err != nil {
		t.Fatalf("install audit failure trigger: %v", err)
	}

	if err := store.TransitionBreakerWithAudit(ctx, initial.Version, opened, event); err == nil {
		t.Fatal("TransitionBreakerWithAudit() succeeded despite forced audit failure")
	}
	persisted, err := store.GetBreaker(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != breaker.StateClosed || persisted.Version != initial.Version || persisted.Epoch != initial.Epoch {
		t.Fatalf("audit failure left a partial breaker transition: %+v", persisted)
	}
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_security_audit_events WHERE event_id=$1
	`, event.EventID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed transaction left %d audit rows, want 0", count)
	}
}

func TestCompareAndSwapBreakerRejectsInvalidStateTransition(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC)
	scope := breaker.Scope{Kind: breaker.ScopeRun, ID: "run-security-1"}
	initial, err := breaker.NewClosed(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, 0, initial); err != nil {
		t.Fatal(err)
	}
	fabricated := initial
	fabricated.Epoch++
	fabricated.Version++
	fabricated.UpdatedAt = now.Add(time.Second)
	if err := store.CompareAndSwapBreaker(ctx, initial.Version, fabricated); !errors.Is(err, postgres.ErrBreakerVersionConflict) {
		t.Fatalf("same-state CAS error = %v, want ErrBreakerVersionConflict", err)
	}
}

func (s *Store) poolQueryCountForTest(ctx context.Context, tenantID, eventID string, count *int) error {
	return s.pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_security_audit_events
		WHERE tenant_id=$1 AND event_id=$2
	`, tenantID, eventID).Scan(count)
}
