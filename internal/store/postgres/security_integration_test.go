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

	if _, err := pool.Exec(ctx, `TRUNCATE runtime_security_audit_events`); err == nil {
		t.Fatal("audit TRUNCATE unexpectedly succeeded")
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

// A database that already recorded migration v4 must receive the TRUNCATE
// protection on upgrade; editing the v4 SQL cannot repair an applied database.
func TestSecurityAuditTruncateGuardUpgradesPreviouslyAppliedV4(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()

	// Reproduce a database genuinely stopped at v4, not merely a v5
	// ledger gap while the newer v6 Outbox lease schema remains installed.
	for _, sql := range []string{
		"DROP INDEX runtime_outbox_start_claim_idx",
		"ALTER TABLE runtime_outbox DROP CONSTRAINT runtime_start_lease_pair",
		"ALTER TABLE runtime_outbox DROP COLUMN lease_owner, DROP COLUMN lease_expires_at",
		"DELETE FROM runtime_schema_migrations WHERE version = 6",
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("simulate original v4 state: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER runtime_security_audit_no_truncate ON runtime_security_audit_events`); err != nil {
		t.Fatalf("simulate original v4 schema without TRUNCATE guard: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM runtime_schema_migrations WHERE version = 5`); err != nil {
		t.Fatalf("simulate original applied-v4 version ledger: %v", err)
	}
	var version int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM runtime_schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Fatalf("migration version before upgrade = %d, want 4", version)
	}

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("upgrade existing v4 schema: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM runtime_schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 6 {
		t.Fatalf("migration version after v4-to-latest upgrade = %d, want 6", version)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE runtime_security_audit_events`); err == nil {
		t.Fatal("previously applied v4 database still permits audit TRUNCATE")
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("repeat migration v5: %v", err)
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
	pool, store := newTestStore(t)
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
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_security_audit_events
		WHERE tenant_id=$1 AND event_id=$2
	`, event.Identity.TenantID(), event.EventID).Scan(&count); err != nil {
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

func TestGetRunBreakerRequiresTenantOwnership(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntent(ctx, testIntent())
	if err != nil {
		t.Fatalf("AcceptIntent(): %v", err)
	}

	owned, err := store.GetRunBreaker(ctx, "tenant-1", receipt.RunID)
	if err != nil {
		t.Fatalf("owner GetRunBreaker(): %v", err)
	}
	if owned.Scope.Kind != breaker.ScopeRun || owned.Scope.ID != receipt.RunID {
		t.Fatalf("owner breaker scope = %+v", owned.Scope)
	}

	if _, err := store.GetRunBreaker(ctx, "tenant-2", receipt.RunID); !errors.Is(err, postgres.ErrBreakerNotFound) {
		t.Fatalf("cross-tenant GetRunBreaker() error = %v, want ErrBreakerNotFound", err)
	}
}

func TestRunInsertTriggerCreatesClosedBreakerForDirectSQLWriter(t *testing.T) {
	pool, _ := newTestStore(t)
	ctx := context.Background()
	runCandidate := candidate("00000000-0000-4000-8000-000000000099")
	_, err := pool.Exec(ctx, `
		INSERT INTO runs (
			run_id, tenant_id, agent_id, agent_release_id, session_id,
			idempotency_key, request_digest, workflow_id, status, input,
			created_at, updated_at
		) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12)
	`, runCandidate.ID, runCandidate.TenantID, runCandidate.AgentID,
		runCandidate.AgentReleaseID, runCandidate.SessionID, runCandidate.IdempotencyKey,
		runCandidate.RequestDigest, runCandidate.WorkflowID, string(runCandidate.Status),
		string(runCandidate.Input), runCandidate.CreatedAt, runCandidate.UpdatedAt)
	if err != nil {
		t.Fatalf("direct Run insert: %v", err)
	}
	var state string
	var epoch, version uint64
	if err := pool.QueryRow(ctx, `
		SELECT state, epoch, version FROM runtime_circuit_breakers
		WHERE scope_kind='RUN' AND scope_id=$1
	`, runCandidate.ID).Scan(&state, &epoch, &version); err != nil {
		t.Fatalf("Run insert trigger did not create breaker: %v", err)
	}
	if state != "CLOSED" || epoch != 1 || version != 1 {
		t.Fatalf("trigger-created breaker = %s/%d/%d, want CLOSED/1/1", state, epoch, version)
	}
}

func TestSecurityMigrationV4RollsBackAtomically(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()

	// Return the isolated schema to the v3 shape, then install a conflicting
	// breaker relation so migration v4 fails after creating its audit objects.
	for _, statement := range []string{
		"DROP TRIGGER runs_create_initial_breaker ON runs",
		"DROP FUNCTION create_initial_run_breaker()",
		"DROP TABLE runtime_circuit_breakers",
		"DROP TABLE runtime_security_audit_events",
		"DROP FUNCTION reject_runtime_security_audit_mutation()",
		"DELETE FROM runtime_schema_migrations WHERE version = 4",
		"CREATE TABLE runtime_circuit_breakers (conflict_marker TEXT)",
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("prepare v3 schema with %q: %v", statement, err)
		}
	}

	if err := store.Migrate(ctx); err == nil {
		t.Fatal("Migrate() succeeded despite conflicting v4 breaker relation")
	}

	for name, query := range map[string]string{
		"v4 schema ledger": `
			SELECT EXISTS (
				SELECT 1 FROM runtime_schema_migrations WHERE version = 4
			)
		`,
		"audit table": `
			SELECT to_regclass('runtime_security_audit_events') IS NOT NULL
		`,
		"audit mutation function": `
			SELECT to_regprocedure('reject_runtime_security_audit_mutation()') IS NOT NULL
		`,
		"Run breaker trigger": `
			SELECT EXISTS (
				SELECT 1 FROM pg_trigger
				WHERE tgname = 'runs_create_initial_breaker'
				  AND NOT tgisinternal
			)
		`,
		"Run breaker trigger function": `
			SELECT to_regprocedure('create_initial_run_breaker()') IS NOT NULL
		`,
	} {
		var exists bool
		if err := pool.QueryRow(ctx, query).Scan(&exists); err != nil {
			t.Fatalf("inspect %s after failed migration: %v", name, err)
		}
		if exists {
			t.Errorf("%s survived failed migration; expected transaction rollback", name)
		}
	}

	var conflictTableExists bool
	if err := pool.QueryRow(ctx, `
		SELECT to_regclass('runtime_circuit_breakers') IS NOT NULL
	`).Scan(&conflictTableExists); err != nil {
		t.Fatalf("inspect conflicting relation: %v", err)
	}
	if !conflictTableExists {
		t.Fatal("pre-existing conflicting relation was removed by failed migration")
	}
}
