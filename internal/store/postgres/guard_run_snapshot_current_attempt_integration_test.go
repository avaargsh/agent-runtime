package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// Guard's authenticated network-facing safety read must not treat a RUNNING
// Run as executable without the Runtime-owned current Attempt pointer.
// The diagnostic reader remains independent of authorization decisions.
func TestTrustedGuardRunSafetyRequiresCurrentAttemptAndMatchingBreakerEpoch(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE runs SET status='RUNNING',updated_at=now() WHERE run_id=$1::uuid", receipt.RunID); err != nil {
		t.Fatal(err)
	}

	// RED on the old implementation: a RUNNING Run with no Attempt pointer
	// incorrectly passes the trusted Guard projection.
	if _, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); !errors.Is(err, run.ErrInvalidIdentity) {
		t.Fatalf("trusted Guard read accepted RUNNING Run with no current Attempt: %v", err)
	}
	if diagnostic, err := store.GetGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); err != nil || diagnostic.Status != run.StatusRunning {
		t.Fatalf("diagnostic Run read unexpectedly changed: %+v err=%v", diagnostic, err)
	}

	// Create an actual persisted Attempt via the canonical Runtime writer.
	turn, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil || turn.AttemptGeneration != 1 || turn.BreakerEpoch != 1 {
		t.Fatalf("canonical current Attempt unavailable: %+v err=%v", turn, err)
	}
	authorized, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID)
	if err != nil || !authorized.EligibleForGuardSubmission() {
		t.Fatalf("valid current Attempt must allow only Guard's prerequisite safety read: %+v err=%v", authorized, err)
	}

	// Simulate successful breaker recovery: the stale Attempt remains
	// generation=1/epoch=1 and must not silently regain authority.
	if _, err := pool.Exec(ctx, `UPDATE runtime_circuit_breakers
		SET epoch=2,version=2,updated_at=now()
		WHERE scope_kind='RUN' AND scope_id=$1`, receipt.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); !errors.Is(err, run.ErrInvalidIdentity) {
		t.Fatalf("trusted Guard read accepted stale Attempt after breaker epoch changed: %v", err)
	}
}

// V8 permits multiple immutable Attempts for a Run. The v13 generation-one
// pointer is not an authorization shortcut when a second persisted Attempt
// makes the identity ambiguous. This must fail closed before Guard admission
// without deleting historical evidence or changing the diagnostic reader.
func TestTrustedGuardRunSafetyRejectsAmbiguousPersistedAttempt(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE runs SET status='RUNNING',updated_at=now() WHERE tenant_id=$1 AND run_id=$2::uuid",
		receipt.TenantID, receipt.RunID); err != nil {
		t.Fatal(err)
	}
	current, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if initial, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); err != nil || !initial.EligibleForGuardSubmission() {
		t.Fatalf("single current Attempt should pass the Guard precondition: %+v err=%v", initial, err)
	}

	// Fixture SQL simulates an inconsistent durable second execution; it is
	// never a public command to allocate or authorize another Attempt.
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)`,
		receipt.TenantID, receipt.RunID, "33333333-3333-4333-8333-333333333332",
		receipt.WorkflowID, secondTemporalExecutionID); err != nil {
		t.Fatal(err)
	}
	if result, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); !errors.Is(err, run.ErrInvalidIdentity) || result.EligibleForGuardSubmission() {
		t.Fatalf("ambiguous persisted Attempts passed trusted Guard safety: %+v err=%v", result, err)
	}
	if diagnostic, err := store.GetGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); err != nil || diagnostic.Status != run.StatusRunning {
		t.Fatalf("diagnostic historical Run projection changed: %+v err=%v", diagnostic, err)
	}
	var attempts, pointers, turns int
	var authority string
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM runtime_run_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
			(SELECT count(*) FROM runtime_current_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
			(SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid),
			(SELECT attempt_id::text FROM runtime_current_attempts WHERE tenant_id=$1 AND run_id=$2::uuid)`,
		receipt.TenantID, receipt.RunID).Scan(&attempts, &pointers, &turns, &authority); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || pointers != 1 || turns != 1 || authority != current.RunAttemptID {
		t.Fatalf("read-only rejection changed historical identity: attempts=%d pointers=%d turns=%d pointer=%s", attempts, pointers, turns, authority)
	}
}

// A changed RUN breaker version with the original epoch is not an initial
// authority snapshot: Temporal Turn binding already rejects the same state.
// Guard's trusted safety read must not disagree even if privileged test DML
// leaves a malformed CLOSED/epoch-one breaker in durable storage.
func TestTrustedGuardRunSafetyRejectsBreakerVersionDrift(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE runs SET status='RUNNING',updated_at=now() WHERE tenant_id=$1 AND run_id=$2::uuid",
		receipt.TenantID, receipt.RunID); err != nil {
		t.Fatal(err)
	}
	turn, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil || turn.AttemptGeneration != 1 || turn.BreakerEpoch != 1 {
		t.Fatalf("canonical initial Attempt missing: %+v err=%v", turn, err)
	}
	before, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID)
	if err != nil || !before.EligibleForGuardSubmission() || before.BreakerVersion != 1 {
		t.Fatalf("untampered initial Breaker must pass prerequisite: %+v err=%v", before, err)
	}
	// Simulate inconsistent durable breaker state via privileged fixture SQL.
	// Supported breaker transitions increase epoch along with version.
	if _, err := pool.Exec(ctx, `UPDATE runtime_circuit_breakers
		SET version=2,updated_at=clock_timestamp()
		WHERE scope_kind='RUN' AND scope_id=$1`, receipt.RunID); err != nil {
		t.Fatal(err)
	}
	if result, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); !errors.Is(err, run.ErrInvalidIdentity) || result.EligibleForGuardSubmission() {
		t.Fatalf("version-drifted breaker passed trusted Guard safety: %+v err=%v", result, err)
	}
	if diagnostic, err := store.GetGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); err != nil ||
		diagnostic.Status != run.StatusRunning || diagnostic.BreakerEpoch != 1 || diagnostic.BreakerVersion != 2 {
		t.Fatalf("diagnostic read unexpectedly lost durable evidence: %+v err=%v", diagnostic, err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID,
		receipt.WorkflowID, firstTemporalExecutionID, 2); !errors.Is(err, postgres.ErrTemporalTurnUntrustedRun) {
		t.Fatalf("Temporal Turn accepted the same stale breaker version: %v", err)
	}
	var attempts, pointers, turns int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM runtime_run_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
		(SELECT count(*) FROM runtime_current_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
		(SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid)
	`, receipt.TenantID, receipt.RunID).Scan(&attempts, &pointers, &turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || pointers != 1 || turns != 1 {
		t.Fatalf("denial mutated immutable history: attempts=%d pointers=%d turns=%d", attempts, pointers, turns)
	}
}
