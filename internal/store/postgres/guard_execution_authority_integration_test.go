package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

const guardAuthorityExecutionID = "11111111-2222-4333-8444-555555555551"

func runningPrincipalRun(t *testing.T) (*pgxpool.Pool, *postgres.Store, run.IntentReceipt) {
	t.Helper()
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='RUNNING',updated_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2::uuid", receipt.TenantID, receipt.RunID); err != nil {
		t.Fatal(err)
	}
	return pool, store, receipt
}

func TestGuardExecutionAuthorityReturnsOnlyCurrentAttemptAndTurn(t *testing.T) {
	_, store, receipt := runningPrincipalRun(t)
	ctx := context.Background()
	const missingTurn = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if got, err := store.GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, receipt.RunID, missingTurn); !errors.Is(err, run.ErrGuardExecutionAuthorityDenied) || got != (run.GuardExecutionAuthority{}) {
		t.Fatalf("missing Turn gained authority: %+v err=%v", got, err)
	}

	first, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID, receipt.WorkflowID, guardAuthorityExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, receipt.RunID, first.TurnID)
	if err != nil {
		t.Fatalf("first current Turn authority: %v", err)
	}
	if got.SchemaVersion != run.GuardExecutionAuthoritySchema ||
		got.TenantID != receipt.TenantID || got.RunID != receipt.RunID ||
		got.WorkflowID != receipt.WorkflowID || got.TemporalExecutionID != guardAuthorityExecutionID ||
		got.RunAttemptID != first.RunAttemptID || got.TurnID != first.TurnID ||
		got.InvocationID != first.InvocationID || got.TurnIndex != 1 ||
		got.AttemptGeneration != 1 || got.AttemptBreakerEpoch != 1 ||
		got.Status != string(run.StatusRunning) || got.BreakerState != "CLOSED" ||
		got.BreakerEpoch != 1 || got.BreakerVersion != 1 {
		t.Fatalf("wrong canonical Guard execution authority: %+v", got)
	}

	second, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID, receipt.WorkflowID, guardAuthorityExecutionID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if second.RunAttemptID != first.RunAttemptID || second.TurnID == first.TurnID {
		t.Fatalf("second Turn did not reuse the one current Attempt: first=%+v second=%+v", first, second)
	}
	if old, err := store.GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, receipt.RunID, first.TurnID); !errors.Is(err, run.ErrGuardExecutionAuthorityDenied) || old != (run.GuardExecutionAuthority{}) {
		t.Fatalf("superseded Turn retained current authority: %+v err=%v", old, err)
	}
	current, err := store.GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, receipt.RunID, second.TurnID)
	if err != nil || current.TurnID != second.TurnID || current.TurnIndex != 2 {
		t.Fatalf("latest persisted Turn did not resolve: %+v err=%v", current, err)
	}
	if wrongTenant, err := store.GetTrustedGuardExecutionAuthority(ctx, "other-tenant", receipt.RunID, second.TurnID); !errors.Is(err, run.ErrGuardExecutionAuthorityDenied) || wrongTenant != (run.GuardExecutionAuthority{}) {
		t.Fatalf("cross-tenant Turn authority leaked: %+v err=%v", wrongTenant, err)
	}
	if wrongRun, err := store.GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, "99999999-9999-4999-8999-999999999999", second.TurnID); !errors.Is(err, run.ErrGuardExecutionAuthorityDenied) || wrongRun != (run.GuardExecutionAuthority{}) {
		t.Fatalf("cross-Run Turn authority leaked: %+v err=%v", wrongRun, err)
	}
}

func TestGuardExecutionAuthorityRejectsAmbiguousAttempt(t *testing.T) {
	pool, store, receipt := runningPrincipalRun(t)
	ctx := context.Background()
	turn, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID, receipt.WorkflowID, guardAuthorityExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)`,
		receipt.TenantID, receipt.RunID, "33333333-3333-4333-8333-333333333332",
		receipt.WorkflowID, "11111111-2222-4333-8444-555555555552"); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, receipt.RunID, turn.TurnID); !errors.Is(err, run.ErrGuardExecutionAuthorityDenied) || got != (run.GuardExecutionAuthority{}) {
		t.Fatalf("ambiguous Attempt authority was returned: %+v err=%v", got, err)
	}
}

func TestGuardExecutionAuthorityRejectsBreakerVersionDriftAndTerminalRun(t *testing.T) {
	pool, store, receipt := runningPrincipalRun(t)
	ctx := context.Background()
	turn, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID, receipt.WorkflowID, guardAuthorityExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	disableBreakerTransitionTrigger(t, pool)
	if _, err := pool.Exec(ctx, `UPDATE runtime_circuit_breakers
		SET version=2,updated_at=clock_timestamp()
		WHERE scope_kind='RUN' AND scope_id=$1`, receipt.RunID); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, receipt.RunID, turn.TurnID); !errors.Is(err, run.ErrGuardExecutionAuthorityDenied) || got != (run.GuardExecutionAuthority{}) {
		t.Fatalf("version-drifted breaker authority was returned: %+v err=%v", got, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='CANCELLED',updated_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2::uuid", receipt.TenantID, receipt.RunID); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, receipt.RunID, turn.TurnID); !errors.Is(err, run.ErrGuardExecutionAuthorityDenied) || got != (run.GuardExecutionAuthority{}) {
		t.Fatalf("terminal Run authority was returned: %+v err=%v", got, err)
	}
}
