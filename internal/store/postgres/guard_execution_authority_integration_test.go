package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

func TestGuardExecutionAuthorityWorksWithSelectOnlyDatabaseRole(t *testing.T) {
	pool, _, receipt := runningPrincipalRun(t)
	ctx := context.Background()
	turn, err := postgres.New(pool).GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID, receipt.WorkflowID, guardAuthorityExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}

	schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		schema = "public"
	}
	role := "guard_ro_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := uuid.NewString()
	roleIdent := pgx.Identifier{role}.Sanitize()
	schemaIdent := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION",
		roleIdent, password,
	)); err != nil {
		t.Skipf("TEST_DATABASE_URL cannot create a least-privilege database role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP OWNED BY "+roleIdent)
		_, _ = pool.Exec(context.Background(), "DROP ROLE "+roleIdent)
	})
	if _, err := pool.Exec(ctx, "GRANT USAGE ON SCHEMA "+schemaIdent+" TO "+roleIdent); err != nil {
		t.Fatal(err)
	}
	tables := []string{
		"runs", "runtime_run_principal_snapshots", "runtime_run_attempts",
		"runtime_current_attempts", "runtime_decision_turns", "runtime_circuit_breakers",
	}
	qualified := make([]string, 0, len(tables))
	for _, table := range tables {
		qualified = append(qualified, pgx.Identifier{schema, table}.Sanitize())
	}
	if _, err := pool.Exec(ctx, "GRANT SELECT ON TABLE "+strings.Join(qualified, ",")+" TO "+roleIdent); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "ALTER ROLE "+roleIdent+" SET default_transaction_read_only=on"); err != nil {
		t.Fatal(err)
	}

	cfg, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = password
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readOnlyPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readOnlyPool.Close)
	if err := readOnlyPool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	var readOnly string
	if err := readOnlyPool.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
		t.Fatalf("Guard DB role transaction_read_only=%q err=%v", readOnly, err)
	}
	got, err := postgres.New(readOnlyPool).GetTrustedGuardExecutionAuthority(ctx, receipt.TenantID, receipt.RunID, turn.TurnID)
	if err != nil || got.RunAttemptID == "" || got.TurnID != turn.TurnID {
		t.Fatalf("SELECT-only role could not read Guard authority: %+v err=%v", got, err)
	}
	if _, err := readOnlyPool.Exec(ctx,
		"UPDATE runs SET status='CANCELLED' WHERE tenant_id=$1 AND run_id=$2::uuid",
		receipt.TenantID, receipt.RunID,
	); err == nil {
		t.Fatal("Guard database role unexpectedly mutated Runtime Run state")
	}
}
