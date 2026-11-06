package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A connection-scoped temp table precedes the regular schema for unqualified
// relation names even when the configured search_path points to the correct
// schema. The claim writer must never use that untrusted temp relation.
func TestHarnessClaimIgnoresPgTempShadowAndUpdatesPermanentRelation(t *testing.T) {
	pool, _, claim := harnessFixture(t)
	ctx := context.Background()
	cfg := pool.Config()
	cfg.MaxConns = 1
	shadowPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer shadowPool.Close()

	// Copies the PK and indexes but NOT the append-only protection triggers.
	// An unqualified INSERT can otherwise succeed entirely in pg_temp.
	if _, err := shadowPool.Exec(ctx, `
		CREATE TEMP TABLE runtime_harness_session_claims
		(LIKE runtime_harness_session_claims INCLUDING ALL)
	`); err != nil {
		t.Fatalf("create temp table shadow: %v", err)
	}
	shadowStore := postgres.New(shadowPool)
	first, err := shadowStore.ClaimHarnessSession(ctx, claim)
	if err != nil || !first.Created || first.State != acp.ClaimPrepared {
		t.Fatalf("permanent claim required: %+v %v", first, err)
	}
	var durable int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_harness_session_claims
		WHERE tenant_id=$1 AND run_id=$2::uuid
	`, claim.TenantID, claim.RunID).Scan(&durable); err != nil {
		t.Fatal(err)
	}
	if durable != 1 {
		t.Fatalf("claim redirected into pg_temp: permanent rows=%d, want 1", durable)
	}
	if ok, err := shadowStore.BeginHarnessSessionDispatch(ctx, claim); err != nil || !ok {
		t.Fatalf("must CAS permanent claim: %t %v", ok, err)
	}
	var permanentState string
	if err := pool.QueryRow(ctx, `
		SELECT state FROM runtime_harness_session_claims
		WHERE tenant_id=$1 AND run_id=$2::uuid
	`, claim.TenantID, claim.RunID).Scan(&permanentState); err != nil {
		t.Fatal(err)
	}
	if permanentState != string(acp.ClaimUnknown) {
		t.Fatalf("dispatch bypassed permanent UNKNOWN fence: %q", permanentState)
	}
	rec, err := shadowStore.ConfirmHarnessSession(ctx, claim, "agent-session-1")
	if err != nil || rec.State != acp.ClaimConfirmed {
		t.Fatalf("confirm must write permanent row: %+v %v", rec, err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT state FROM runtime_harness_session_claims
		WHERE tenant_id=$1 AND run_id=$2::uuid
	`, claim.TenantID, claim.RunID).Scan(&permanentState); err != nil {
		t.Fatal(err)
	}
	if permanentState != string(acp.ClaimConfirmed) {
		t.Fatalf("confirmation bypassed permanent claim row: %q", permanentState)
	}
}

func TestHarnessClaimRejectsPgTempShadowedRunAuthority(t *testing.T) {
	pool, _, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		UPDATE runs SET status='CANCELLED', updated_at=now()
		WHERE tenant_id=$1 AND run_id=$2::uuid
	`, claim.TenantID, claim.RunID); err != nil {
		t.Fatal(err)
	}

	cfg := pool.Config()
	cfg.MaxConns = 1
	shadowPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer shadowPool.Close()
	// The fake Run is RUNNING while the authoritative permanent Run is
	// CANCELLED; an unqualified FROM runs can incorrectly grant a claim.
	if _, err := shadowPool.Exec(ctx, `
		CREATE TEMP TABLE runs AS TABLE runs;
		UPDATE runs SET status='RUNNING'
	`); err != nil {
		t.Fatalf("create temp Run authority shadow: %v", err)
	}

	if record, err := postgres.New(shadowPool).ClaimHarnessSession(ctx, claim); !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("cancelled Run created a claim through pg_temp authority: %+v %v", record, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_harness_session_claims
		WHERE tenant_id=$1 AND run_id=$2::uuid
	`, claim.TenantID, claim.RunID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("claim created for cancelled authoritative Run: %d", count)
	}
}

func TestHarnessClaimRejectsAmbiguousStartupSearchPath(t *testing.T) {
	pool, _, claim := harnessFixture(t)
	cfg := pool.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = "pg_temp,public"
	badPool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer badPool.Close()
	record, err := postgres.New(badPool).ClaimHarnessSession(context.Background(), claim)
	if !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("ambiguous configured schema accepted: %+v %v", record, err)
	}
}
