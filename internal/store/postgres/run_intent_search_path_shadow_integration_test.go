package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newPgTempShadowPool(t *testing.T, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	cfg := pool.Config()
	cfg.MaxConns = 1
	shadow, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("create pg_temp shadow pool: %v", err)
	}
	t.Cleanup(shadow.Close)
	return shadow
}

func TestAcceptIntentWithPrincipalIgnoresPgTempRelationShadows(t *testing.T) {
	pool, _ := newTestStore(t)
	ctx := context.Background()
	shadowPool := newPgTempShadowPool(t, pool)
	if _, err := shadowPool.Exec(ctx, `
		CREATE TEMP TABLE runs (LIKE runs INCLUDING ALL);
		CREATE TEMP TABLE runtime_run_principal_snapshots (LIKE runtime_run_principal_snapshots INCLUDING ALL);
		CREATE TEMP TABLE runtime_outbox (LIKE runtime_outbox INCLUDING ALL)
	`); err != nil {
		t.Fatalf("create temporary authority shadows: %v", err)
	}

	receipt, err := postgres.New(shadowPool).AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatalf("accept through shadowed connection: %v", err)
	}
	if !receipt.Created || receipt.RunID == "" {
		t.Fatalf("acceptance did not return its canonical receipt: %+v", receipt)
	}

	var durableRuns, durablePrincipals, durableOutbox int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM runs WHERE run_intent_id=$1::uuid),
			(SELECT count(*) FROM runtime_run_principal_snapshots WHERE run_id=$2::uuid),
			(SELECT count(*) FROM runtime_outbox WHERE aggregate_id=$2::uuid AND event_type='RUN_START_REQUESTED')
	`, sampleIntentID, receipt.RunID).Scan(&durableRuns, &durablePrincipals, &durableOutbox); err != nil {
		t.Fatal(err)
	}
	if durableRuns != 1 || durablePrincipals != 1 || durableOutbox != 1 {
		t.Fatalf("pg_temp captured an accepted Run: durable rows=%d/%d/%d, want 1/1/1",
			durableRuns, durablePrincipals, durableOutbox)
	}
	var shadowRuns, shadowPrincipals, shadowOutbox int
	if err := shadowPool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM pg_temp.runs),
			(SELECT count(*) FROM pg_temp.runtime_run_principal_snapshots),
			(SELECT count(*) FROM pg_temp.runtime_outbox)
	`).Scan(&shadowRuns, &shadowPrincipals, &shadowOutbox); err != nil {
		t.Fatal(err)
	}
	if shadowRuns != 0 || shadowPrincipals != 0 || shadowOutbox != 0 {
		t.Fatalf("acceptance wrote into pg_temp shadows: %d/%d/%d", shadowRuns, shadowPrincipals, shadowOutbox)
	}
}

func TestLookupIntentWithPrincipalIgnoresPgTempPrincipalShadow(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command, principal := testIntent(), trustedSnapshot()
	if _, err := store.AcceptIntentWithPrincipal(ctx, command, principal); err != nil {
		t.Fatal(err)
	}

	shadowPool := newPgTempShadowPool(t, pool)
	if _, err := shadowPool.Exec(ctx, `
		CREATE TEMP TABLE runtime_run_principal_snapshots AS TABLE runtime_run_principal_snapshots;
		UPDATE runtime_run_principal_snapshots SET subject_id='forged-subject'
	`); err != nil {
		t.Fatalf("create forged temporary principal snapshot: %v", err)
	}
	forged := principal
	forged.SubjectID = "forged-subject"
	if receipt, err := postgres.New(shadowPool).LookupIntentWithPrincipal(ctx, command, forged); !errors.Is(err, run.ErrIdempotencyConflict) || receipt != (run.IntentReceipt{}) {
		t.Fatalf("pg_temp principal shadow spoofed trusted inspection: %+v %v", receipt, err)
	}
}

func TestLookupIntentIgnoresPgTempRunShadow(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}

	shadowPool := newPgTempShadowPool(t, pool)
	forgedDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := shadowPool.Exec(ctx, "CREATE TEMP TABLE runs AS TABLE runs"); err != nil {
		t.Fatalf("create temporary Run shadow: %v", err)
	}
	if _, err := shadowPool.Exec(ctx, "UPDATE pg_temp.runs SET source_request_digest=$1 WHERE run_intent_id=$2::uuid",
		forgedDigest, command.RunIntentID); err != nil {
		t.Fatalf("forge temporary Run digest: %v", err)
	}
	found, err := postgres.New(shadowPool).LookupIntent(ctx, command.TenantID, command.RunIntentID, forgedDigest)
	if !errors.Is(err, run.ErrIdempotencyConflict) || found != (run.IntentReceipt{}) {
		t.Fatalf("pg_temp Run shadow forged a durable lookup: %+v %v (canonical Run %s)", found, err, receipt.RunID)
	}
}


func TestGetRunPrincipalSnapshotIgnoresPgTempPrincipalShadow(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	shadowPool := newPgTempShadowPool(t, pool)
	if _, err := shadowPool.Exec(ctx, `
		CREATE TEMP TABLE runtime_run_principal_snapshots AS TABLE runtime_run_principal_snapshots;
		UPDATE runtime_run_principal_snapshots SET subject_id='forged-subject'
	`); err != nil {
		t.Fatalf("create forged principal shadow: %v", err)
	}
	got, err := postgres.New(shadowPool).GetRunPrincipalSnapshot(ctx, receipt.TenantID, receipt.RunID)
	if err != nil || got != trustedSnapshot() {
		t.Fatalf("temporary principal relation changed trusted snapshot: %+v %v", got, err)
	}
}

func TestClaimRuntimeStartIgnoresPgTempRelationShadows(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	shadowPool := newPgTempShadowPool(t, pool)
	for _, table := range []string{"runtime_outbox", "runs", "runtime_run_principal_snapshots"} {
		if _, err := shadowPool.Exec(ctx, "CREATE TEMP TABLE "+table+" (LIKE "+table+" INCLUDING ALL)"); err != nil {
			t.Fatalf("create empty pg_temp %s shadow: %v", table, err)
		}
	}
	lease, found, err := postgres.New(shadowPool).ClaimRuntimeStart(ctx, "shadow-worker", time.Minute)
	if err != nil || !found || lease.RunID != receipt.RunID {
		t.Fatalf("temporary relations hid or replaced durable start authority: %+v found=%v err=%v", lease, found, err)
	}
}

func TestAcknowledgeRuntimeStartIgnoresPgTempOutboxShadow(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	_, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	lease, found, err := store.ClaimRuntimeStart(ctx, "durable-worker", time.Minute)
	if err != nil || !found {
		t.Fatalf("claim durable start before shadow: %+v found=%v err=%v", lease, found, err)
	}
	shadowPool := newPgTempShadowPool(t, pool)
	if _, err := shadowPool.Exec(ctx, "CREATE TEMP TABLE runtime_outbox (LIKE runtime_outbox INCLUDING ALL)"); err != nil {
		t.Fatalf("create empty pg_temp Outbox shadow: %v", err)
	}
	if err := postgres.New(shadowPool).AcknowledgeRuntimeStart(ctx, lease); err != nil {
		t.Fatalf("ACK was redirected into pg_temp: %v", err)
	}
	var delivered int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_outbox WHERE outbox_id=$1::uuid AND delivered_at IS NOT NULL", lease.OutboxID).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Fatalf("durable Outbox was not acknowledged: %d", delivered)
	}
}

func TestCreateOrGetIgnoresPgTempRunAndOutboxShadows(t *testing.T) {
	pool, _ := newTestStore(t)
	ctx := context.Background()
	shadowPool := newPgTempShadowPool(t, pool)
	for _, table := range []string{"runs", "runtime_outbox"} {
		if _, err := shadowPool.Exec(ctx, "CREATE TEMP TABLE "+table+" (LIKE "+table+" INCLUDING ALL)"); err != nil {
			t.Fatalf("create empty pg_temp %s shadow: %v", table, err)
		}
	}
	candidateRun := candidate("00000000-0000-4000-8000-000000000701")
	created, isNew, err := postgres.New(shadowPool).CreateOrGet(ctx, candidateRun)
	if err != nil || !isNew || created.ID != candidateRun.ID {
		t.Fatalf("Run creation through shadowed pool: %+v new=%v err=%v", created, isNew, err)
	}
	var durableRuns, durableOutbox int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM runs WHERE run_id=$1::uuid), (SELECT count(*) FROM runtime_outbox WHERE aggregate_id=$1::uuid)", candidateRun.ID).Scan(&durableRuns, &durableOutbox); err != nil {
		t.Fatal(err)
	}
	if durableRuns != 1 || durableOutbox != 1 {
		t.Fatalf("pg_temp captured generic Run creation: %d/%d", durableRuns, durableOutbox)
	}
}
