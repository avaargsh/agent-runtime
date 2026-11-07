package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func harnessFixture(t *testing.T) (*pgxpool.Pool, *postgres.Store, acp.SessionClaim) {
	t.Helper()
	pool, store := newTestStore(t)
	receipt, err := store.AcceptIntentWithPrincipal(context.Background(), testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		"UPDATE runs SET status='RUNNING', updated_at=now() WHERE tenant_id=$1 AND run_id=$2::uuid",
		"tenant-1", receipt.RunID); err != nil {
		t.Fatal(err)
	}
	return pool, store, acp.SessionClaim{
		TenantID: "tenant-1", RunID: receipt.RunID,
		AttemptID:         "22222222-2222-4222-8222-222222222222",
		HarnessInstanceID: "worker-codex-1", AgentReleaseID: "release-1",
		PolicyRevision: trustedSnapshot().PolicyRevision, RequestDigest: "sha256:" + strings.Repeat("a", 64),
		WorkingDir: "/workspace/project",
	}
}

func TestHarnessSessionClaimConcurrentSingleDispatch(t *testing.T) {
	_, store, claim := harnessFixture(t)
	ctx := context.Background()
	const workers = 12
	type outcome struct {
		record acp.SessionClaimRecord
		err    error
	}
	results := make(chan outcome, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, err := store.ClaimHarnessSession(ctx, claim)
			results <- outcome{rec, err}
		}()
	}
	wg.Wait()
	close(results)
	created := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.record.State != acp.ClaimPrepared {
			t.Fatalf("unexpected claim state: %+v", result.record)
		}
		if result.record.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created %d claims, want 1", created)
	}
	dispatch := make(chan bool, workers)
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.BeginHarnessSessionDispatch(ctx, claim)
			dispatch <- ok
			errs <- err
		}()
	}
	wg.Wait()
	close(dispatch)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	count := 0
	for ok := range dispatch {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("dispatch grants = %d, want 1", count)
	}
	got, err := store.ReadHarnessSessionClaim(ctx, claim)
	if err != nil || got.State != acp.ClaimUnknown || got.AgentSessionID != "" {
		t.Fatalf("dispatch must persist uncertainty: %+v %v", got, err)
	}
}

func TestHarnessClaimLostACKAndStoreRestartNeverReauthorizesDispatch(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx := context.Background()
	first, err := store.ClaimHarnessSession(ctx, claim)
	if err != nil || !first.Created {
		t.Fatalf("claim: %+v %v", first, err)
	}
	if ok, err := store.BeginHarnessSessionDispatch(ctx, claim); err != nil || !ok {
		t.Fatalf("begin: %t %v", ok, err)
	}
	// The handler never receives session/new's ACK. Recreated store has only
	// PostgreSQL evidence; it must not issue another dispatch grant.
	again := postgres.New(pool)
	second, err := again.ClaimHarnessSession(ctx, claim)
	if err != nil || second.State != acp.ClaimUnknown || second.Created {
		t.Fatalf("lost-ACK replay: %+v %v", second, err)
	}
	if ok, err := again.BeginHarnessSessionDispatch(ctx, claim); err != nil || ok {
		t.Fatalf("unknown dispatch retried: %t %v", ok, err)
	}
}

func TestHarnessClaimChangedBindingsAndMissingAuthorityFailClosed(t *testing.T) {
	_, store, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name   string
		change func(*acp.SessionClaim)
	}{
		{"attempt", func(c *acp.SessionClaim) { c.AttemptID = "33333333-3333-4333-8333-333333333333" }},
		{"harness", func(c *acp.SessionClaim) { c.HarnessInstanceID = "worker-claude-2" }},
		{"release", func(c *acp.SessionClaim) { c.AgentReleaseID = "release-2" }},
		{"policy", func(c *acp.SessionClaim) { c.PolicyRevision = "policy-rev-2" }},
		{"digest", func(c *acp.SessionClaim) { c.RequestDigest = "sha256:" + strings.Repeat("b", 64) }},
		{"cwd", func(c *acp.SessionClaim) { c.WorkingDir = "/other-dir" }},
		{"tenant", func(c *acp.SessionClaim) { c.TenantID = "tenant-2" }},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			mutated := claim
			tc.change(&mutated)
			if _, err := store.ClaimHarnessSession(ctx, mutated); !errors.Is(err, acp.ErrBindingInvalid) && !errors.Is(err, acp.ErrClaimConflict) {
				t.Fatalf("changed claim accepted: %v", err)
			}
			if ok, err := store.BeginHarnessSessionDispatch(ctx, mutated); err == nil || ok {
				t.Fatalf("changed dispatch accepted: %t %v", ok, err)
			}
		})
	}
	unbound := claim
	unbound.RunID = "44444444-4444-4444-8444-444444444444"
	if _, err := store.ClaimHarnessSession(ctx, unbound); !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("missing canonical Run accepted: %v", err)
	}
}

func TestHarnessClaimConfirmIsIdempotentAndConflictsOnDifferentSession(t *testing.T) {
	_, store, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.BeginHarnessSessionDispatch(ctx, claim); err != nil || !ok {
		t.Fatalf("dispatch: %t %v", ok, err)
	}
	first, err := store.ConfirmHarnessSession(ctx, claim, "agent-session-1")
	if err != nil || first.State != acp.ClaimConfirmed || first.AgentSessionID != "agent-session-1" {
		t.Fatalf("confirm: %+v %v", first, err)
	}
	second, err := store.ConfirmHarnessSession(ctx, claim, "agent-session-1")
	if err != nil || second.AgentSessionID != first.AgentSessionID {
		t.Fatalf("replay changed session: %+v %v", second, err)
	}
	if _, err := store.ConfirmHarnessSession(ctx, claim, "agent-session-2"); !errors.Is(err, acp.ErrClaimConflict) {
		t.Fatalf("changed session was accepted: %v", err)
	}
}

func TestHarnessClaimMustDispatchBeforeConfirmAndValidateRequest(t *testing.T) {
	_, store, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmHarnessSession(ctx, claim, "agent-session-1"); !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("premature confirm: %v", err)
	}
	if _, err := store.ConfirmHarnessSession(ctx, claim, " "); !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("malformed session accepted: %v", err)
	}
	if _, err := store.ClaimHarnessSession(ctx, acp.SessionClaim{TenantID: "tenant-1"}); !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("malformed claim accepted: %v", err)
	}
}

func TestHarnessClaimRequiresCanonicalRunIntentDigestAndRelease(t *testing.T) {
	_, store, claim := harnessFixture(t)
	wrongDigest := claim
	wrongDigest.RequestDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := store.ClaimHarnessSession(context.Background(), wrongDigest); !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("digest not bound to canonical RunIntent: %v", err)
	}
	wrongRelease := claim
	wrongRelease.AgentReleaseID = "release-2"
	if _, err := store.ClaimHarnessSession(context.Background(), wrongRelease); !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("AgentRelease not bound to canonical Run: %v", err)
	}
}

func TestHarnessClaimRejectsDispatchAfterRunCancellation(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='CANCELLED', updated_at=now() WHERE tenant_id=$1 AND run_id=$2::uuid", claim.TenantID, claim.RunID); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.BeginHarnessSessionDispatch(ctx, claim); ok || !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("cancelled Run granted session dispatch: %t %v", ok, err)
	}
	record, err := store.ReadHarnessSessionClaim(ctx, claim)
	if err != nil || record.State != acp.ClaimPrepared {
		t.Fatalf("failed admission mutated claim: %+v %v", record, err)
	}
}

func TestHarnessClaimDatabaseForbidsIdentityMutationDeletionTruncateAndStateRegression(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"UPDATE runtime_harness_session_claims SET attempt_id='55555555-5555-4555-8555-555555555555'::uuid WHERE tenant_id=$1 AND run_id=$2::uuid",
		"UPDATE runtime_harness_session_claims SET state='CONFIRMED',agent_session_id='forged' WHERE tenant_id=$1 AND run_id=$2::uuid",
		"DELETE FROM runtime_harness_session_claims WHERE tenant_id=$1 AND run_id=$2::uuid",
	} {
		if _, err := pool.Exec(ctx, statement, claim.TenantID, claim.RunID); err == nil {
			t.Fatalf("forbidden mutation succeeded: %s", statement)
		}
	}
	if _, err := pool.Exec(ctx, "TRUNCATE runtime_harness_session_claims"); err == nil {
		t.Fatal("claim TRUNCATE succeeded")
	}
	if ok, err := store.BeginHarnessSessionDispatch(ctx, claim); err != nil || !ok {
		t.Fatalf("dispatch: %t %v", ok, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runtime_harness_session_claims SET state='PREPARED' WHERE tenant_id=$1 AND run_id=$2::uuid", claim.TenantID, claim.RunID); err == nil {
		t.Fatal("UNKNOWN state was rolled back to PREPARED")
	}
	record, err := store.ReadHarnessSessionClaim(ctx, claim)
	if err != nil || record.State != acp.ClaimUnknown {
		t.Fatalf("claim no longer UNKNOWN: %+v %v", record, err)
	}
}

func TestHarnessClaimMigrationVersionAndReapply(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_schema_migrations WHERE version IN (6,7,8)").Scan(&count); err != nil || count != 3 {
		t.Fatalf("required v6 Outbox, v7 Principal and v8 Harness migrations missing: %d %v", count, err)
	}
	var principals, harness string
	if err := pool.QueryRow(ctx, "SELECT coalesce(to_regclass('runtime_run_principal_snapshots')::text, ''), coalesce(to_regclass('runtime_harness_session_claims')::text, '')").Scan(&principals, &harness); err != nil || principals == "" || harness == "" {
		t.Fatalf("both principal and Harness authorities must exist: principal=%q harness=%q err=%v", principals, harness, err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO runtime_harness_session_claims (tenant_id, run_id) VALUES ('x', '11111111-1111-4111-8111-111111111111'::uuid)"); err == nil {
		t.Fatal("incomplete orphaned harness claim was accepted")
	}
}

func TestHarnessSessionClaimCannotRaceUncommittedRunCancellation(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Hold a cancellation transaction's Run row lock while a competing
	// creation claim reads the authoritative RUNNING predicate.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE runs SET status='CANCELLED', updated_at=now()
		WHERE tenant_id=$1 AND run_id=$2::uuid`, claim.TenantID, claim.RunID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		record acp.SessionClaimRecord
		err    error
	}
	out := make(chan result, 1)
	go func() {
		r, e := store.ClaimHarnessSession(ctx, claim)
		out <- result{r, e}
	}()
	// Give the concurrent SQL statement time to enter PostgreSQL while the
	// cancelling transaction holds its row lock. The operation must eventually
	// observe the committed cancellation, not a stale pre-lock snapshot.
	time.Sleep(150 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Read the outcome afresh: a prior success is a security regression.
	got := <-out
	if !errors.Is(got.err, acp.ErrBindingInvalid) || got.record.Created {
		t.Fatalf("cancelled Run gained a new Harness claim: %+v err=%v", got.record, got.err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_harness_session_claims
		WHERE tenant_id=$1 AND run_id=$2::uuid`, claim.TenantID, claim.RunID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("cancelled Run retained %d unauthorized Harness claims", count)
	}
}

func TestHarnessDispatchCannotRaceUncommittedRunCancellation(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE runs SET status='CANCELLED', updated_at=now()
		WHERE tenant_id=$1 AND run_id=$2::uuid`, claim.TenantID, claim.RunID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		allowed bool
		err     error
	}
	out := make(chan result, 1)
	go func() {
		ok, e := store.BeginHarnessSessionDispatch(ctx, claim)
		out <- result{ok, e}
	}()
	select {
	case <-out:
	case <-time.After(150 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := <-out
	if got.allowed || !errors.Is(got.err, acp.ErrBindingInvalid) {
		t.Fatalf("cancelled Run gained a session/new dispatch grant: %+v", got)
	}
	record, err := store.ReadHarnessSessionClaim(ctx, claim)
	if err != nil || record.State != acp.ClaimPrepared {
		t.Fatalf("rejected dispatch modified preflight claim: %+v err=%v", record, err)
	}
}

func TestHarnessClaimRequiresPersistedACPPrincipalSnapshot(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	// Legacy acceptance is retained for compatibility but cannot authorize
	// a Harness session/new without a trusted, persisted ACP principal.
	receipt, err := store.AcceptIntent(ctx, testIntent())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runs SET status='RUNNING', updated_at=now()
		WHERE tenant_id=$1 AND run_id=$2::uuid`, "tenant-1", receipt.RunID); err != nil {
		t.Fatal(err)
	}
	claim := acp.SessionClaim{
		TenantID: "tenant-1", RunID: receipt.RunID,
		AttemptID: "22222222-2222-4222-8222-222222222222",
		HarnessInstanceID: "worker-codex-1", AgentReleaseID: "release-1",
		PolicyRevision: "policy-revision-1", RequestDigest: testIntent().RequestDigest,
		WorkingDir: "/workspace/project",
	}
	if rec, err := store.ClaimHarnessSession(ctx, claim); !errors.Is(err, acp.ErrBindingInvalid) || rec.Created {
		t.Fatalf("legacy Run without authenticated ACP principal created Harness claim: %+v err=%v", rec, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_harness_session_claims
		WHERE tenant_id=$1 AND run_id=$2::uuid`, claim.TenantID, claim.RunID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unauthenticated Run created %d Harness claims", count)
	}
}

func TestHarnessClaimRequiresExactPersistedPolicyRevision(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx := context.Background()
	changed := claim
	changed.PolicyRevision = "different-policy-revision"
	if rec, err := store.ClaimHarnessSession(ctx, changed); !errors.Is(err, acp.ErrBindingInvalid) || rec.Created {
		t.Fatalf("caller-supplied policy was promoted to authority: %+v err=%v", rec, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_harness_session_claims
		WHERE tenant_id=$1 AND run_id=$2::uuid`, claim.TenantID, claim.RunID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("mismatched policy created %d Harness claims", count)
	}
}

func TestHarnessDispatchRejectsUnboundOrMismatchedPersistedPrincipal(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	// A DB-superuser fixture can deliberately remove the previously trusted
	// snapshot; ordinary runtime writers must not have such DDL privilege.
	if _, err := pool.Exec(ctx, "DROP TRIGGER runtime_principal_no_row_mutation ON runtime_run_principal_snapshots"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM runtime_run_principal_snapshots WHERE run_id=$1::uuid", claim.RunID); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.BeginHarnessSessionDispatch(ctx, claim); ok || !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("unbound principal still received session/new grant: allowed=%t err=%v", ok, err)
	}
	rec, err := store.ReadHarnessSessionClaim(ctx, claim)
	if err != nil || rec.State != acp.ClaimPrepared {
		t.Fatalf("untrusted dispatch changed state: %+v err=%v", rec, err)
	}
}
