package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func trustedSnapshot() run.PrincipalSnapshot {
	return run.PrincipalSnapshot{
		Version:        "acp-principal/v1",
		IssuerSPIFFEID: "spiffe://example.org/acp",
		ProjectID:      "project-1",
		SubjectID:      "subject-1",
		ActorID:        "actor-1",
		PolicyRevision: "policy-revision-1",
		ConfigDigest:   "sha256:" + strings.Repeat("b", 64),
	}
}

func TestPrincipalSnapshotRejectsMissingAndMalformedFields(t *testing.T) {
	base := trustedSnapshot()
	tests := []struct {
		name   string
		mutate func(*run.PrincipalSnapshot)
	}{
		{"missing actor", func(s *run.PrincipalSnapshot) { s.ActorID = "" }},
		{"missing subject", func(s *run.PrincipalSnapshot) { s.SubjectID = "" }},
		{"missing project", func(s *run.PrincipalSnapshot) { s.ProjectID = "" }},
		{"missing policy revision", func(s *run.PrincipalSnapshot) { s.PolicyRevision = "" }},
		{"missing config stamp", func(s *run.PrincipalSnapshot) { s.ConfigDigest = "" }},
		{"bad digest", func(s *run.PrincipalSnapshot) { s.ConfigDigest = "sha256:missing" }},
		{"wrong version", func(s *run.PrincipalSnapshot) { s.Version = "unknown" }},
		{"no issuer", func(s *run.PrincipalSnapshot) { s.IssuerSPIFFEID = "" }},
		{"issuer port", func(s *run.PrincipalSnapshot) { s.IssuerSPIFFEID = "spiffe://example.org:9443/acp" }},
		{"issuer fragment", func(s *run.PrincipalSnapshot) { s.IssuerSPIFFEID = "spiffe://example.org/acp#spoof" }},
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.mutate(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("malformed trusted snapshot accepted")
			}
		})
	}
}

func TestRuntimeRefusesToClaimLegacyRunWithoutTrustedPrincipal(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	_, err := store.AcceptIntent(ctx, testIntent())
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := store.ClaimRuntimeStart(ctx, "executor-a", time.Minute)
	if err != nil || found {
		t.Fatalf("workload-only identity bypassed principal binding: found=%v err=%v", found, err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_outbox WHERE delivered_at IS NULL").Scan(&count); err != nil || count != 1 {
		t.Fatalf("unbound start event not retained: %d %v", count, err)
	}
}

func TestRuntimePrincipalSnapshotAtomicReplayAndUnmodifiable(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	snapshot := trustedSnapshot()
	created, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), snapshot)
	if err != nil || !created.Created {
		t.Fatalf("first acceptance: %+v %v", created, err)
	}
	replayed, err := postgres.New(pool).AcceptIntentWithPrincipal(ctx, testIntent(), snapshot)
	if err != nil || replayed.Created || replayed.RunID != created.RunID {
		t.Fatalf("replay changed canonical Run: %+v %v", replayed, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*run.PrincipalSnapshot)
	}{
		{"actor", func(s *run.PrincipalSnapshot) { s.ActorID = "actor-2" }},
		{"subject", func(s *run.PrincipalSnapshot) { s.SubjectID = "subject-2" }},
		{"policy", func(s *run.PrincipalSnapshot) { s.PolicyRevision = "policy-revision-2" }},
		{"issuer", func(s *run.PrincipalSnapshot) { s.IssuerSPIFFEID = "spiffe://another.example/acp" }},
		{"project", func(s *run.PrincipalSnapshot) { s.ProjectID = "project-2" }},
		{"config", func(s *run.PrincipalSnapshot) { s.ConfigDigest = "sha256:" + strings.Repeat("c", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := snapshot
			tc.mutate(&changed)
			if _, err := postgres.New(pool).AcceptIntentWithPrincipal(ctx, testIntent(), changed); !errors.Is(err, run.ErrIdempotencyConflict) {
				t.Fatalf("principal/policy replay mutation accepted: %v", err)
			}
		})
	}
	if _, err := store.AcceptIntent(ctx, testIntent()); !errors.Is(err, run.ErrIdempotencyConflict) {
		t.Fatalf("legacy API bypassed authenticated principal binding: %v", err)
	}
	leased, found, err := store.ClaimRuntimeStart(ctx, "executor-a", time.Minute)
	if err != nil || !found || leased.RunID != created.RunID {
		t.Fatalf("bound Run not claimable: %+v found=%v err=%v", leased, found, err)
	}
	var rows, runs, starts int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_run_principal_snapshots WHERE run_id=$1::uuid", created.RunID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runs WHERE run_intent_id=$1::uuid", sampleIntentID).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_outbox WHERE aggregate_id=$1::uuid AND event_type='RUN_START_REQUESTED'", created.RunID).Scan(&starts); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || runs != 1 || starts != 1 {
		t.Fatalf("atomic binding duplicated: snapshot=%d run=%d start=%d", rows, runs, starts)
	}
	for _, sql := range []string{
		"UPDATE runtime_run_principal_snapshots SET actor_id='hijacked'",
		"DELETE FROM runtime_run_principal_snapshots",
		"TRUNCATE runtime_run_principal_snapshots",
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatalf("mutable principal snapshot: %s", sql)
		}
	}
}

func TestPrincipalAcceptanceOutboxFailureRollsBackRunSnapshotAndBreaker(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	// Inject a real SQL failure after both Run and principal snapshot inserts.
	if _, err := pool.Exec(ctx, "ALTER TABLE runtime_outbox ADD CONSTRAINT test_reject_start CHECK (event_type <> 'RUN_START_REQUESTED')"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot()); err == nil {
		t.Fatal("Runtime committed Run despite start Outbox failure")
	}
	for _, query := range []string{
		"SELECT count(*) FROM runs",
		"SELECT count(*) FROM runtime_run_principal_snapshots",
		"SELECT count(*) FROM runtime_outbox",
		"SELECT count(*) FROM runtime_circuit_breakers WHERE scope_kind='RUN'",
	} {
		var count int
		if err := pool.QueryRow(ctx, query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("failed principal acceptance leaked %d rows: %s", count, query)
		}
	}
}
