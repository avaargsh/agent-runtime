package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestStore(t *testing.T) (*pgxpool.Pool, *postgres.Store) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; PostgreSQL integration test skipped")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect to PostgreSQL: %v", err)
	}

	schema := fmt.Sprintf("test_runtime_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+(pgx.Identifier{schema}).Sanitize()); err != nil {
		adminPool.Close()
		t.Fatalf("create isolated schema: %v", err)
	}

	testConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		adminPool.Exec(ctx, "DROP SCHEMA "+(pgx.Identifier{schema}).Sanitize()+" CASCADE")
		adminPool.Close()
		t.Fatalf("parse test pool config: %v", err)
	}
	testConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, testConfig)
	if err != nil {
		adminPool.Exec(ctx, "DROP SCHEMA "+(pgx.Identifier{schema}).Sanitize()+" CASCADE")
		adminPool.Close()
		t.Fatalf("connect isolated test pool: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		_, _ = adminPool.Exec(dropCtx, "DROP SCHEMA "+(pgx.Identifier{schema}).Sanitize()+" CASCADE")
		adminPool.Close()
	})

	store := postgres.New(pool)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool, store
}

func candidate(id string) run.Run {
	return run.Run{
		ID:             id,
		TenantID:       "tenant-1",
		AgentID:        "agent-1",
		AgentReleaseID: "release-1",
		SessionID:      "session-1",
		IdempotencyKey: "request-1",
		RequestDigest:  strings.Repeat("a", 64),
		WorkflowID:     "agent-run/" + id,
		Status:         run.StatusQueued,
		Input:          []byte(`{"message":"hello"}`),
		CreatedAt:      time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
		UpdatedAt:      time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
	}
}

func TestCreateOrGetPersistsOneRunAndOneStartOutboxRecord(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()

	first, created, err := store.CreateOrGet(ctx, candidate("00000000-0000-4000-8000-000000000001"))
	if err != nil {
		t.Fatalf("first CreateOrGet() error = %v", err)
	}
	if !created {
		t.Fatal("first CreateOrGet() must create the Run")
	}

	second, created, err := store.CreateOrGet(ctx, candidate("00000000-0000-4000-8000-000000000002"))
	if err != nil {
		t.Fatalf("second CreateOrGet() error = %v", err)
	}
	if created {
		t.Fatal("duplicate CreateOrGet() must not create another Run")
	}
	if second.ID != first.ID || second.WorkflowID != first.WorkflowID {
		t.Fatalf("duplicate returned different identity: first=%+v second=%+v", first, second)
	}

	var runs, outbox int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runs").Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_outbox WHERE event_type = 'RUN_START_REQUESTED'").Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || outbox != 1 {
		t.Fatalf("persisted runs=%d outbox=%d, want 1 and 1", runs, outbox)
	}
}

func TestCreateOrGetRejectsChangedDigestForSameKey(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()

	if _, _, err := store.CreateOrGet(ctx, candidate("00000000-0000-4000-8000-000000000001")); err != nil {
		t.Fatal(err)
	}
	changed := candidate("00000000-0000-4000-8000-000000000002")
	changed.RequestDigest = strings.Repeat("b", 64)
	if _, _, err := store.CreateOrGet(ctx, changed); !errors.Is(err, run.ErrIdempotencyConflict) {
		t.Fatalf("CreateOrGet() error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestCreateOrGetSerializesConcurrentDuplicateStarts(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()

	const workers = 12
	var wg sync.WaitGroup
	type outcome struct {
		run     run.Run
		created bool
		err     error
	}
	results := make(chan outcome, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)
			got, created, err := store.CreateOrGet(ctx, candidate(id))
			results <- outcome{run: got, created: created, err: err}
		}(i)
	}
	wg.Wait()
	close(results)

	var canonicalID string
	createdCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent CreateOrGet() error = %v", result.err)
		}
		if canonicalID == "" {
			canonicalID = result.run.ID
		}
		if result.run.ID != canonicalID {
			t.Fatalf("concurrent starts returned different Run IDs: %q and %q", canonicalID, result.run.ID)
		}
		if result.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created count = %d, want exactly 1", createdCount)
	}

	var runs int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runs").Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("persisted Run count = %d, want 1", runs)
	}
}
