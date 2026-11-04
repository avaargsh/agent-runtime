package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

const sampleIntentID = "11111111-1111-4111-8111-111111111111"

func testIntent() run.IntentStartRequest {
	return run.IntentStartRequest{
		TenantID: "tenant-1", RunIntentID: sampleIntentID,
		RequestDigest: "sha256:" + strings.Repeat("a", 64),
		AgentID:       "agent-1", AgentReleaseID: "release-1", SessionID: "session-1",
		Input: []byte(`{"message":"hello"}`),
	}
}

func TestAcceptIntentIsStableAfterLostAcknowledgementAndStoreRecreation(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	first, err := store.AcceptIntent(ctx, testIntent())
	if err != nil || !first.Created {
		t.Fatalf("initial acceptance: %+v %v", first, err)
	}
	if first.RunIntentID != sampleIntentID || first.RequestDigest != testIntent().RequestDigest ||
		first.WorkflowID != "agent-run/v1/"+first.RunID {
		t.Fatalf("invalid ACP receipt: %+v", first)
	}
	// The caller did not receive the first ACK and creates a new store/client.
	afterRestart := postgres.New(pool)
	second, err := afterRestart.AcceptIntent(ctx, testIntent())
	if err != nil || second.Created || second.RunID != first.RunID ||
		second.WorkflowID != first.WorkflowID || second.RequestDigest != first.RequestDigest {
		t.Fatalf("lost-ACK replay changed identity: %+v %v", second, err)
	}
	found, err := afterRestart.LookupIntent(ctx, testIntent().TenantID, sampleIntentID, testIntent().RequestDigest)
	if err != nil || found.RunID != first.RunID || found.WorkflowID != first.WorkflowID {
		t.Fatalf("durable authoritative FOUND lookup: %+v %v", found, err)
	}
	var runCount, eventCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runs WHERE run_intent_id = $1::uuid", sampleIntentID).Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_outbox WHERE aggregate_id = $1::uuid", first.RunID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 || eventCount != 1 {
		t.Fatalf("Run/outbox duplicates: %d / %d", runCount, eventCount)
	}
	var state string
	var epoch, version uint64
	if err := pool.QueryRow(ctx, `
		SELECT state, epoch, version FROM runtime_circuit_breakers
		WHERE scope_kind='RUN' AND scope_id=$1
	`, first.RunID).Scan(&state, &epoch, &version); err != nil {
		t.Fatalf("load initial Run breaker: %v", err)
	}
	if state != "CLOSED" || epoch != 1 || version != 1 {
		t.Fatalf("initial Run breaker = %s/%d/%d, want CLOSED/1/1", state, epoch, version)
	}
}

func TestAcceptIntentRejectsReusedIDWithChangedDigestOrBindings(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	if _, err := store.AcceptIntent(ctx, testIntent()); err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name   string
		mutate func(*run.IntentStartRequest)
	}{
		{"digest", func(r *run.IntentStartRequest) { r.RequestDigest = "sha256:" + strings.Repeat("b", 64) }},
		{"agent", func(r *run.IntentStartRequest) { r.AgentID = "agent-2" }},
		{"release", func(r *run.IntentStartRequest) { r.AgentReleaseID = "release-2" }},
		{"session", func(r *run.IntentStartRequest) { r.SessionID = "session-2" }},
		{"input", func(r *run.IntentStartRequest) { r.Input = []byte(`{"message":"changed"}`) }},
		{"tenant", func(r *run.IntentStartRequest) { r.TenantID = "tenant-2" }},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			req := testIntent()
			tc.mutate(&req)
			if _, err := store.AcceptIntent(ctx, req); !errors.Is(err, run.ErrIdempotencyConflict) {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}
}

func TestAcceptIntentRejectsInvalidDigestAndIDBeforeWrite(t *testing.T) {
	pool, store := newTestStore(t)
	req := testIntent()
	req.RequestDigest = "bad"
	if _, err := store.AcceptIntent(context.Background(), req); !errors.Is(err, run.ErrInvalidRequest) {
		t.Fatalf("digest: %v", err)
	}
	req = testIntent()
	req.RunIntentID = "invalid"
	if _, err := store.AcceptIntent(context.Background(), req); !errors.Is(err, run.ErrInvalidRequest) {
		t.Fatalf("id: %v", err)
	}
	var count int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM runs").Scan(&count); err != nil || count != 0 {
		t.Fatalf("unexpected rows: %d %v", count, err)
	}
}

func TestAcceptIntentConcurrentSameIDHasOneRunAndOutbox(t *testing.T) {
	pool, store := newTestStore(t)
	const workers = 8
	var wg sync.WaitGroup
	receipts := make(chan run.IntentReceipt, workers)
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := store.AcceptIntent(context.Background(), testIntent())
			receipts <- r
			errs <- err
		}()
	}
	wg.Wait()
	close(receipts)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first string
	created := 0
	for r := range receipts {
		if first == "" {
			first = r.RunID
		}
		if first != r.RunID {
			t.Fatal("multiple run ids")
		}
		if r.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created count=%d", created)
	}
	var count int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM runtime_outbox").Scan(&count); err != nil || count != 1 {
		t.Fatalf("outbox=%d %v", count, err)
	}
}

func TestLookupIntentDoesNotClaimFinalAbsence(t *testing.T) {
	_, store := newTestStore(t)
	_, err := store.LookupIntent(context.Background(), "tenant-1", sampleIntentID, testIntent().RequestDigest)
	if !errors.Is(err, run.ErrIntentNotFound) {
		t.Fatalf("must not falsely claim NOT_FOUND_FINAL: %v", err)
	}
}

func TestAcceptIntentOutboxFailureRollsBackRunAndInitialBreaker(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION reject_accept_intent_outbox() RETURNS trigger
		LANGUAGE plpgsql AS 'BEGIN
			RAISE EXCEPTION ''forced RunIntent outbox failure'';
		END;'
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TRIGGER reject_accept_intent_outbox
		BEFORE INSERT ON runtime_outbox
		FOR EACH ROW EXECUTE FUNCTION reject_accept_intent_outbox()
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptIntent(ctx, testIntent()); err == nil {
		t.Fatal("AcceptIntent succeeded despite forced outbox failure")
	}
	for _, query := range []string{
		"SELECT count(*) FROM runs",
		"SELECT count(*) FROM runtime_circuit_breakers WHERE scope_kind='RUN'",
	} {
		var count int
		if err := pool.QueryRow(ctx, query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("failed AcceptIntent left %d rows for %q", count, query)
		}
	}
}

