package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func TestRuntimeStartOutboxRecoverLostACKWithFence(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntent(ctx, testIntent())
	if err != nil {
		t.Fatal(err)
	}
	first, found, err := store.ClaimRuntimeStart(ctx, "worker-a", time.Minute)
	if err != nil || !found {
		t.Fatalf("claim: found=%v err=%v", found, err)
	}
	if first.RunID != receipt.RunID || first.WorkflowID != receipt.WorkflowID ||
		first.RunIntentID != sampleIntentID || first.RequestDigest != testIntent().RequestDigest ||
		first.Attempt != 1 || first.Owner != "worker-a" {
		t.Fatalf("untrusted outbox claim: %+v", first)
	}
	_, found, err = store.ClaimRuntimeStart(ctx, "worker-b", time.Minute)
	if err != nil || found {
		t.Fatalf("unexpired lease was stolen: found=%v err=%v", found, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runtime_outbox SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE outbox_id=$1::uuid", first.OutboxID); err != nil {
		t.Fatal(err)
	}
	// Worker A has lost the Temporal ACK. Worker B must recover the same
	// canonical Workflow ID rather than allocate a second logical Run.
	restarted := postgres.New(pool)
	second, found, err := restarted.ClaimRuntimeStart(ctx, "worker-b", time.Minute)
	if err != nil || !found {
		t.Fatalf("reclaim: found=%v err=%v", found, err)
	}
	if second.RunID != first.RunID || second.WorkflowID != first.WorkflowID ||
		second.OutboxID != first.OutboxID || second.Attempt != 2 {
		t.Fatalf("reclaim minted new identity: first=%+v second=%+v", first, second)
	}
	if err := store.AcknowledgeRuntimeStart(ctx, first); !errors.Is(err, postgres.ErrRuntimeStartLeaseLost) {
		t.Fatalf("stale worker ACK succeeded: %v", err)
	}
	if err := restarted.AcknowledgeRuntimeStart(ctx, second); err != nil {
		t.Fatalf("recovered ACK: %v", err)
	}
	if err := restarted.AcknowledgeRuntimeStart(ctx, second); !errors.Is(err, postgres.ErrRuntimeStartLeaseLost) {
		t.Fatalf("duplicate ACK succeeded: %v", err)
	}
	_, found, err = restarted.ClaimRuntimeStart(ctx, "worker-c", time.Minute)
	if err != nil || found {
		t.Fatalf("delivered row was replayed: found=%v err=%v", found, err)
	}
	var runs, outbox, delivered int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runs WHERE run_intent_id=$1::uuid", sampleIntentID).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*), count(delivered_at) FROM runtime_outbox WHERE aggregate_id=$1::uuid AND event_type='RUN_START_REQUESTED'", first.RunID).Scan(&outbox, &delivered); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || outbox != 1 || delivered != 1 {
		t.Fatalf("duplicates or uncommitted ACK: runs=%d outbox=%d delivered=%d", runs, outbox, delivered)
	}
}

func TestRuntimeStartOutboxOnlyClaimsACPOriginatedRuns(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	if _, _, err := store.CreateOrGet(ctx, candidate("00000000-0000-4000-8000-000000000001")); err != nil {
		t.Fatal(err)
	}
	_, found, err := store.ClaimRuntimeStart(ctx, "worker-a", time.Minute)
	if err != nil || found {
		t.Fatalf("legacy untrusted Run was dispatched: found=%v err=%v", found, err)
	}
}

func TestRuntimeStartOutboxReleaseReusesIdentityAndRejectsExpiredFence(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	if _, err := store.AcceptIntent(ctx, testIntent()); err != nil {
		t.Fatal(err)
	}
	first, found, err := store.ClaimRuntimeStart(ctx, "worker-a", time.Minute)
	if err != nil || !found {
		t.Fatalf("claim: %v / %v", found, err)
	}
	if err := store.ReleaseRuntimeStart(ctx, first, time.Microsecond); err != nil {
		t.Fatalf("release after ambiguous Temporal RPC: %v", err)
	}
	second, found, err := store.ClaimRuntimeStart(ctx, "worker-b", time.Minute)
	if err != nil || !found || second.Attempt != 2 || second.RunID != first.RunID {
		t.Fatalf("reclaim after release: %+v found=%v err=%v", second, found, err)
	}
	if err := store.ReleaseRuntimeStart(ctx, first, time.Microsecond); !errors.Is(err, postgres.ErrRuntimeStartLeaseLost) {
		t.Fatalf("stale release accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runtime_outbox SET lease_expires_at=clock_timestamp() - interval '1 second' WHERE outbox_id=$1::uuid", second.OutboxID); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeRuntimeStart(ctx, second); !errors.Is(err, postgres.ErrRuntimeStartLeaseLost) {
		t.Fatalf("expired fence ACK accepted: %v", err)
	}
}

func TestRuntimeStartOutboxRejectsInvalidClaimBeforeDB(t *testing.T) {
	_, store := newTestStore(t)
	if _, _, err := store.ClaimRuntimeStart(context.Background(), "", time.Minute); !errors.Is(err, postgres.ErrInvalidRuntimeStartLease) {
		t.Fatalf("missing worker identity accepted: %v", err)
	}
	if _, _, err := store.ClaimRuntimeStart(context.Background(), "worker-a", 0); !errors.Is(err, postgres.ErrInvalidRuntimeStartLease) {
		t.Fatalf("zero TTL accepted: %v", err)
	}
	if err := store.AcknowledgeRuntimeStart(context.Background(), postgres.RuntimeStartLease{Owner:"worker-a"}); !errors.Is(err, postgres.ErrInvalidRuntimeStartLease) {
		t.Fatalf("incomplete ACK accepted: %v", err)
	}
}
