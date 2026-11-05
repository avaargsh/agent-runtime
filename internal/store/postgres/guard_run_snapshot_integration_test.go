package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func TestGuardRunSafetySnapshotIsTenantBoundAndFailClosed(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	const runID = "00000000-0000-4000-8000-000000000611"
	created, ok, err := store.CreateOrGet(ctx, candidate(runID))
	if err != nil || !ok {
		t.Fatalf("CreateOrGet: created=%t err=%v", ok, err)
	}

	// QUEUED is not enough to submit protected effects, even with a CLOSED
	// breaker. The snapshot must be loaded from the persisted Runtime row.
	initial, err := store.GetGuardRunSafetySnapshot(ctx, created.TenantID, created.ID)
	if err != nil {
		t.Fatalf("lookup canonical Run readiness: %v", err)
	}
	if initial.Identity.RunID != created.ID ||
		initial.Identity.TenantID != created.TenantID ||
		initial.Identity.AgentReleaseID != created.AgentReleaseID ||
		initial.Status != run.StatusQueued || initial.BreakerState != "CLOSED" ||
		initial.BreakerEpoch != 1 || initial.BreakerVersion != 1 ||
		initial.EligibleForGuardSubmission() {
		t.Fatalf("queued Run safety snapshot should block effects: %+v", initial)
	}

	if _, err := store.GetGuardRunSafetySnapshot(ctx, "other-tenant", created.ID); !errors.Is(err, run.ErrRunNotFound) {
		t.Fatalf("cross-tenant Run lookup leaked ownership: %v", err)
	}
	if _, err := store.GetGuardRunSafetySnapshot(ctx, created.TenantID, "not-a-uuid"); !errors.Is(err, run.ErrInvalidRequest) {
		t.Fatalf("malformed Run ID must be rejected: %v", err)
	}

	if _, err := pool.Exec(ctx, "UPDATE runs SET status='RUNNING',updated_at=now() WHERE run_id=$1::uuid", created.ID); err != nil {
		t.Fatal(err)
	}
	running, err := store.GetGuardRunSafetySnapshot(ctx, created.TenantID, created.ID)
	if err != nil || !running.EligibleForGuardSubmission() {
		t.Fatalf("active Run with CLOSED breaker must be ready for further authorization: %+v err=%v", running, err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE runtime_circuit_breakers
		SET state='OPEN',reason_code='guard_test',trigger_event_id='guard-event',
			opened_at=now(),epoch=2,version=2,updated_at=now()
		WHERE scope_kind='RUN' AND scope_id=$1
	`, created.ID); err != nil {
		t.Fatal(err)
	}
	blocked, err := store.GetGuardRunSafetySnapshot(ctx, created.TenantID, created.ID)
	if err != nil || blocked.EligibleForGuardSubmission() || blocked.BreakerEpoch != 2 || blocked.BreakerState != "OPEN" {
		t.Fatalf("tripped Run breaker must block further admission: %+v err=%v", blocked, err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE runtime_circuit_breakers
		SET state='CLOSED',reason_code='',trigger_event_id='',opened_at=NULL,
			recovery_approval_id='',epoch=3,version=3,updated_at=now()
		WHERE scope_kind='RUN' AND scope_id=$1
	`, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='SUCCEEDED',updated_at=now() WHERE run_id=$1::uuid", created.ID); err != nil {
		t.Fatal(err)
	}
	terminal, err := store.GetGuardRunSafetySnapshot(ctx, created.TenantID, created.ID)
	if err != nil || terminal.Status != run.StatusSucceeded || terminal.EligibleForGuardSubmission() {
		t.Fatalf("terminal Run must block new protected effects: %+v err=%v", terminal, err)
	}

	if _, err := pool.Exec(ctx,
		"DELETE FROM runtime_circuit_breakers WHERE scope_kind='RUN' AND scope_id=$1", created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetGuardRunSafetySnapshot(ctx, created.TenantID, created.ID); !errors.Is(err, postgres.ErrBreakerNotFound) {
		t.Fatalf("Run without durable breaker must fail closed: %v", err)
	}
}

func TestGuardRunSafetySnapshotUnavailableDoesNotAuthorize(t *testing.T) {
	var nilStore *postgres.Store
	if _, err := nilStore.GetGuardRunSafetySnapshot(context.Background(), "tenant-1", "00000000-0000-4000-8000-000000000611"); err == nil {
		t.Fatal("nil Runtime Run authority accepted")
	}
}
