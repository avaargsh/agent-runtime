package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func TestRuntimePrincipalSnapshotReadSurvivesStoreRestartAndIsTenantBound(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	want := trustedSnapshot()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), want)
	if err != nil {
		t.Fatal(err)
	}
	afterRestart := postgres.New(pool)
	got, err := afterRestart.GetRunPrincipalSnapshot(ctx, testIntent().TenantID, receipt.RunID)
	if err != nil || got != want {
		t.Fatalf("durable Runtime principal mismatch after restart: %+v err=%v", got, err)
	}
	if _, err := afterRestart.GetRunPrincipalSnapshot(ctx, "tenant-2", receipt.RunID); !errors.Is(err, postgres.ErrRunPrincipalSnapshotNotFound) {
		t.Fatalf("cross-tenant snapshot leak: %v", err)
	}
	if _, err := afterRestart.GetRunPrincipalSnapshot(ctx, testIntent().TenantID, "not-a-uuid"); err == nil {
		t.Fatal("malformed Run ID accepted")
	}
}

func TestRuntimePrincipalSnapshotReadFailsClosedForLegacyRun(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntent(ctx, testIntent())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetRunPrincipalSnapshot(ctx, receipt.TenantID, receipt.RunID)
	if !errors.Is(err, postgres.ErrRunPrincipalSnapshotNotFound) {
		t.Fatalf("legacy unbound Run returned trusted principal: %v", err)
	}
}
