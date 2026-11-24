package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// The initial epoch authorizes creation only once. A revoked or recovered
// breaker cannot silently authorize loading the historical session again.
func TestHarnessRecoveryDeniesRevokedBreakerPreservesHistory(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.BeginHarnessSessionDispatch(ctx, claim); !ok || err != nil {
		t.Fatalf("initial dispatch: %t %v", ok, err)
	}
	const session = "historical-breaker-session"
	confirmed, err := store.ConfirmHarnessSession(ctx, claim, session)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.GetRunBreaker(ctx, claim.TenantID, claim.RunID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := initial.Trip("UNAUTHORIZED_EGRESS", "harness-load-revoked", initial.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, initial.Version, opened); err != nil {
		t.Fatal(err)
	}
	check := func(phase string) {
		t.Helper()
		rpc := &durableHarnessRPCProbe{}
		restarted := postgres.New(pool)
		client, err := acp.NewClient(rpc, restarted, claim.HarnessInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		if status, err := client.Recover(ctx, claim.TenantID, claim.RunID); status != acp.RecoveryUnknown || !errors.Is(err, acp.ErrBindingInvalid) {
			t.Errorf("%s: revoked authority loaded session: %s %v", phase, status, err)
		}
		if !reflect.DeepEqual(rpc.methods, []string{"initialize"}) {
			t.Errorf("%s: revoked authority emitted load: %v", phase, rpc.methods)
		}
		got, err := restarted.ReadHarnessSessionClaim(ctx, claim)
		if err != nil || got != confirmed {
			t.Fatalf("%s: historical receipt changed: %+v %v", phase, got, err)
		}
		if status, err := client.Cancel(ctx, claim.TenantID, claim.RunID); status != acp.CancelSent || err != nil ||
			!reflect.DeepEqual(rpc.notifications, []string{"session/cancel"}) || rpc.cancelSession != session {
			t.Fatalf("%s: historical cancellation lost: %s %v", phase, status, err)
		}
	}
	check("OPEN")
	half, err := opened.BeginRecovery("approval-harness-load", opened.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, opened.Version, half); err != nil {
		t.Fatal(err)
	}
	check("HALF_OPEN")
	recovered, err := half.CompleteRecovery("approval-harness-load", "evidence://harness-load-recovery", half.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, half.Version, recovered); err != nil {
		t.Fatal(err)
	}
	check("recovered epoch")

	// A missing breaker must deny recovery without hiding the confirmed
	// historical binding needed for best-effort cancellation.
	if _, err := pool.Exec(ctx, `DELETE FROM runtime_circuit_breakers WHERE scope_kind='RUN' AND scope_id=$1`, claim.RunID); err != nil {
		t.Fatal(err)
	}
	check("missing breaker")
}
