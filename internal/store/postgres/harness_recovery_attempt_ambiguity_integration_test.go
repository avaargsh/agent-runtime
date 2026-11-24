package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// A historical confirmed session is still useful for best-effort cancellation,
// but cannot be loaded for continued work when its Attempt authority is ambiguous.
func TestHarnessRecoveryRejectsAmbiguousAttemptPreservesCancellation(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx := context.Background()
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if granted, err := store.BeginHarnessSessionDispatch(ctx, claim); err != nil || !granted {
		t.Fatalf("begin dispatch: %t %v", granted, err)
	}
	const session = "historical-confirmed-session"
	confirmed, err := store.ConfirmHarnessSession(ctx, claim, session)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO runtime_run_attempts
		(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
		SELECT tenant_id,run_id,$3::uuid,workflow_id,$4::uuid
		FROM runtime_run_attempts WHERE tenant_id=$1 AND run_id=$2::uuid AND run_attempt_id=$5::uuid`,
		claim.TenantID, claim.RunID, "33333333-3333-4333-8333-333333333332",
		secondTemporalExecutionID, claim.AttemptID); err != nil {
		t.Fatal(err)
	}
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
		t.Errorf("ambiguous Attempt loaded historical session: status=%s err=%v", status, err)
	}
	if !reflect.DeepEqual(rpc.methods, []string{"initialize"}) {
		t.Errorf("ambiguous Attempt emitted session/load: %v", rpc.methods)
	}
	// Historical evidence must remain readable; denial is not final absence.
	got, err := restarted.ReadHarnessSessionClaim(ctx, claim)
	if err != nil || got != confirmed {
		t.Fatalf("historical claim changed: %+v err=%v", got, err)
	}
	if status, err := client.Cancel(ctx, claim.TenantID, claim.RunID); status != acp.CancelSent || err != nil {
		t.Fatalf("historical cancellation blocked: status=%s err=%v", status, err)
	}
	if !reflect.DeepEqual(rpc.notifications, []string{"session/cancel"}) || rpc.cancelSession != session {
		t.Fatalf("cancellation did not target exact historical binding: %+v", rpc)
	}
}
