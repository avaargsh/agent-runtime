package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
)

func TestHarnessSessionCreationRequiresCurrentAttemptPointer(t *testing.T) {
	for _, stage := range []string{"claim", "dispatch"} {
		t.Run(stage, func(t *testing.T) {
			pool, store, claim := harnessFixture(t)
			ctx := context.Background()

			if stage == "dispatch" {
				record, err := store.ClaimHarnessSession(ctx, claim)
				if err != nil || !record.Created || record.State != acp.ClaimPrepared {
					t.Fatalf("prepare claim before removing current Attempt: %+v err=%v", record, err)
				}
			}
			// Recreate a legacy v12 schema without backfilling its historical
			// Attempt. The immutable v13 pointer trigger correctly prevents a
			// normal DELETE, so model the supported migration path instead.
			if _, err := pool.Exec(ctx, "DROP TABLE runtime_current_attempts"); err != nil {
				t.Fatalf("remove v13 pointer table for legacy fixture: %v", err)
			}
			if _, err := pool.Exec(ctx, "DELETE FROM runtime_schema_migrations WHERE version=13"); err != nil {
				t.Fatalf("reset v13 migration ledger for legacy fixture: %v", err)
			}
			if err := store.Migrate(ctx); err != nil {
				t.Fatalf("reapply v13 without historical Attempt backfill: %v", err)
			}

			if stage == "claim" {
				record, err := store.ClaimHarnessSession(ctx, claim)
				if !errors.Is(err, acp.ErrBindingInvalid) || record.Created {
					t.Fatalf("missing current Attempt created a Harness claim: %+v err=%v", record, err)
				}
				var count int
				if err := pool.QueryRow(ctx, `
					SELECT count(*) FROM runtime_harness_session_claims
					WHERE tenant_id=$1 AND run_id=$2::uuid
				`, claim.TenantID, claim.RunID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("missing current Attempt persisted a claim: count=%d err=%v", count, err)
				}
				return
			}

			allowed, err := store.BeginHarnessSessionDispatch(ctx, claim)
			if allowed || !errors.Is(err, acp.ErrBindingInvalid) {
				t.Fatalf("missing current Attempt granted session/new: allowed=%t err=%v", allowed, err)
			}
			record, err := store.ReadHarnessSessionClaim(ctx, claim)
			if err != nil || record.State != acp.ClaimPrepared {
				t.Fatalf("rejected dispatch changed durable claim: %+v err=%v", record, err)
			}
		})
	}
}

func TestHarnessSessionCreationRejectsBreakerVersionDrift(t *testing.T) {
	for _, stage := range []string{"claim", "dispatch"} {
		t.Run(stage, func(t *testing.T) {
			pool, store, claim := harnessFixture(t)
			ctx := context.Background()

			if stage == "dispatch" {
				record, err := store.ClaimHarnessSession(ctx, claim)
				if err != nil || !record.Created || record.State != acp.ClaimPrepared {
					t.Fatalf("prepare claim before breaker drift: %+v err=%v", record, err)
				}
			}
			// Simulate privileged DML that bypasses the ordinary transition guard.
			disableBreakerTransitionTrigger(t, pool)
			if _, err := pool.Exec(ctx, `
				UPDATE runtime_circuit_breakers
				SET version=version+1, updated_at=clock_timestamp()
				WHERE scope_kind='RUN' AND scope_id=$1 AND state='CLOSED' AND epoch=1
			`, claim.RunID); err != nil {
				t.Fatalf("inject breaker version drift: %v", err)
			}

			if stage == "claim" {
				record, err := store.ClaimHarnessSession(ctx, claim)
				if !errors.Is(err, acp.ErrBindingInvalid) || record.Created {
					t.Fatalf("version-drifted breaker created a Harness claim: %+v err=%v", record, err)
				}
				var count int
				if err := pool.QueryRow(ctx, `
					SELECT count(*) FROM runtime_harness_session_claims
					WHERE tenant_id=$1 AND run_id=$2::uuid
				`, claim.TenantID, claim.RunID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("version-drifted breaker persisted a claim: count=%d err=%v", count, err)
				}
				return
			}

			allowed, err := store.BeginHarnessSessionDispatch(ctx, claim)
			if allowed || !errors.Is(err, acp.ErrBindingInvalid) {
				t.Fatalf("version-drifted breaker granted session/new: allowed=%t err=%v", allowed, err)
			}
			record, err := store.ReadHarnessSessionClaim(ctx, claim)
			if err != nil || record.State != acp.ClaimPrepared {
				t.Fatalf("rejected version-drifted dispatch changed claim: %+v err=%v", record, err)
			}
		})
	}
}
