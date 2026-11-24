package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
)

// V8 stores immutable Attempt identities but does not provide an authoritative
// current-Attempt selector. Until such a selector exists, ambiguous persisted
// attempts must never authorize a new Harness session dispatch. Direct SQL
// here models inconsistent durable authority; it is not a supported API for
// creating or advancing a Temporal execution.
func TestHarnessCreationAndDispatchRejectAmbiguousAttempts(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		name := "before-claim"
		if prepared {
			name = "before-dispatch"
		}
		t.Run(name, func(t *testing.T) {
			pool, store, claim := harnessFixture(t)
			ctx := context.Background()
			if prepared {
				if rec, err := store.ClaimHarnessSession(ctx, claim); err != nil || !rec.Created {
					t.Fatalf("prepare unambiguous claim: %+v err=%v", rec, err)
				}
			}
			if _, err := pool.Exec(ctx, `INSERT INTO runtime_run_attempts
				(tenant_id, run_id, run_attempt_id, workflow_id, temporal_execution_id)
				VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)`,
				claim.TenantID, claim.RunID, "33333333-3333-4333-8333-333333333333",
				"agent-run/v1/"+claim.RunID, "44444444-4444-4444-8444-444444444444"); err != nil {
				t.Fatalf("create ambiguous durable Attempt fixture: %v", err)
			}
			if prepared {
				if allowed, err := store.BeginHarnessSessionDispatch(ctx, claim); allowed || !errors.Is(err, acp.ErrBindingInvalid) {
					t.Fatalf("ambiguous Attempt granted dispatch: allowed=%t err=%v", allowed, err)
				}
				rec, err := store.ReadHarnessSessionClaim(ctx, claim)
				if err != nil || rec.State != acp.ClaimPrepared {
					t.Fatalf("denial must preserve prepared evidence: %+v err=%v", rec, err)
				}
				return
			}
			if rec, err := store.ClaimHarnessSession(ctx, claim); rec.Created || !errors.Is(err, acp.ErrBindingInvalid) {
				t.Fatalf("ambiguous Attempt gained creation claim: %+v err=%v", rec, err)
			}
			var count int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_harness_session_claims
				WHERE tenant_id=$1 AND run_id=$2::uuid`, claim.TenantID, claim.RunID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("denial left unauthorized claim: count=%d err=%v", count, err)
			}
		})
	}
}
