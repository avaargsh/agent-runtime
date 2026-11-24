package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// An existing checkpoint is historical evidence, not fresh authorization
// when its Run has ambiguous persisted Attempt identities.
func TestDecisionAuthorityAndContinuationRejectAmbiguousAttempts(t *testing.T) {
	for _, replay := range []bool{false, true} {
		name := "initial-acceptance"
		if replay {
			name = "accepted-replay"
		}
		t.Run(name, func(t *testing.T) {
			pool, store := newTestStore(t)
			ctx := context.Background()
			command := testIntent()
			command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
			principal := trustedSnapshot()
			principal.ActorID = principal.SubjectID
			accepted, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
			if err != nil {
				t.Fatal(err)
			}
			ref := run.AcceptedDecisionRef{TenantID: accepted.TenantID, RunID: accepted.RunID,
				WorkflowID: accepted.WorkflowID, RunIntentID: accepted.RunIntentID, RequestDigest: accepted.RequestDigest}
			checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, firstTemporalExecutionID)
			if err != nil {
				t.Fatal(err)
			}
			a, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID)
			if err != nil {
				t.Fatal(err)
			}
			receipt := testContinuationReceipt(t, a)
			wantCount := 0
			if replay {
				if got, err := store.AcceptDecisionContinuation(ctx, a, receipt); err != nil || got != receipt {
					t.Fatalf("seed accepted continuation: %+v err=%v", got, err)
				}
				wantCount = 1
			}
			if _, err := pool.Exec(ctx, `INSERT INTO runtime_run_attempts
				(tenant_id,run_id,run_attempt_id,workflow_id,temporal_execution_id)
				VALUES ($1,$2::uuid,$3::uuid,$4,$5::uuid)`, ref.TenantID, ref.RunID,
				"33333333-3333-4333-8333-333333333332", ref.WorkflowID, secondTemporalExecutionID); err != nil {
				t.Fatal(err)
			}
			restarted := postgres.New(pool)
			if got, err := restarted.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID); !errors.Is(err, run.ErrDecisionPreparationDenied) || got != (run.DecisionAuthority{}) {
				t.Errorf("ambiguous Attempt granted Decision authority: %+v err=%v", got, err)
			}
			if got, err := restarted.AcceptDecisionContinuation(ctx, a, receipt); !errors.Is(err, run.ErrDecisionPreparationDenied) || got != (run.DecisionContinuationReceipt{}) {
				t.Errorf("ambiguous Attempt accepted continuation: %+v err=%v", got, err)
			}
			var attempts, turns, checkpoints, acceptances int
			var status string
			if err := pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM runtime_run_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
				(SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid),
				(SELECT count(*) FROM runtime_decision_checkpoints WHERE tenant_id=$1 AND run_id=$2::uuid),
				(SELECT count(*) FROM runtime_decision_acceptances WHERE tenant_id=$1 AND run_id=$2::uuid),
				(SELECT status FROM runs WHERE tenant_id=$1 AND run_id=$2::uuid)`,
				ref.TenantID, ref.RunID).Scan(&attempts, &turns, &checkpoints, &acceptances, &status); err != nil {
				t.Fatal(err)
			}
			if attempts != 2 || turns != 1 || checkpoints != 1 || acceptances != wantCount || status != "RUNNING" {
				t.Fatalf("denial changed durable state: attempts=%d turns=%d checkpoints=%d acceptances=%d status=%s", attempts, turns, checkpoints, acceptances, status)
			}
			if replay {
				var raw []byte
				if err := pool.QueryRow(ctx, `SELECT receipt FROM runtime_decision_acceptances
					WHERE tenant_id=$1 AND run_id=$2::uuid`, ref.TenantID, ref.RunID).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var persisted run.DecisionContinuationReceipt
				if err := json.Unmarshal(raw, &persisted); err != nil || persisted != receipt {
					t.Fatalf("historical receipt changed: %+v err=%v", persisted, err)
				}
			}
		})
	}
}
