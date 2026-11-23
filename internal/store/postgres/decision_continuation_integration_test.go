package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func testContinuationReceipt(t *testing.T, a run.DecisionAuthority) run.DecisionContinuationReceipt {
	t.Helper()
	identity, err := json.Marshal(struct{ TenantID, InvocationID string }{a.TenantID, a.InvocationID})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(identity)
	return run.DecisionContinuationReceipt{
		SchemaVersion: "decision.continuation.v1",
		Authority:     a,
		DecisionID:    "dec_" + hex.EncodeToString(hash[:]),
		RecordSHA256:  strings.Repeat("a", 64),
		PlanHash:      strings.Repeat("b", 64),
	}
}

// These are real PostgreSQL transaction tests with synthetic receipt digests,
// not proof of trusted network origin or live Decision integration.
func TestDecisionContinuationAcceptanceIsImmutableAndIdempotent(t *testing.T) {
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
	ref := run.AcceptedDecisionRef{TenantID: accepted.TenantID, RunID: accepted.RunID, WorkflowID: accepted.WorkflowID,
		RunIntentID: accepted.RunIntentID, RequestDigest: accepted.RequestDigest}
	checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, "11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID)
	if err != nil {
		t.Fatal(err)
	}
	receipt := testContinuationReceipt(t, a)
	first, err := store.AcceptDecisionContinuation(ctx, a, receipt)
	if err != nil || first != receipt {
		t.Fatalf("accept exact continuation: %+v %v", first, err)
	}
	replay, err := postgres.New(pool).AcceptDecisionContinuation(ctx, a, receipt)
	if err != nil || replay != first {
		t.Fatalf("lost ACK replay: %+v %v", replay, err)
	}
	bad := receipt
	bad.RecordSHA256 = strings.Repeat("c", 64)
	if _, err := store.AcceptDecisionContinuation(ctx, a, bad); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("different record replaced accepted proposal: %v", err)
	}
	for _, sql := range []string{
		"UPDATE runtime_decision_acceptances SET receipt=receipt",
		"DELETE FROM runtime_decision_acceptances",
		"TRUNCATE runtime_decision_acceptances",
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatalf("accepted fact mutable: %s", sql)
		}
	}
	var rows int
	var phase, lifecycle string
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM runtime_decision_acceptances), c.phase, r.status FROM runtime_decision_checkpoints c JOIN runs r USING (run_id) WHERE c.run_id=$1::uuid", ref.RunID).Scan(&rows, &phase, &lifecycle); err != nil || rows != 1 || phase != run.DecisionWaitingAuthority || lifecycle != "RUNNING" {
		t.Fatalf("duplicate or unauthorized phase/lifecycle change: %d %s %s %v", rows, phase, lifecycle, err)
	}
}

func TestDecisionContinuationAcceptRejectsStaleCurrentAuthority(t *testing.T) {
	for _, change := range []string{"cancelled", "breaker", "wrong-attempt", "wrong-digest", "insert-failure"} {
		t.Run(change, func(t *testing.T) {
			pool, store := newTestStore(t)
			ctx := context.Background()
			command := testIntent()
			command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"errors"}`)
			principal := trustedSnapshot()
			principal.ActorID = principal.SubjectID
			accepted, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
			if err != nil {
				t.Fatal(err)
			}
			ref := run.AcceptedDecisionRef{TenantID: accepted.TenantID, RunID: accepted.RunID, WorkflowID: accepted.WorkflowID,
				RunIntentID: accepted.RunIntentID, RequestDigest: accepted.RequestDigest}
			checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, "11111111-2222-4333-8444-555555555555")
			if err != nil {
				t.Fatal(err)
			}
			a, err := store.GetDecisionAuthority(ctx, ref.TenantID, ref.RunID, checkpoint.TurnID)
			if err != nil {
				t.Fatal(err)
			}
			receipt := testContinuationReceipt(t, a)
			switch change {
			case "cancelled":
				if err := store.CancelPreparedDecision(ctx, ref, checkpoint.ExecutionID); err != nil {
					t.Fatal(err)
				}
			case "breaker":
				b, err := store.GetRunBreaker(ctx, ref.TenantID, ref.RunID)
				if err != nil {
					t.Fatal(err)
				}
				opened, err := b.Trip("UNAUTHORIZED_EGRESS", "stale-continuation", b.UpdatedAt.Add(1))
				if err != nil {
					t.Fatal(err)
				}
				if err := store.CompareAndSwapBreaker(ctx, b.Version, opened); err != nil {
					t.Fatal(err)
				}
			case "wrong-attempt":
				receipt.Authority.AttemptID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "wrong-digest":
				receipt.Authority.ConfigDigest = "sha256:" + strings.Repeat("c", 64)
			case "insert-failure":
				if _, err := pool.Exec(ctx, "CREATE FUNCTION reject_acceptance_insert() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''forced acceptance failure''; END;'"); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, "CREATE TRIGGER reject_acceptance_insert BEFORE INSERT ON runtime_decision_acceptances FOR EACH ROW EXECUTE FUNCTION reject_acceptance_insert()"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.AcceptDecisionContinuation(ctx, a, receipt); err == nil {
				t.Fatal("stale or failed acceptance succeeded")
			}
			var rows int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_acceptances").Scan(&rows); err != nil || rows != 0 {
				t.Fatalf("denied acceptance persisted: %d %v", rows, err)
			}
		})
	}
}

func TestDecisionAcceptanceMigrationRejectsDisabledTruncateFence(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "ALTER TABLE runtime_decision_acceptances DISABLE TRIGGER runtime_decision_acceptance_no_truncate"); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err == nil {
		t.Fatal("migration ledger concealed weakened acceptance protection")
	}
}
