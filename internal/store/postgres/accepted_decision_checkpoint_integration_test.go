package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

func TestAcceptedDecisionCheckpointIsBusinessInputBoundAndDurable(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	principal := trustedSnapshot()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{
		TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
		RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest,
	}
	const execution = "11111111-2222-4333-8444-555555555555"
	first, err := store.PrepareAcceptedDecision(ctx, ref, execution)
	if err != nil || first.Phase != run.DecisionWaitingAuthority || first.RunID != receipt.RunID ||
		first.ExecutionID != execution || first.AttemptID == "" || first.TurnID == "" ||
		first.PolicyRevision != principal.PolicyRevision || first.ConfigDigest != principal.ConfigDigest ||
		first.InputDigest == "" {
		t.Fatalf("prepare checkpoint from committed business input: %+v %v", first, err)
	}
	// A worker can die after PostgreSQL commit but before Activity ACK.
	// Restart must recover the same checkpoint, not allocate a new Turn.
	replay, err := postgres.New(pool).PrepareAcceptedDecision(ctx, ref, execution)
	if err != nil || replay != first {
		t.Fatalf("checkpoint replay changed binding: %+v %v", replay, err)
	}
	if _, err := store.PrepareAcceptedDecision(ctx, ref, secondTemporalExecutionID); err == nil {
		t.Fatal("second Temporal execution claimed business checkpoint")
	}
	foreign := ref
	foreign.TenantID = "other-tenant"
	if _, err := store.PrepareAcceptedDecision(ctx, foreign, execution); err == nil {
		t.Fatal("foreign tenant read execution checkpoint")
	}
	wrong := ref
	wrong.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := store.PrepareAcceptedDecision(ctx, wrong, execution); err == nil {
		t.Fatal("wrong digest obtained checkpoint")
	}
	var rows, turns int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM runtime_decision_checkpoints), (SELECT count(*) FROM runtime_decision_turns)").Scan(&rows, &turns); err != nil || rows != 1 || turns != 1 {
		t.Fatalf("duplicate business state: %d/%d %v", rows, turns, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE runtime_decision_checkpoints SET input_digest='sha256:'||repeat('b',64)"); err == nil {
		t.Fatal("checkpoint digest mutated")
	}
	if _, err := pool.Exec(ctx, "DELETE FROM runtime_decision_checkpoints"); err == nil {
		t.Fatal("checkpoint evidence deleted")
	}
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='CANCELLED',updated_at=clock_timestamp() WHERE run_id=$1::uuid", receipt.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareAcceptedDecision(ctx, ref, execution); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("cancelled Run resumed business work: %v", err)
	}
}

func TestAcceptedDecisionCheckpointRejectsInvalidObjectiveBeforeAllocatingTurn(t *testing.T) {
	for _, input := range []string{
		`{"objective":"deploy","service":"payments","signal":"latency"}`,
		`{"objective":"sre_incident_triage","service":"payments","signal":"latency","permit":"forged"}`,
		`{"objective":"sre_incident_triage","service":"payments","signal":"unknown"}`,
		`{"message":"legacy prompt is not a decision.v1 input"}`,
	} {
		t.Run(input, func(t *testing.T) {
			pool, store := newTestStore(t)
			ctx := context.Background()
			command := testIntent()
			command.Input = []byte(input)
			receipt, err := store.AcceptIntentWithPrincipal(ctx, command, trustedSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			ref := run.AcceptedDecisionRef{TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
				RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest}
			if _, err := store.PrepareAcceptedDecision(ctx, ref, "11111111-2222-4333-8444-555555555555"); !errors.Is(err, run.ErrDecisionPreparationDenied) {
				t.Fatalf("invalid business objective was accepted: %v", err)
			}
			var count int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns").Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid input allocated a decision turn: %d %v", count, err)
			}
		})
	}
}

func TestAcceptedDecisionCheckpointRollbackLeavesNoExecutionIdentity(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"errors"}`)
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
		RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest}
	for _, sql := range []string{
		"CREATE FUNCTION reject_checkpoint_insert() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''forced checkpoint insert failure''; END;'",
		"CREATE TRIGGER reject_checkpoint_insert BEFORE INSERT ON runtime_decision_checkpoints FOR EACH ROW EXECUTE FUNCTION reject_checkpoint_insert()",
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.PrepareAcceptedDecision(ctx, ref, "11111111-2222-4333-8444-555555555555"); err == nil {
		t.Fatal("preparation succeeded despite mandatory checkpoint failure")
	}
	var checkpoints, attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM runtime_decision_checkpoints), (SELECT count(*) FROM runtime_run_attempts), (SELECT count(*) FROM runtime_decision_turns)").Scan(&checkpoints, &attempts, &turns); err != nil || checkpoints != 0 || attempts != 0 || turns != 0 {
		t.Fatalf("failed preparation committed orphan identity: %d/%d/%d %v", checkpoints, attempts, turns, err)
	}
	if _, err := pool.Exec(ctx, "DROP TRIGGER reject_checkpoint_insert ON runtime_decision_checkpoints"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareAcceptedDecision(ctx, ref, "11111111-2222-4333-8444-555555555555"); err != nil {
		t.Fatalf("local transaction rollback was not recoverable: %v", err)
	}
}

func TestAcceptedDecisionCheckpointRejectsOpenedBreaker(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"saturation"}`)
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	ref := run.AcceptedDecisionRef{TenantID: receipt.TenantID, RunID: receipt.RunID, WorkflowID: receipt.WorkflowID,
		RunIntentID: receipt.RunIntentID, RequestDigest: receipt.RequestDigest}
	initial, err := store.GetRunBreaker(ctx, ref.TenantID, ref.RunID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := initial.Trip("UNAUTHORIZED_EGRESS", "checkpoint-breaker-test", initial.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, initial.Version, opened); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareAcceptedDecision(ctx, ref, "11111111-2222-4333-8444-555555555555"); !errors.Is(err, run.ErrDecisionPreparationDenied) {
		t.Fatalf("opened breaker did not deny preparation: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_run_attempts").Scan(&count); err != nil || count != 0 {
		t.Fatalf("denied preparation allocated attempt: %d %v", count, err)
	}
}

func TestDecisionCheckpointMigrationRejectsDisabledTruncateFence(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "ALTER TABLE runtime_decision_checkpoints DISABLE TRIGGER runtime_decision_checkpoint_no_truncate"); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err == nil {
		t.Fatal("migration ledger concealed weakened checkpoint protection")
	}
}
