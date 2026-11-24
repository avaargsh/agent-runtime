package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/google/uuid"
)

const firstTemporalExecutionID = "d98f86e9-2511-464f-8c63-012345678901"
const secondTemporalExecutionID = "d98f86e9-2511-464f-8c63-012345678902"

func TestTemporalTurnIdentityIsDurableAcrossRetryAndWorkerRestart(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if uuid.Validate(first.RunAttemptID) != nil || uuid.Validate(first.TurnID) != nil ||
		first.InvocationID != first.TurnID || first.RunID != r.RunID ||
		first.WorkflowID != r.WorkflowID || first.TemporalExecutionID != firstTemporalExecutionID {
		t.Fatalf("invalid Runtime-owned identity: %+v", first)
	}
	afterRestart := postgres.New(pool)
	replay, err := afterRestart.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil || replay != first {
		t.Fatalf("Temporal retry changed durable identity: first=%+v replay=%+v err=%v", first, replay, err)
	}
	secondTurn, err := afterRestart.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 2)
	if err != nil || secondTurn.RunAttemptID != first.RunAttemptID || secondTurn.TurnID == first.TurnID {
		t.Fatalf("new decision turn failed to retain Attempt: %+v %v", secondTurn, err)
	}
	// A second Temporal Server execution for the same logical Run might be
	// a replay after history retention expiry. Without an explicit fenced
	// continuation contract, a second Attempt could repeat effects.
	if _, err := afterRestart.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, secondTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalExecutionConflict) {
		t.Fatalf("new Temporal execution bypassed UNKNOWN reconciliation: %v", err)
	}
	var attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_run_attempts WHERE run_id=$1::uuid", r.RunID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns WHERE run_id=$1::uuid", r.RunID).Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || turns != 2 {
		t.Fatalf("duplicated canonical identities: attempts=%d turns=%d", attempts, turns)
	}
}

func TestTemporalTurnConcurrentSameExecutionHasOneAuthorityRecord(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	const n = 10
	identities := make(chan run.TemporalTurnIdentity, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := postgres.New(pool).GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1)
			identities <- got
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	close(identities)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first run.TemporalTurnIdentity
	for id := range identities {
		if first.RunAttemptID == "" {
			first = id
		} else if first != id {
			t.Fatalf("concurrent replay minted different identity: first=%+v got=%+v", first, id)
		}
	}
	var attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_run_attempts").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns").Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || turns != 1 {
		t.Fatalf("concurrent Temporal retries created duplicates: attempts=%d turns=%d", attempts, turns)
	}
	var currentCount int
	var attemptID, executionID string
	var generation, epoch int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_current_attempts").Scan(&currentCount); err != nil {
		t.Fatal(err)
	}
	if currentCount != 1 {
		t.Fatalf("concurrent retries persisted %d current Attempt pointers, want one", currentCount)
	}
	if err := pool.QueryRow(ctx, `
		SELECT c.attempt_id::text, a.temporal_execution_id::text, c.generation, c.breaker_epoch
		FROM runtime_current_attempts c
		JOIN runtime_run_attempts a ON a.tenant_id=c.tenant_id AND a.run_id=c.run_id AND a.run_attempt_id=c.attempt_id
		WHERE c.tenant_id=$1 AND c.run_id=$2::uuid
	`, r.TenantID, r.RunID).Scan(&attemptID, &executionID, &generation, &epoch); err != nil {
		t.Fatal(err)
	}
	if attemptID != first.RunAttemptID || executionID != firstTemporalExecutionID || generation != 1 || epoch != 1 {
		t.Fatalf("concurrent retries changed current authority: attempt=%s execution=%s generation=%d epoch=%d", attemptID, executionID, generation, epoch)
	}
}

func TestTemporalTurnIdentityRejectsUnboundLegacyWrongScopeAndMalformedExecution(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	bound, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                               string
		tenant, runID, workflow, execution string
		ordinal                            int32
	}{
		{"wrong tenant", "tenant-victim", bound.RunID, bound.WorkflowID, firstTemporalExecutionID, 1},
		{"wrong workflow", bound.TenantID, bound.RunID, "agent-run/v1/spoof", firstTemporalExecutionID, 1},
		{"invalid execution", bound.TenantID, bound.RunID, bound.WorkflowID, "random-untrusted-key", 1},
		{"zero ordinal", bound.TenantID, bound.RunID, bound.WorkflowID, firstTemporalExecutionID, 0},
		{"huge ordinal", bound.TenantID, bound.RunID, bound.WorkflowID, firstTemporalExecutionID, 10001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.GetOrCreateTemporalTurn(ctx, tc.tenant, tc.runID, tc.workflow, tc.execution, tc.ordinal); err == nil {
				t.Fatal("untrusted Temporal identity accepted")
			}
		})
	}
	legacyIntent := testIntent()
	legacyIntent.RunIntentID = "11111111-1111-4111-8111-111111111112"
	legacy, err := store.AcceptIntent(ctx, legacyIntent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, legacy.TenantID, legacy.RunID, legacy.WorkflowID, firstTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalTurnUntrustedRun) {
		t.Fatalf("legacy Run without immutable ACP principal got Temporal identity: %v", err)
	}
	var attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_run_attempts").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM runtime_decision_turns").Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || turns != 0 {
		t.Fatalf("rejected execution wrote identities: %d/%d", attempts, turns)
	}
}

func TestTemporalAttemptTurnIdentityCannotBeRewrittenOrTruncated(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	r, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOrCreateTemporalTurn(ctx, r.TenantID, r.RunID, r.WorkflowID, firstTemporalExecutionID, 1); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"UPDATE runtime_run_attempts SET temporal_execution_id='00000000-0000-4000-8000-000000000000'",
		"DELETE FROM runtime_run_attempts",
		"TRUNCATE runtime_run_attempts CASCADE",
		"UPDATE runtime_decision_turns SET turn_index=2",
		"DELETE FROM runtime_decision_turns",
		"TRUNCATE runtime_decision_turns",
	} {
		if _, err := pool.Exec(ctx, query); err == nil {
			t.Fatalf("immutable Execution ID changed or removed: %s", query)
		}
	}
}

// Two actually persisted tenants share one Runtime database. A stale Worker
// must not obtain the old Turn identity after cancellation or a breaker trip,
// even if the same Temporal execution ID is replayed after process restart.
// This Store gate is not proof of Temporal namespace or Sandbox filesystem IAM.
func TestTemporalTurnTwoTenantsRevocationFencesRecoveredIdentity(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()

	tenantA := testIntent()
	tenantB := testIntent()
	tenantB.TenantID = "tenant-2"
	tenantB.RunIntentID = "22222222-2222-4222-8222-222222222222"

	a, err := store.AcceptIntentWithPrincipal(ctx, tenantA, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.AcceptIntentWithPrincipal(ctx, tenantB, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	aTurn, err := store.GetOrCreateTemporalTurn(ctx, a.TenantID, a.RunID, a.WorkflowID, firstTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	bTurn, err := store.GetOrCreateTemporalTurn(ctx, b.TenantID, b.RunID, b.WorkflowID, secondTemporalExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if aTurn.RunAttemptID == bTurn.RunAttemptID || aTurn.TurnID == bTurn.TurnID {
		t.Fatal("two tenants reused a Runtime execution identity")
	}

	restarted := postgres.New(pool)
	if _, err := restarted.GetOrCreateTemporalTurn(ctx, a.TenantID, b.RunID, b.WorkflowID, secondTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalTurnUntrustedRun) {
		t.Fatalf("tenant A acquired tenant B's existing Turn: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE runs SET status='CANCELLED', updated_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2::uuid",
		a.TenantID, a.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.GetOrCreateTemporalTurn(ctx, a.TenantID, a.RunID, a.WorkflowID, firstTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalTurnUntrustedRun) {
		t.Fatalf("cancelled tenant A Run recovered an existing Turn identity: %v", err)
	}
	if got, err := restarted.GetOrCreateTemporalTurn(ctx, b.TenantID, b.RunID, b.WorkflowID, secondTemporalExecutionID, 1); err != nil || got != bTurn {
		t.Fatalf("tenant B was affected by tenant A cancellation: %+v %v", got, err)
	}

	current, err := store.GetRunBreaker(ctx, b.TenantID, b.RunID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := current.Trip("UNAUTHORIZED_EGRESS", "test-revoked-tenant-b", current.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, current.Version, opened); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.GetOrCreateTemporalTurn(ctx, b.TenantID, b.RunID, b.WorkflowID, secondTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalTurnUntrustedRun) {
		t.Fatalf("OPEN breaker allowed a restarted Worker to replay its Turn: %v", err)
	}
	// A legitimate breaker recovery is not automatically an authority to
	// reuse the pre-revocation Attempt/Turn: no epoch-bound continuation
	// credential has been issued by this Store API.
	half, err := opened.BeginRecovery("approval-tenant-b", opened.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, opened.Version, half); err != nil {
		t.Fatal(err)
	}
	recovered, err := half.CompleteRecovery("approval-tenant-b", "evidence://tenant-b-recovery", half.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, half.Version, recovered); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.GetOrCreateTemporalTurn(ctx, b.TenantID, b.RunID, b.WorkflowID, secondTemporalExecutionID, 1); !errors.Is(err, postgres.ErrTemporalTurnUntrustedRun) {
		t.Fatalf("recovered CLOSED breaker silently reauthorized stale Turn epoch: %v", err)
	}

	var attempts, turns int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM runtime_run_attempts), (SELECT count(*) FROM runtime_decision_turns)").Scan(&attempts, &turns); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || turns != 2 {
		t.Fatalf("denied cross-tenant/revoked replays mutated durable state: attempts=%d turns=%d", attempts, turns)
	}
}


// Until an explicit generation transition is implemented, Temporal Turn
// binding must reject a current pointer that claims any generation other
// than one. This fixture simulates privileged catalog drift after startup:
// the v13 CHECK and immutable trigger are weakened after the Store is live.
// Startup catalog verification alone cannot protect an already-running
// process from later out-of-band DDL/DML.
func TestTemporalTurnRejectsUnsupportedCurrentAttemptGeneration(t *testing.T) {
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
	ref := run.AcceptedDecisionRef{
		TenantID: accepted.TenantID, RunID: accepted.RunID, WorkflowID: accepted.WorkflowID,
		RunIntentID: accepted.RunIntentID, RequestDigest: accepted.RequestDigest,
	}
	checkpoint, err := store.PrepareAcceptedDecision(ctx, ref, firstTemporalExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.RunID != ref.RunID || checkpoint.TurnID == "" {
		t.Fatalf("initial business checkpoint missing: %+v", checkpoint)
	}

	// This is not a supported generation transition. It deliberately bypasses
	// the database guard after startup to prove the live read path still fails
	// closed if the schema is weakened while a worker remains running.
	if _, err := pool.Exec(ctx, `
		ALTER TABLE runtime_current_attempts DISABLE TRIGGER runtime_current_attempt_no_mutation;
		ALTER TABLE runtime_current_attempts DROP CONSTRAINT runtime_current_attempts_generation_check;
		UPDATE runtime_current_attempts SET generation=2
		WHERE tenant_id=$1 AND run_id=$2::uuid
	`, ref.TenantID, ref.RunID); err != nil {
		t.Fatalf("simulate post-startup generation drift: %v", err)
	}

	if got, err := store.GetOrCreateTemporalTurn(ctx, ref.TenantID, ref.RunID, ref.WorkflowID, firstTemporalExecutionID, 2); err == nil || got != (run.TemporalTurnIdentity{}) {
		t.Fatalf("unsupported generation created a new Temporal Turn: %+v err=%v", got, err)
	}
	if got, err := store.PrepareAcceptedDecision(ctx, ref, firstTemporalExecutionID); err == nil || got != (run.DecisionCheckpoint{}) {
		t.Fatalf("unsupported generation replayed a business checkpoint: %+v err=%v", got, err)
	}

	var generation, turns, checkpoints, acceptances int
	var status string
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT generation FROM runtime_current_attempts WHERE tenant_id=$1 AND run_id=$2::uuid),
			(SELECT count(*) FROM runtime_decision_turns WHERE tenant_id=$1 AND run_id=$2::uuid),
			(SELECT count(*) FROM runtime_decision_checkpoints WHERE tenant_id=$1 AND run_id=$2::uuid),
			(SELECT count(*) FROM runtime_decision_acceptances WHERE tenant_id=$1 AND run_id=$2::uuid),
			(SELECT status FROM runs WHERE tenant_id=$1 AND run_id=$2::uuid)
	`, ref.TenantID, ref.RunID).Scan(&generation, &turns, &checkpoints, &acceptances, &status); err != nil {
		t.Fatal(err)
	}
	if generation != 2 || turns != 1 || checkpoints != 1 || acceptances != 0 || status != "RUNNING" {
		t.Fatalf("rejected generation drift changed durable business state: generation=%d turns=%d checkpoints=%d acceptances=%d status=%s",
			generation, turns, checkpoints, acceptances, status)
	}
}
