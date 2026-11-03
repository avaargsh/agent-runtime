package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AcceptIntent atomically records an ACP RunIntent, the Runtime-owned Run ID,
// and one Temporal start outbox row. No workflow start happens in the SQL tx.
// Caller authentication and ACP ownership verification MUST happen upstream.
func (s *Store) AcceptIntent(ctx context.Context, command run.IntentStartRequest) (run.IntentReceipt, error) {
	if s == nil || s.pool == nil {
		return run.IntentReceipt{}, run.ErrRepositoryUnavailable
	}
	if err := command.Validate(); err != nil {
		return run.IntentReceipt{}, err
	}
	input, err := run.CanonicalIntentInput(command.Input)
	if err != nil {
		return run.IntentReceipt{}, run.ErrInvalidRequest
	}
	id := uuid.NewString()
	workflow := run.ACPWorkflowPrefix + id
	// Namespace the submission key so generic experimental StartRun callers
	// cannot accidentally reuse the same key without causing a conflict.
	idem := "run-intent:" + command.RunIntentID
	now := time.Now().UTC()
	digestHex := strings.TrimPrefix(command.RequestDigest, "sha256:")
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return run.IntentReceipt{}, fmt.Errorf("begin ACP RunIntent acceptance: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var storedID, storedWorkflow string
	err = tx.QueryRow(ctx, `
       INSERT INTO runs
       (run_id,tenant_id,agent_id,agent_release_id,session_id,
        idempotency_key,request_digest,workflow_id,status,input,
        created_at,updated_at,run_intent_id,source_request_digest)
       VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,'QUEUED',$9::jsonb,$10,$10,$11::uuid,$12)
       ON CONFLICT DO NOTHING
       RETURNING run_id::text,workflow_id
    `, id, command.TenantID, command.AgentID, command.AgentReleaseID,
		command.SessionID, idem, digestHex, workflow, string(input), now,
		command.RunIntentID, command.RequestDigest).Scan(&storedID, &storedWorkflow)
	if err == nil {
		_, err = tx.Exec(ctx, `
           INSERT INTO runtime_outbox
           (outbox_id,tenant_id,aggregate_id,event_type,payload,created_at,available_at)
           VALUES ($1::uuid,$2,$3::uuid,$4,
              jsonb_build_object('tenant_id',$2::text,'run_intent_id',$5::text,
                 'request_digest',$6::text,'run_id',$3::text,'workflow_id',$7::text),
              $8,$8)`,
			uuid.NewString(), command.TenantID, storedID, runStartEventType,
			command.RunIntentID, command.RequestDigest, storedWorkflow, now)
		if err != nil {
			return run.IntentReceipt{}, fmt.Errorf("insert ACP Run start outbox: %w", err)
		}
		if err = tx.Commit(ctx); err != nil {
			return run.IntentReceipt{}, fmt.Errorf("commit ACP Run: %w", err)
		}
		return run.IntentReceipt{TenantID: command.TenantID, RunIntentID: command.RunIntentID,
			RequestDigest: command.RequestDigest, RunID: storedID, WorkflowID: storedWorkflow, Created: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return run.IntentReceipt{}, fmt.Errorf("insert ACP Run: %w", err)
	}
	receipt, err := lookupIntentRow(ctx, tx, command.TenantID, command.RunIntentID, command.RequestDigest)
	if err != nil {
		return run.IntentReceipt{}, err
	}
	var agent, release, session string
	var sameInput bool
	err = tx.QueryRow(ctx, `
       SELECT agent_id,agent_release_id,session_id,input=$2::jsonb
       FROM runs WHERE run_intent_id=$1::uuid FOR UPDATE
    `, command.RunIntentID, string(input)).Scan(&agent, &release, &session, &sameInput)
	if err != nil {
		return run.IntentReceipt{}, fmt.Errorf("verify ACP Run binding: %w", err)
	}
	if agent != command.AgentID || release != command.AgentReleaseID ||
		session != command.SessionID || !sameInput {
		return run.IntentReceipt{}, run.ErrIdempotencyConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return run.IntentReceipt{}, fmt.Errorf("commit ACP replay: %w", err)
	}
	return receipt, nil
}

// LookupIntent can prove FOUND from the durable registry. Absence is only
// ABSENT_UNCERTAIN: a concurrent uncommitted acceptance may still commit.
// Never translate ErrIntentNotFound to ACP NOT_FOUND_FINAL automatically.
func (s *Store) LookupIntent(ctx context.Context, tenantID, intentID, digest string) (run.IntentReceipt, error) {
	if s == nil || s.pool == nil {
		return run.IntentReceipt{}, run.ErrRepositoryUnavailable
	}
	if err := (run.IntentStartRequest{TenantID: tenantID, RunIntentID: intentID,
		RequestDigest: digest, AgentID: "lookup", AgentReleaseID: "lookup", SessionID: "lookup"}).Validate(); err != nil {
		return run.IntentReceipt{}, err
	}
	return lookupIntentRow(ctx, s.pool, tenantID, intentID, digest)
}

type intentRow interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func lookupIntentRow(ctx context.Context, q intentRow, tenantID, intentID, digest string) (run.IntentReceipt, error) {
	var id, workflow, tenant, source string
	err := q.QueryRow(ctx, `
        SELECT run_id::text,workflow_id,tenant_id,source_request_digest
        FROM runs WHERE run_intent_id=$1::uuid
    `, intentID).Scan(&id, &workflow, &tenant, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return run.IntentReceipt{}, run.ErrIntentNotFound
	}
	if err != nil {
		return run.IntentReceipt{}, fmt.Errorf("inspect ACP Run intent: %w", err)
	}
	if tenant != tenantID || source != digest || workflow != run.ACPWorkflowPrefix+id {
		return run.IntentReceipt{}, run.ErrIdempotencyConflict
	}
	return run.IntentReceipt{TenantID: tenant, RunIntentID: intentID,
		RequestDigest: source, RunID: id, WorkflowID: workflow}, nil
}
