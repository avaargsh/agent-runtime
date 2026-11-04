package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-runtime/internal/executionsafety"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrTurnIntentNotFound       = errors.New("TurnIntent not found")
	ErrTurnRevisionConflict     = errors.New("TurnIntent revision conflict")
	ErrProposalNotFound         = errors.New("Tool Proposal not found")
	ErrProposalVersionConflict  = errors.New("Tool Proposal version conflict")
	ErrProposalIdentityConflict = errors.New("Tool Proposal identity reused with different immutable content")
)

// TurnIntent is a Runtime-owned snapshot of the current interaction intent.
// ACP continues to own the canonical Session identity and desired-state policy.
type TurnIntent struct {
	TenantID  string
	RunID     string
	TurnID    string
	Revision  int64
	Complete  bool
	Version   int64
	UpdatedAt time.Time
}

const proposalColumns = `
	tenant_id, proposal_id, run_id::text, turn_id, intent_revision,
	arguments_digest, action_request_digest, tool_policy::text, state, version,
	guard_submission_key, guard_operation_id, confirmation_actor_id,
	confirmation_ref, created_at, updated_at
`

// CreateTurnIntent establishes the row that serializes Proposal admission,
// intent correction and Commit authorization. An identical replay is a no-op.
func (s *Store) CreateTurnIntent(ctx context.Context, intent TurnIntent) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL pool is unavailable")
	}
	if err := validateTurnIntent(intent); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin TurnIntent creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `
		INSERT INTO runtime_turn_intents
			(tenant_id, run_id, turn_id, intent_revision, intent_complete, version, created_at, updated_at)
		VALUES ($1, $2::uuid, $3, $4, $5, 1, $6, $6)
		ON CONFLICT (tenant_id, run_id, turn_id) DO NOTHING
	`, intent.TenantID, intent.RunID, intent.TurnID, intent.Revision, intent.Complete, now)
	if err != nil {
		return fmt.Errorf("insert TurnIntent: %w", err)
	}
	if tag.RowsAffected() == 1 {
		intent.Version = 1
		intent.UpdatedAt = now
		if err := appendTurnEvent(ctx, tx, "TurnIntentCreated", intent, now); err != nil {
			return err
		}
	} else {
		existing, err := loadTurnIntent(ctx, tx, intent.TenantID, intent.RunID, intent.TurnID, true)
		if err != nil {
			return err
		}
		if existing.Revision != intent.Revision || existing.Complete != intent.Complete {
			return ErrTurnRevisionConflict
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit TurnIntent creation: %w", err)
	}
	return nil
}

// AdvanceTurnIntent commits a new intent revision and invalidates all older
// uncommitted proposals in one transaction. It takes the TurnIntent row lock
// before any Proposal lock; CommitProposal uses the same lock order.
func (s *Store) AdvanceTurnIntent(
	ctx context.Context,
	tenantID, runID, turnID string,
	expectedRevision, newRevision int64,
	complete bool,
) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL pool is unavailable")
	}
	if tenantID == "" || turnID == "" || expectedRevision < 1 || newRevision <= expectedRevision {
		return ErrTurnRevisionConflict
	}
	if _, err := uuid.Parse(runID); err != nil {
		return fmt.Errorf("invalid Run ID: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin TurnIntent advance: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	intent, err := loadTurnIntent(ctx, tx, tenantID, runID, turnID, true)
	if err != nil {
		return err
	}
	if intent.Revision != expectedRevision {
		return ErrTurnRevisionConflict
	}
	now := time.Now().UTC()
	intent.Revision = newRevision
	intent.Complete = complete
	intent.Version++
	intent.UpdatedAt = now
	tag, err := tx.Exec(ctx, `
		UPDATE runtime_turn_intents
		SET intent_revision=$1, intent_complete=$2, version=$3, updated_at=$4
		WHERE tenant_id=$5 AND run_id=$6::uuid AND turn_id=$7 AND version=$8
	`, intent.Revision, intent.Complete, intent.Version, now,
		intent.TenantID, intent.RunID, intent.TurnID, intent.Version-1)
	if err != nil {
		return fmt.Errorf("advance TurnIntent revision: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrTurnRevisionConflict
	}
	if err := appendTurnEvent(ctx, tx, "TurnIntentRevised", intent, now); err != nil {
		return err
	}

	rows, err := tx.Query(ctx, `
		SELECT `+proposalColumns+`
		FROM runtime_proposals
		WHERE tenant_id=$1 AND run_id=$2::uuid AND turn_id=$3
		  AND intent_revision < $4 AND state IN ('PROPOSED','PREPARED')
		ORDER BY proposal_id
		FOR UPDATE
	`, tenantID, runID, turnID, newRevision)
	if err != nil {
		return fmt.Errorf("select stale Proposals: %w", err)
	}
	var stale []executionsafety.Proposal
	for rows.Next() {
		proposal, scanErr := scanProposal(rows)
		if scanErr != nil {
			rows.Close()
			return scanErr
		}
		stale = append(stale, proposal)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read stale Proposals: %w", err)
	}
	rows.Close()

	for _, old := range stale {
		next, err := old.Supersede(newRevision)
		if err != nil {
			return fmt.Errorf("supersede stale Proposal %s: %w", old.ID, err)
		}
		if err := persistProposal(ctx, tx, old, next, now); err != nil {
			return err
		}
		if err := appendProposalEvent(ctx, tx, "ToolProposalSuperseded", next, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit TurnIntent advance: %w", err)
	}
	return nil
}

// CreateProposal persists a new untrusted Tool Proposal against the exact
// current Turn revision. The current Turn row is locked before insertion.
func (s *Store) CreateProposal(ctx context.Context, proposal executionsafety.Proposal) error {
	if s == nil || s.pool == nil {
		return errors.New("PostgreSQL pool is unavailable")
	}
	validated, err := validateNewProposal(proposal)
	if err != nil {
		return err
	}
	policyJSON, err := json.Marshal(validated.ToolPolicy)
	if err != nil {
		return fmt.Errorf("marshal ToolPolicy: %w", err)
	}
	if _, err := uuid.Parse(validated.RunID); err != nil {
		return fmt.Errorf("invalid Run ID: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Proposal creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// TurnIntent is always the first write lock. A replay must be resolved
	// before comparing against the latest revision: the original Proposal may
	// already have been prepared, superseded or committed after its ACK was lost.
	intent, err := loadTurnIntent(ctx, tx, validated.TenantID, validated.RunID, validated.TurnID, true)
	if err != nil {
		return err
	}
	existing, err := loadProposal(ctx, tx, validated.TenantID, validated.ID, true)
	if err == nil {
		if !sameProposalIdentity(existing, validated) {
			return ErrProposalIdentityConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit idempotent Proposal create replay: %w", err)
		}
		return nil
	}
	if !errors.Is(err, ErrProposalNotFound) {
		return err
	}
	if intent.Revision != validated.IntentRevision {
		return executionsafety.ErrStaleIntent
	}

	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
		INSERT INTO runtime_proposals (
			tenant_id, proposal_id, run_id, turn_id, intent_revision,
			arguments_digest, action_request_digest, tool_policy, state, version,
			guard_submission_key, guard_operation_id, confirmation_actor_id,
			confirmation_ref, created_at, updated_at
		)
		VALUES ($1,$2,$3::uuid,$4,$5,$6,$7,$8::jsonb,$9,$10,'','','','',$11,$11)
	`, validated.TenantID, validated.ID, validated.RunID, validated.TurnID,
		validated.IntentRevision, validated.ArgumentsDigest, validated.ActionRequestDigest,
		string(policyJSON), string(validated.State), validated.Version, now)
	if err != nil {
		return fmt.Errorf("insert Tool Proposal: %w", err)
	}
	if err := appendProposalEvent(ctx, tx, "ToolProposalCreated", validated, now); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Tool Proposal creation: %w", err)
	}
	return nil
}

func sameProposalIdentity(existing, candidate executionsafety.Proposal) bool {
	return existing.TenantID == candidate.TenantID &&
		existing.ID == candidate.ID &&
		existing.RunID == candidate.RunID &&
		existing.TurnID == candidate.TurnID &&
		existing.IntentRevision == candidate.IntentRevision &&
		existing.ArgumentsDigest == candidate.ArgumentsDigest &&
		existing.ActionRequestDigest == candidate.ActionRequestDigest &&
		existing.ToolPolicy == candidate.ToolPolicy
}

// PrepareProposal runs side-effect-free Runtime admission against the current
// durable Turn revision. It never crosses the external Commit Boundary.
func (s *Store) PrepareProposal(
	ctx context.Context,
	tenantID, proposalID string,
	capabilityAllowed bool,
) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, errors.New("PostgreSQL pool is unavailable")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("begin Proposal prepare: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	proposal, err := loadProposal(ctx, tx, tenantID, proposalID, false)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	intent, err := loadTurnIntent(ctx, tx, tenantID, proposal.RunID, proposal.TurnID, true)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	// Re-read the Proposal after taking the serialization lock. Every writer
	// locks TurnIntent first, so this lock order is consistent across operations.
	proposal, err = loadProposal(ctx, tx, tenantID, proposalID, true)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if !intent.Complete {
		return executionsafety.Proposal{}, executionsafety.ErrCommitNotAuthorized
	}
	next, err := proposal.Prepare(intent.Revision, capabilityAllowed)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	now := time.Now().UTC()
	if err := persistProposal(ctx, tx, proposal, next, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := appendProposalEvent(ctx, tx, "ToolProposalPrepared", next, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("commit Proposal prepare: %w", err)
	}
	return next, nil
}

// CommitProposal is the durable Runtime Commit Boundary. The authoritative
// Turn revision/completion are loaded while holding the same row lock used by
// AdvanceTurnIntent, so a correction and Commit cannot both win out of order.
func (s *Store) CommitProposal(
	ctx context.Context,
	tenantID, proposalID string,
	conditions executionsafety.CommitConditions,
) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, errors.New("PostgreSQL pool is unavailable")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("begin Proposal Commit: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	proposal, err := loadProposal(ctx, tx, tenantID, proposalID, false)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	intent, err := loadTurnIntent(ctx, tx, tenantID, proposal.RunID, proposal.TurnID, true)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	proposal, err = loadProposal(ctx, tx, tenantID, proposalID, true)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	conditions.CurrentIntentRevision = intent.Revision
	conditions.IntentComplete = intent.Complete
	next, err := proposal.AuthorizeCommit(conditions)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if next.Version == proposal.Version {
		if err := tx.Commit(ctx); err != nil {
			return executionsafety.Proposal{}, fmt.Errorf("commit idempotent Proposal Commit replay: %w", err)
		}
		return next, nil
	}
	now := time.Now().UTC()
	if err := persistProposal(ctx, tx, proposal, next, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := appendProposalEvent(ctx, tx, "ProposalCommitAuthorized", next, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("commit Proposal Commit boundary: %w", err)
	}
	return next, nil
}

// LinkGuardOperation stores an authoritative Guard operation reference after
// the authenticated Guard adapter has validated its response correlation.
func (s *Store) LinkGuardOperation(
	ctx context.Context,
	link executionsafety.GuardOperationLink,
) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, errors.New("PostgreSQL pool is unavailable")
	}
	// Discover immutable Turn coordinates before acquiring locks. The actual
	// write path then follows the global TurnIntent -> Proposal lock order.
	initial, err := loadProposal(ctx, s.pool, link.TenantID, link.ProposalID, false)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("begin Guard operation link: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadTurnIntent(ctx, tx, initial.TenantID, initial.RunID, initial.TurnID, true); err != nil {
		return executionsafety.Proposal{}, err
	}
	proposal, err := loadProposal(ctx, tx, link.TenantID, link.ProposalID, true)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	next, err := proposal.MarkSubmittedToGuard(link)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if next.Version == proposal.Version {
		if err := tx.Commit(ctx); err != nil {
			return executionsafety.Proposal{}, fmt.Errorf("commit idempotent Guard link replay: %w", err)
		}
		return next, nil
	}
	now := time.Now().UTC()
	if err := persistProposal(ctx, tx, proposal, next, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := appendProposalEvent(ctx, tx, "GuardOperationLinked", next, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("commit Guard operation link: %w", err)
	}
	return next, nil
}

func (s *Store) GetProposal(ctx context.Context, tenantID, proposalID string) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, errors.New("PostgreSQL pool is unavailable")
	}
	return loadProposal(ctx, s.pool, tenantID, proposalID, false)
}

type turnIntentQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadTurnIntent(
	ctx context.Context,
	q turnIntentQuerier,
	tenantID, runID, turnID string,
	forUpdate bool,
) (TurnIntent, error) {
	query := `
		SELECT tenant_id, run_id::text, turn_id, intent_revision, intent_complete, version, updated_at
		FROM runtime_turn_intents
		WHERE tenant_id=$1 AND run_id=$2::uuid AND turn_id=$3
	`
	if forUpdate {
		query += " FOR UPDATE"
	}
	var intent TurnIntent
	err := q.QueryRow(ctx, query, tenantID, runID, turnID).Scan(
		&intent.TenantID, &intent.RunID, &intent.TurnID,
		&intent.Revision, &intent.Complete, &intent.Version, &intent.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return TurnIntent{}, ErrTurnIntentNotFound
	}
	if err != nil {
		return TurnIntent{}, fmt.Errorf("load TurnIntent: %w", err)
	}
	return intent, nil
}

type proposalQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadProposal(
	ctx context.Context,
	q proposalQuerier,
	tenantID, proposalID string,
	forUpdate bool,
) (executionsafety.Proposal, error) {
	query := "SELECT " + proposalColumns + " FROM runtime_proposals WHERE tenant_id=$1 AND proposal_id=$2"
	if forUpdate {
		query += " FOR UPDATE"
	}
	proposal, err := scanProposal(q.QueryRow(ctx, query, tenantID, proposalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionsafety.Proposal{}, ErrProposalNotFound
	}
	return proposal, err
}

type proposalScanner interface {
	Scan(...any) error
}

func scanProposal(row proposalScanner) (executionsafety.Proposal, error) {
	var proposal executionsafety.Proposal
	var policyJSON, state string
	err := row.Scan(
		&proposal.TenantID, &proposal.ID, &proposal.RunID, &proposal.TurnID,
		&proposal.IntentRevision, &proposal.ArgumentsDigest, &proposal.ActionRequestDigest,
		&policyJSON, &state, &proposal.Version, &proposal.GuardSubmissionKey,
		&proposal.GuardOperationID, &proposal.ConfirmationActorID,
		&proposal.ConfirmationRef, new(time.Time), new(time.Time),
	)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := json.Unmarshal([]byte(policyJSON), &proposal.ToolPolicy); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("decode persisted ToolPolicy: %w", err)
	}
	proposal.State = executionsafety.ProposalState(state)
	return proposal, nil
}

func validateTurnIntent(intent TurnIntent) error {
	if intent.TenantID == "" || intent.TurnID == "" || intent.Revision < 1 {
		return ErrTurnRevisionConflict
	}
	if _, err := uuid.Parse(intent.RunID); err != nil {
		return fmt.Errorf("invalid Run ID: %w", err)
	}
	return nil
}

func validateNewProposal(proposal executionsafety.Proposal) (executionsafety.Proposal, error) {
	if proposal.State != executionsafety.ProposalProposed || proposal.Version != 1 ||
		proposal.GuardSubmissionKey != "" || proposal.GuardOperationID != "" ||
		proposal.ConfirmationActorID != "" || proposal.ConfirmationRef != "" {
		return executionsafety.Proposal{}, fmt.Errorf("%w: new Proposal must start uncommitted at version 1", executionsafety.ErrInvalidProposal)
	}
	return executionsafety.NewProposal(executionsafety.ProposalInput{
		ID: proposal.ID, TenantID: proposal.TenantID, RunID: proposal.RunID, TurnID: proposal.TurnID,
		IntentRevision: proposal.IntentRevision, ArgumentsDigest: proposal.ArgumentsDigest,
		ActionRequestDigest: proposal.ActionRequestDigest, ToolPolicy: proposal.ToolPolicy,
	})
}

type proposalEventPayload struct {
	TenantID            string                        `json:"tenant_id"`
	RunID               string                        `json:"run_id"`
	TurnID              string                        `json:"turn_id"`
	ProposalID          string                        `json:"proposal_id"`
	IntentRevision      int64                         `json:"intent_revision"`
	ProposalVersion     int64                         `json:"proposal_version"`
	State               executionsafety.ProposalState `json:"state"`
	CapabilityID        string                        `json:"capability_id"`
	CapabilityVersion   string                        `json:"capability_version"`
	PolicyDigest        string                        `json:"policy_digest"`
	ArgumentsDigest     string                        `json:"arguments_digest"`
	ActionRequestDigest string                        `json:"action_request_digest"`
	GuardSubmissionKey  string                        `json:"guard_submission_key,omitempty"`
	GuardOperationID    string                        `json:"guard_operation_id,omitempty"`
	ConfirmationActorID string                        `json:"confirmation_actor_id,omitempty"`
	ConfirmationRef     string                        `json:"confirmation_ref,omitempty"`
}

func appendProposalEvent(
	ctx context.Context,
	tx pgx.Tx,
	eventType string,
	proposal executionsafety.Proposal,
	at time.Time,
) error {
	payload, err := json.Marshal(proposalEventPayload{
		TenantID: proposal.TenantID, RunID: proposal.RunID, TurnID: proposal.TurnID,
		ProposalID: proposal.ID, IntentRevision: proposal.IntentRevision,
		ProposalVersion: proposal.Version, State: proposal.State,
		CapabilityID:        proposal.ToolPolicy.CapabilityID,
		CapabilityVersion:   proposal.ToolPolicy.CapabilityVersion,
		PolicyDigest:        proposal.ToolPolicy.PolicyDigest,
		ArgumentsDigest:     proposal.ArgumentsDigest,
		ActionRequestDigest: proposal.ActionRequestDigest,
		GuardSubmissionKey:  proposal.GuardSubmissionKey,
		GuardOperationID:    proposal.GuardOperationID,
		ConfirmationActorID: proposal.ConfirmationActorID,
		ConfirmationRef:     proposal.ConfirmationRef,
	})
	if err != nil {
		return fmt.Errorf("marshal Proposal event: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO runtime_execution_outbox (
			event_id, tenant_id, run_id, turn_id, aggregate_type, proposal_id,
			aggregate_version, event_type, payload, created_at
		)
		VALUES ($1::uuid,$2,$3::uuid,$4,'TOOL_PROPOSAL',$5,$6,$7,$8::jsonb,$9)
	`, uuid.NewString(), proposal.TenantID, proposal.RunID, proposal.TurnID,
		proposal.ID, proposal.Version, eventType, string(payload), at)
	if err != nil {
		return fmt.Errorf("append Proposal execution event: %w", err)
	}
	return nil
}

func appendTurnEvent(ctx context.Context, tx pgx.Tx, eventType string, intent TurnIntent, at time.Time) error {
	payload, err := json.Marshal(struct {
		TenantID       string    `json:"tenant_id"`
		RunID          string    `json:"run_id"`
		TurnID         string    `json:"turn_id"`
		IntentRevision int64     `json:"intent_revision"`
		IntentComplete bool      `json:"intent_complete"`
		Version        int64     `json:"version"`
		UpdatedAt      time.Time `json:"updated_at"`
	}{
		TenantID: intent.TenantID, RunID: intent.RunID, TurnID: intent.TurnID,
		IntentRevision: intent.Revision, IntentComplete: intent.Complete,
		Version: intent.Version, UpdatedAt: intent.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("marshal TurnIntent event: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO runtime_execution_outbox (
			event_id, tenant_id, run_id, turn_id, aggregate_type, proposal_id,
			aggregate_version, event_type, payload, created_at
		)
		VALUES ($1::uuid,$2,$3::uuid,$4,'TURN_INTENT','',$5,$6,$7::jsonb,$8)
	`, uuid.NewString(), intent.TenantID, intent.RunID, intent.TurnID,
		intent.Version, eventType, string(payload), at)
	if err != nil {
		return fmt.Errorf("append TurnIntent execution event: %w", err)
	}
	return nil
}

func persistProposal(
	ctx context.Context,
	tx pgx.Tx,
	old, next executionsafety.Proposal,
	at time.Time,
) error {
	policyJSON, err := json.Marshal(next.ToolPolicy)
	if err != nil {
		return fmt.Errorf("marshal ToolPolicy: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE runtime_proposals
		SET intent_revision=$1, arguments_digest=$2, action_request_digest=$3,
			tool_policy=$4::jsonb, state=$5, version=$6, guard_submission_key=$7,
			guard_operation_id=$8, confirmation_actor_id=$9, confirmation_ref=$10,
			updated_at=$11
		WHERE tenant_id=$12 AND proposal_id=$13 AND version=$14
	`, next.IntentRevision, next.ArgumentsDigest, next.ActionRequestDigest,
		string(policyJSON), string(next.State), next.Version, next.GuardSubmissionKey,
		next.GuardOperationID, next.ConfirmationActorID, next.ConfirmationRef,
		at, old.TenantID, old.ID, old.Version)
	if err != nil {
		return fmt.Errorf("persist Proposal transition: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrProposalVersionConflict
	}
	return nil
}
