package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-runtime/internal/executionsafety"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const proposalColumns = `
	tenant_id, proposal_id, run_id, turn_id, intent_revision,
	arguments_digest, action_request_digest, tool_policy, state, version,
	guard_submission_key, guard_operation_id, confirmation_actor_id,
	confirmation_ref
`

type intentScope struct {
	Revision int64
	Digest   string
	Complete bool
}

func (s *Store) AdvanceIntentRevision(ctx context.Context, incoming executionsafety.IntentRevision) error {
	if s == nil || s.pool == nil {
		return executionsafety.ErrNotFound
	}
	if err := validateIntentRevision(incoming); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin intent revision transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := requireAuthoritativeRun(ctx, tx, incoming.TenantID, incoming.RunID); err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
		INSERT INTO execution_intents
			(tenant_id, run_id, turn_id, current_revision, intent_digest, complete, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
		ON CONFLICT (tenant_id,run_id,turn_id) DO NOTHING
	`, incoming.TenantID, incoming.RunID, incoming.TurnID, incoming.Revision, incoming.Digest, incoming.Complete, now)
	if err != nil {
		return fmt.Errorf("claim intent identity: %w", err)
	}

	var current intentScope
	err = tx.QueryRow(ctx, `
		SELECT current_revision, intent_digest, complete
		FROM execution_intents
		WHERE tenant_id=$1 AND run_id=$2 AND turn_id=$3
		FOR UPDATE
	`, incoming.TenantID, incoming.RunID, incoming.TurnID).Scan(&current.Revision, &current.Digest, &current.Complete)
	if err != nil {
		return fmt.Errorf("lock current intent revision: %w", err)
	}

	advanced := false
	switch {
	case incoming.Revision < current.Revision:
		return executionsafety.ErrStaleIntent
	case incoming.Revision == current.Revision:
		if incoming.Digest != current.Digest {
			return executionsafety.ErrIntentRevisionConflict
		}
		if current.Complete && !incoming.Complete {
			return executionsafety.ErrStaleIntent
		}
		if incoming.Complete && !current.Complete {
			_, err = tx.Exec(ctx, `
				UPDATE execution_intents SET complete=TRUE, updated_at=$1
				WHERE tenant_id=$2 AND run_id=$3 AND turn_id=$4
			`, now, incoming.TenantID, incoming.RunID, incoming.TurnID)
			if err != nil {
				return fmt.Errorf("complete intent revision: %w", err)
			}
		}
	case incoming.Revision > current.Revision:
		_, err = tx.Exec(ctx, `
			UPDATE execution_intents
			SET current_revision=$1, intent_digest=$2, complete=$3, updated_at=$4
			WHERE tenant_id=$5 AND run_id=$6 AND turn_id=$7
		`, incoming.Revision, incoming.Digest, incoming.Complete, now,
			incoming.TenantID, incoming.RunID, incoming.TurnID)
		if err != nil {
			return fmt.Errorf("advance intent revision: %w", err)
		}
		advanced = true
	}

	if advanced {
		rows, queryErr := tx.Query(ctx, `
			SELECT `+proposalColumns+`
			FROM execution_proposals
			WHERE tenant_id=$1 AND run_id=$2 AND turn_id=$3
			  AND intent_revision < $4 AND state IN ('PROPOSED','PREPARED')
			ORDER BY proposal_id
			FOR UPDATE
		`, incoming.TenantID, incoming.RunID, incoming.TurnID, incoming.Revision)
		if queryErr != nil {
			return fmt.Errorf("lock stale proposals: %w", queryErr)
		}
		var stale []executionsafety.Proposal
		for rows.Next() {
			p, scanErr := scanProposal(rows)
			if scanErr != nil {
				rows.Close()
				return fmt.Errorf("scan stale proposal: %w", scanErr)
			}
			stale = append(stale, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read stale proposals: %w", err)
		}

		for _, proposal := range stale {
			superseded, transitionErr := proposal.Supersede(incoming.Revision)
			if transitionErr != nil {
				return fmt.Errorf("supersede stale proposal %s: %w", proposal.ID, transitionErr)
			}
			if err := updateProposal(ctx, tx, superseded, now); err != nil {
				return err
			}
			if err := insertProposalEvidence(ctx, tx, superseded, "ToolProposalSuperseded", map[string]any{
				"proposal_id":              superseded.ID,
				"previous_intent_revision": proposal.IntentRevision,
				"superseded_by_revision":   incoming.Revision,
				"state":                    string(superseded.State),
			}, now); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit intent revision: %w", err)
	}
	return nil
}

func (s *Store) CreateProposal(ctx context.Context, proposal executionsafety.Proposal) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	if err := validateProposalForCreate(proposal); err != nil {
		return executionsafety.Proposal{}, err
	}
	policy, err := json.Marshal(proposal.ToolPolicy)
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("marshal trusted ToolPolicy: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("begin proposal creation: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// A legacy intent row does not prove its Run still exists or belongs to
	// this tenant. Verify the authoritative Runtime Run before admitting work.
	if err := requireAuthoritativeRun(ctx, tx, proposal.TenantID, proposal.RunID); err != nil {
		return executionsafety.Proposal{}, err
	}
	var currentRevision int64
	err = tx.QueryRow(ctx, `
		SELECT current_revision FROM execution_intents
		WHERE tenant_id=$1 AND run_id=$2 AND turn_id=$3
		FOR UPDATE
	`, proposal.TenantID, proposal.RunID, proposal.TurnID).Scan(&currentRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("read current intent: %w", err)
	}
	if currentRevision != proposal.IntentRevision {
		return executionsafety.Proposal{}, executionsafety.ErrStaleIntent
	}

	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `
		INSERT INTO execution_proposals (
			tenant_id, proposal_id, run_id, turn_id, intent_revision,
			arguments_digest, action_request_digest, tool_policy, state, version,
			guard_submission_key, guard_operation_id, confirmation_actor_id,
			confirmation_ref, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,NULL,NULL,NULL,NULL,$11,$11)
		ON CONFLICT (tenant_id,proposal_id) DO NOTHING
	`, proposal.TenantID, proposal.ID, proposal.RunID, proposal.TurnID, proposal.IntentRevision,
		proposal.ArgumentsDigest, proposal.ActionRequestDigest, string(policy), string(proposal.State), proposal.Version, now)
	if err != nil {
		return executionsafety.Proposal{}, mapProposalWriteError(err)
	}
	if tag.RowsAffected() == 0 {
		existing, scanErr := scanProposal(tx.QueryRow(ctx, `
			SELECT `+proposalColumns+` FROM execution_proposals
			WHERE tenant_id=$1 AND proposal_id=$2 FOR UPDATE
		`, proposal.TenantID, proposal.ID))
		if scanErr != nil {
			return executionsafety.Proposal{}, fmt.Errorf("load duplicate proposal: %w", scanErr)
		}
		if !sameProposalIdentity(existing, proposal) {
			return executionsafety.Proposal{}, executionsafety.ErrIdempotencyKeyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return executionsafety.Proposal{}, fmt.Errorf("commit proposal replay: %w", err)
		}
		return existing, nil
	}

	if err := insertProposalEvidence(ctx, tx, proposal, "ToolProposalCreated", map[string]any{
		"proposal_id":           proposal.ID,
		"intent_revision":       proposal.IntentRevision,
		"arguments_digest":      proposal.ArgumentsDigest,
		"action_request_digest": proposal.ActionRequestDigest,
		"state":                 string(proposal.State),
	}, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("commit proposal creation: %w", err)
	}
	return proposal, nil
}

func (s *Store) PrepareProposal(ctx context.Context, tenantID, proposalID string, expectedVersion int64, capabilityAllowed bool) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("begin prepare transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	scope, err := readProposalScope(ctx, tx, tenantID, proposalID)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := requireAuthoritativeRun(ctx, tx, tenantID, scope.RunID); err != nil {
		return executionsafety.Proposal{}, err
	}
	var currentRevision int64
	err = tx.QueryRow(ctx, `
		SELECT current_revision FROM execution_intents
		WHERE tenant_id=$1 AND run_id=$2 AND turn_id=$3 FOR UPDATE
	`, tenantID, scope.RunID, scope.TurnID).Scan(&currentRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("lock intent for prepare: %w", err)
	}

	proposal, err := scanProposal(tx.QueryRow(ctx, `
		SELECT `+proposalColumns+` FROM execution_proposals
		WHERE tenant_id=$1 AND proposal_id=$2 FOR UPDATE
	`, tenantID, proposalID))
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if proposal.Version != expectedVersion {
		return executionsafety.Proposal{}, executionsafety.ErrVersionConflict
	}
	prepared, err := proposal.Prepare(currentRevision, capabilityAllowed)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	now := time.Now().UTC()
	if err := updateProposal(ctx, tx, prepared, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := insertProposalEvidence(ctx, tx, prepared, "ToolProposalPrepared", map[string]any{
		"proposal_id": prepared.ID, "intent_revision": prepared.IntentRevision, "state": string(prepared.State),
	}, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("commit proposal prepare: %w", err)
	}
	return prepared, nil
}

func (s *Store) CommitProposal(ctx context.Context, tenantID, proposalID string, expectedVersion int64, conditions executionsafety.CommitConditions) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("begin proposal Commit transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	scope, err := readProposalScope(ctx, tx, tenantID, proposalID)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := requireAuthoritativeRun(ctx, tx, tenantID, scope.RunID); err != nil {
		return executionsafety.Proposal{}, err
	}
	var intent intentScope
	err = tx.QueryRow(ctx, `
		SELECT current_revision, intent_digest, complete
		FROM execution_intents
		WHERE tenant_id=$1 AND run_id=$2 AND turn_id=$3
		FOR UPDATE
	`, tenantID, scope.RunID, scope.TurnID).Scan(&intent.Revision, &intent.Digest, &intent.Complete)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("lock current intent for Commit: %w", err)
	}

	proposal, err := scanProposal(tx.QueryRow(ctx, `
		SELECT `+proposalColumns+` FROM execution_proposals
		WHERE tenant_id=$1 AND proposal_id=$2 FOR UPDATE
	`, tenantID, proposalID))
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	isReplay := proposal.State == executionsafety.ProposalCommitAuthorized ||
		proposal.State == executionsafety.ProposalSubmittedToGuard
	if !isReplay && proposal.Version != expectedVersion {
		return executionsafety.Proposal{}, executionsafety.ErrVersionConflict
	}
	// The database owns the current revision/completion flags. Caller-supplied
	// values are overwritten inside the same transaction as the state change.
	conditions.CurrentIntentRevision = intent.Revision
	conditions.IntentComplete = intent.Complete
	committed, err := proposal.AuthorizeCommit(conditions)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if committed.Version == proposal.Version {
		if err := tx.Commit(ctx); err != nil {
			return executionsafety.Proposal{}, fmt.Errorf("commit idempotent proposal Commit replay: %w", err)
		}
		return proposal, nil
	}

	now := time.Now().UTC()
	if err := updateProposal(ctx, tx, committed, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := insertProposalEvidence(ctx, tx, committed, "ProposalCommitAuthorized", map[string]any{
		"proposal_id":           committed.ID,
		"intent_revision":       committed.IntentRevision,
		"action_request_digest": committed.ActionRequestDigest,
		"guard_submission_key":  committed.GuardSubmissionKey,
		"confirmation_ref":      committed.ConfirmationRef,
		"state":                 string(committed.State),
	}, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("commit authorized proposal: %w", err)
	}
	return committed, nil
}

func (s *Store) LinkGuardOperation(ctx context.Context, tenantID, proposalID string, expectedVersion int64, link executionsafety.GuardOperationLink) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("begin Guard operation link: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	proposal, err := scanProposal(tx.QueryRow(ctx, `
		SELECT `+proposalColumns+` FROM execution_proposals
		WHERE tenant_id=$1 AND proposal_id=$2 FOR UPDATE
	`, tenantID, proposalID))
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := requireAuthoritativeRun(ctx, tx, tenantID, proposal.RunID); err != nil {
		return executionsafety.Proposal{}, err
	}
	isReplay := proposal.State == executionsafety.ProposalSubmittedToGuard
	if !isReplay && proposal.Version != expectedVersion {
		return executionsafety.Proposal{}, executionsafety.ErrVersionConflict
	}
	submitted, err := proposal.MarkSubmittedToGuard(link)
	if err != nil {
		return executionsafety.Proposal{}, err
	}
	if submitted.Version == proposal.Version {
		if err := tx.Commit(ctx); err != nil {
			return executionsafety.Proposal{}, fmt.Errorf("commit idempotent Guard operation link replay: %w", err)
		}
		return proposal, nil
	}
	now := time.Now().UTC()
	if err := updateProposal(ctx, tx, submitted, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := insertProposalEvidence(ctx, tx, submitted, "GuardOperationLinked", map[string]any{
		"proposal_id":           submitted.ID,
		"guard_operation_id":    submitted.GuardOperationID,
		"action_request_digest": submitted.ActionRequestDigest,
		"state":                 string(submitted.State),
	}, now); err != nil {
		return executionsafety.Proposal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("commit Guard operation link: %w", err)
	}
	return submitted, nil
}

func (s *Store) GetProposal(ctx context.Context, tenantID, proposalID string) (executionsafety.Proposal, error) {
	if s == nil || s.pool == nil {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	return scanProposal(s.pool.QueryRow(ctx, `
		SELECT `+proposalColumns+` FROM execution_proposals
		WHERE tenant_id=$1 AND proposal_id=$2
	`, tenantID, proposalID))
}

func (s *Store) ListProposalEvidence(ctx context.Context, tenantID, proposalID string) ([]executionsafety.EvidenceRecord, error) {
	if _, err := s.GetProposal(ctx, tenantID, proposalID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT event_id::text, tenant_id, proposal_id, event_type,
			proposal_version, intent_revision, payload, created_at
		FROM execution_evidence
		WHERE tenant_id=$1 AND proposal_id=$2
		ORDER BY created_at, event_id
	`, tenantID, proposalID)
	if err != nil {
		return nil, fmt.Errorf("query proposal Evidence: %w", err)
	}
	defer rows.Close()
	var result []executionsafety.EvidenceRecord
	for rows.Next() {
		var item executionsafety.EvidenceRecord
		var payload []byte
		var created time.Time
		if err := rows.Scan(&item.EventID, &item.TenantID, &item.ProposalID, &item.EventType,
			&item.ProposalVersion, &item.IntentRevision, &payload, &created); err != nil {
			return nil, fmt.Errorf("scan proposal Evidence: %w", err)
		}
		item.Payload = append(json.RawMessage(nil), payload...)
		item.CreatedAt = created.UTC().Format(time.RFC3339Nano)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate proposal Evidence: %w", err)
	}
	return result, nil
}

type proposalScope struct {
	RunID  string
	TurnID string
}

func readProposalScope(ctx context.Context, tx pgx.Tx, tenantID, proposalID string) (proposalScope, error) {
	var result proposalScope
	err := tx.QueryRow(ctx, `
		SELECT run_id, turn_id FROM execution_proposals
		WHERE tenant_id=$1 AND proposal_id=$2
	`, tenantID, proposalID).Scan(&result.RunID, &result.TurnID)
	if errors.Is(err, pgx.ErrNoRows) {
		return proposalScope{}, executionsafety.ErrNotFound
	}
	if err != nil {
		return proposalScope{}, fmt.Errorf("read proposal scope: %w", err)
	}
	return result, nil
}

type proposalRow interface {
	Scan(dest ...any) error
}

func scanProposal(row proposalRow) (executionsafety.Proposal, error) {
	var p executionsafety.Proposal
	var state string
	var policy []byte
	var guardKey, operationID, confirmationActor, confirmationRef pgtype.Text
	err := row.Scan(
		&p.TenantID, &p.ID, &p.RunID, &p.TurnID, &p.IntentRevision,
		&p.ArgumentsDigest, &p.ActionRequestDigest, &policy, &state, &p.Version,
		&guardKey, &operationID, &confirmationActor, &confirmationRef,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionsafety.Proposal{}, executionsafety.ErrNotFound
	}
	if err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("scan execution proposal: %w", err)
	}
	if err := json.Unmarshal(policy, &p.ToolPolicy); err != nil {
		return executionsafety.Proposal{}, fmt.Errorf("decode trusted ToolPolicy: %w", err)
	}
	p.State = executionsafety.ProposalState(state)
	if guardKey.Valid {
		p.GuardSubmissionKey = guardKey.String
	}
	if operationID.Valid {
		p.GuardOperationID = operationID.String
	}
	if confirmationActor.Valid {
		p.ConfirmationActorID = confirmationActor.String
	}
	if confirmationRef.Valid {
		p.ConfirmationRef = confirmationRef.String
	}
	return p, nil
}

func updateProposal(ctx context.Context, tx pgx.Tx, p executionsafety.Proposal, now time.Time) error {
	tag, err := tx.Exec(ctx, `
		UPDATE execution_proposals
		SET state=$1, version=$2, guard_submission_key=NULLIF($3,''),
			guard_operation_id=NULLIF($4,''), confirmation_actor_id=NULLIF($5,''),
			confirmation_ref=NULLIF($6,''), updated_at=$7
		WHERE tenant_id=$8 AND proposal_id=$9 AND version=$10
	`, string(p.State), p.Version, p.GuardSubmissionKey, p.GuardOperationID,
		p.ConfirmationActorID, p.ConfirmationRef, now, p.TenantID, p.ID, p.Version-1)
	if err != nil {
		return mapProposalWriteError(fmt.Errorf("update execution proposal: %w", err))
	}
	if tag.RowsAffected() != 1 {
		return executionsafety.ErrVersionConflict
	}
	return nil
}

func insertProposalEvidence(ctx context.Context, tx pgx.Tx, p executionsafety.Proposal, eventType string, payload map[string]any, now time.Time) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal Evidence metadata: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO execution_evidence
			(event_id, tenant_id, proposal_id, event_type, proposal_version, intent_revision, payload, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
	`, uuid.NewString(), p.TenantID, p.ID, eventType, p.Version, p.IntentRevision, string(data), now)
	if err != nil {
		return fmt.Errorf("append proposal Evidence: %w", err)
	}
	return nil
}

// requireAuthoritativeRun is the common fail-closed ownership fence for
// both new and legacy Execution Safety records. The key-share lock is held
// until the caller commits or rolls back its state transition.
func requireAuthoritativeRun(ctx context.Context, tx pgx.Tx, tenantID, runID string) error {
	parsedRunID, err := uuid.Parse(runID)
	if err != nil || parsedRunID.String() != runID {
		return executionsafety.ErrInvalidProposal
	}
	var persistedRunID string
	err = tx.QueryRow(ctx, `
		SELECT run_id::text FROM runs
		WHERE tenant_id=$1 AND run_id=$2::uuid
		FOR KEY SHARE
	`, tenantID, runID).Scan(&persistedRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionsafety.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("verify authoritative execution Run: %w", err)
	}
	if persistedRunID != runID {
		return executionsafety.ErrInvalidProposal
	}
	return nil
}

func validateIntentRevision(in executionsafety.IntentRevision) error {
	for _, value := range []string{in.TenantID, in.RunID, in.TurnID} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 255 || strings.ContainsRune(value, 0) {
			return executionsafety.ErrInvalidProposal
		}
	}
	parsedRunID, err := uuid.Parse(in.RunID)
	if err != nil || parsedRunID.String() != in.RunID {
		return executionsafety.ErrInvalidProposal
	}
	if in.Revision < 1 || !isSHA256Digest(in.Digest) {
		return executionsafety.ErrInvalidProposal
	}
	return nil
}

func validateProposalForCreate(p executionsafety.Proposal) error {
	rebuilt, err := executionsafety.NewProposal(executionsafety.ProposalInput{
		ID: p.ID, TenantID: p.TenantID, RunID: p.RunID, TurnID: p.TurnID,
		IntentRevision: p.IntentRevision, ArgumentsDigest: p.ArgumentsDigest,
		ActionRequestDigest: p.ActionRequestDigest, ToolPolicy: p.ToolPolicy,
	})
	if err != nil {
		return err
	}
	if p.State != executionsafety.ProposalProposed || p.Version != 1 ||
		p.GuardSubmissionKey != "" || p.GuardOperationID != "" ||
		p.ConfirmationActorID != "" || p.ConfirmationRef != "" ||
		!sameProposalIdentity(rebuilt, p) {
		return executionsafety.ErrInvalidProposal
	}
	return nil
}

func sameProposalIdentity(a, b executionsafety.Proposal) bool {
	ap, _ := json.Marshal(a.ToolPolicy)
	bp, _ := json.Marshal(b.ToolPolicy)
	return a.ID == b.ID && a.TenantID == b.TenantID && a.RunID == b.RunID &&
		a.TurnID == b.TurnID && a.IntentRevision == b.IntentRevision &&
		a.ArgumentsDigest == b.ArgumentsDigest && a.ActionRequestDigest == b.ActionRequestDigest &&
		string(ap) == string(bp)
}

func mapProposalWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return executionsafety.ErrIdempotencyKeyConflict
	}
	return err
}

func isSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

var _ executionsafety.Repository = (*Store)(nil)
