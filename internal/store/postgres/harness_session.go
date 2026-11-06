package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ClaimHarnessSession is an idempotent PostgreSQL-only pre-dispatch claim.
// It MUST be called only with verified Runtime/ACP identity and policy context.
// Its presence never authorizes any Agent tool, terminal or EngageGuard effect.
func (s *Store) ClaimHarnessSession(ctx context.Context, claim acp.SessionClaim) (acp.SessionClaimRecord, error) {
	if s == nil || s.pool == nil {
		return acp.SessionClaimRecord{}, run.ErrRepositoryUnavailable
	}
	if err := claim.Validate(); err != nil {
		return acp.SessionClaimRecord{}, err
	}
	var insertedRunID string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO runtime_harness_session_claims
			(tenant_id, run_id, attempt_id, harness_instance_id,
			 agent_release_id, policy_revision, request_digest, working_dir,
			 state)
		SELECT $1, r.run_id, $3::uuid, $4, $5, $6, $7, $8, 'PREPARED'
		FROM runs AS r
		WHERE r.tenant_id = $1 AND r.run_id = $2::uuid
			AND r.agent_release_id = $5 AND r.status = 'RUNNING'
		ON CONFLICT (tenant_id, run_id) DO NOTHING
		RETURNING run_id::text
	`, claim.TenantID, claim.RunID, claim.AttemptID, claim.HarnessInstanceID,
		claim.AgentReleaseID, claim.PolicyRevision, claim.RequestDigest, claim.WorkingDir).Scan(&insertedRunID)
	if err == nil {
		return acp.SessionClaimRecord{SessionClaim: claim, State: acp.ClaimPrepared, Created: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return acp.SessionClaimRecord{}, fmt.Errorf("insert Harness session claim: %w", err)
	}
	// Concurrent ON CONFLICT waits for the winning transaction; an ordinary
	// missing Run or release mismatch is not permission to start a session.
	record, err := s.ReadHarnessSessionClaim(ctx, claim)
	if err != nil {
		return acp.SessionClaimRecord{}, err
	}
	return record, nil
}

// ReadHarnessSessionClaim is scoped by tenant AND canonical Run. Unknown,
// unconfirmed and stale identity is never translated to final absence.
// It does not prove that AttemptID is current; that separate authority is P0.
func (s *Store) ReadHarnessSessionClaim(ctx context.Context, claim acp.SessionClaim) (acp.SessionClaimRecord, error) {
	if s == nil || s.pool == nil {
		return acp.SessionClaimRecord{}, run.ErrRepositoryUnavailable
	}
	if err := claim.Validate(); err != nil {
		return acp.SessionClaimRecord{}, err
	}
	var r acp.SessionClaimRecord
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id,run_id::text,attempt_id::text,harness_instance_id,
			agent_release_id,policy_revision,request_digest,working_dir,
			state,coalesce(agent_session_id,'')
		FROM runtime_harness_session_claims
		WHERE tenant_id=$1 AND run_id=$2::uuid
	`, claim.TenantID, claim.RunID).Scan(
		&r.TenantID, &r.RunID, &r.AttemptID, &r.HarnessInstanceID,
		&r.AgentReleaseID, &r.PolicyRevision, &r.RequestDigest, &r.WorkingDir,
		&r.State, &r.AgentSessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return acp.SessionClaimRecord{}, acp.ErrBindingInvalid
	}
	if err != nil {
		return acp.SessionClaimRecord{}, fmt.Errorf("read Harness session claim: %w", err)
	}
	if err := r.Matches(claim); err != nil {
		return acp.SessionClaimRecord{}, err
	}
	if r.State != acp.ClaimPrepared && r.State != acp.ClaimUnknown && r.State != acp.ClaimConfirmed {
		return acp.SessionClaimRecord{}, acp.ErrBindingInvalid
	}
	if (r.State == acp.ClaimConfirmed) != (r.AgentSessionID != "") {
		return acp.SessionClaimRecord{}, acp.ErrBindingInvalid
	}
	return r, nil
}

// BeginHarnessSessionDispatch irreversibly claims the one allowed initial
// session/new attempt. Persist UNKNOWN BEFORE any external call. If the
// transaction ACK is lost, a later read is UNKNOWN and grants no new dispatch.
// Only the caller receiving (true, nil) may call session/new once.
func (s *Store) BeginHarnessSessionDispatch(ctx context.Context, claim acp.SessionClaim) (bool, error) {
	if s == nil || s.pool == nil {
		return false, run.ErrRepositoryUnavailable
	}
	if err := claim.Validate(); err != nil {
		return false, err
	}
	var runID string
	err := s.pool.QueryRow(ctx, `
		UPDATE runtime_harness_session_claims AS c
		SET state='UNKNOWN', updated_at=now()
		WHERE c.tenant_id=$1 AND c.run_id=$2::uuid AND c.attempt_id=$3::uuid
			AND c.harness_instance_id=$4 AND c.agent_release_id=$5
			AND c.policy_revision=$6 AND c.request_digest=$7 AND c.working_dir=$8
			AND c.state='PREPARED'
			AND EXISTS (SELECT 1 FROM runs r WHERE r.tenant_id=c.tenant_id
				AND r.run_id=c.run_id AND r.agent_release_id=c.agent_release_id
				AND r.status='RUNNING')
		RETURNING c.run_id::text
	`, claim.TenantID, claim.RunID, claim.AttemptID, claim.HarnessInstanceID,
		claim.AgentReleaseID, claim.PolicyRevision, claim.RequestDigest, claim.WorkingDir).Scan(&runID)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("begin Harness session dispatch: %w", err)
	}
	record, err := s.ReadHarnessSessionClaim(ctx, claim)
	if err != nil {
		return false, err
	}
	if record.State == acp.ClaimPrepared {
		// State was not advanced because the current Run safety predicate
		// failed. Never grant dispatch on an unsafe Run.
		return false, acp.ErrBindingInvalid
	}
	return false, nil
}

// ConfirmHarnessSession records a reply from the ONE previously authorized
// dispatch. It does not authorize protected effects or prove a prompt outcome.
// Same session replay is idempotent; different replies conflict.
func (s *Store) ConfirmHarnessSession(ctx context.Context, claim acp.SessionClaim, agentSessionID string) (acp.SessionClaimRecord, error) {
	if s == nil || s.pool == nil {
		return acp.SessionClaimRecord{}, run.ErrRepositoryUnavailable
	}
	if err := claim.Validate(); err != nil {
		return acp.SessionClaimRecord{}, err
	}
	if !validAgentSessionID(agentSessionID) {
		return acp.SessionClaimRecord{}, acp.ErrBindingInvalid
	}
	var runID string
	err := s.pool.QueryRow(ctx, `
		UPDATE runtime_harness_session_claims
		SET state='CONFIRMED', agent_session_id=$9, updated_at=now()
		WHERE tenant_id=$1 AND run_id=$2::uuid AND attempt_id=$3::uuid
			AND harness_instance_id=$4 AND agent_release_id=$5
			AND policy_revision=$6 AND request_digest=$7 AND working_dir=$8
			AND state='UNKNOWN'
		RETURNING run_id::text
	`, claim.TenantID, claim.RunID, claim.AttemptID, claim.HarnessInstanceID,
		claim.AgentReleaseID, claim.PolicyRevision, claim.RequestDigest,
		claim.WorkingDir, agentSessionID).Scan(&runID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return acp.SessionClaimRecord{}, acp.ErrClaimConflict
		}
		return acp.SessionClaimRecord{}, fmt.Errorf("confirm Harness session: %w", err)
	}
	record, readErr := s.ReadHarnessSessionClaim(ctx, claim)
	if readErr != nil {
		return acp.SessionClaimRecord{}, readErr
	}
	if record.State == acp.ClaimConfirmed && record.AgentSessionID == agentSessionID {
		return record, nil
	}
	if record.State == acp.ClaimConfirmed {
		return acp.SessionClaimRecord{}, acp.ErrClaimConflict
	}
	return acp.SessionClaimRecord{}, acp.ErrBindingInvalid
}

func validAgentSessionID(v string) bool {
	return v != "" && len(v) <= 255 && strings.TrimSpace(v) == v &&
		utf8.ValidString(v) && !strings.ContainsRune(v, '\x00')
}
