package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/avaargsh/agent-runtime/internal/audit"
	"github.com/avaargsh/agent-runtime/internal/executionsafety"
	"github.com/jackc/pgx/v5"
)

// Proposal transition facts share the same authoritative PostgreSQL
// transaction with state and the delivery Outbox. The security archive is
// append-only and independent of the Outbox's delivery lifecycle.
//
// Only internal, trusted state coordinates are stored. In particular, never
// copy the Outbox's Guard submission key, user confirmation evidence URI,
// raw tool policy, or untrusted arguments into the security audit payload.
type proposalLifecycleAuditPayload struct {
	EventID             string                        `json:"event_id"`
	EventType           audit.EventType               `json:"event_type"`
	OccurredAt          time.Time                     `json:"occurred_at"`
	Identity            proposalLifecycleAuditScope   `json:"identity"`
	ProposalID          string                        `json:"proposal_id"`
	ProposalVersion     int64                         `json:"proposal_version"`
	IntentRevision      int64                         `json:"intent_revision"`
	State               executionsafety.ProposalState `json:"state"`
	ActionRequestDigest string                        `json:"action_request_digest"`
}

type proposalLifecycleAuditScope struct {
	TenantID string `json:"tenant_id"`
	RunID    string `json:"run_id"`
	TurnID   string `json:"turn_id"`
}

const proposalAuditSource = "runtime-proposal-state"

func proposalLifecycleEventType(value string) (audit.EventType, error) {
	switch value {
	case "ToolProposalCreated":
		return audit.EventProposalCreated, nil
	case "ToolProposalPrepared":
		return audit.EventProposalPrepared, nil
	case "ToolProposalSuperseded":
		return audit.EventProposalSuperseded, nil
	case "ProposalCommitAuthorized":
		return audit.EventProposalCommitAuthorized, nil
	case "GuardOperationLinked":
		return audit.EventGuardOperationLinked, nil
	default:
		return "", fmt.Errorf("unsupported Proposal lifecycle event type %q", value)
	}
}

func appendProposalLifecycleAuditTx(
	ctx context.Context,
	tx pgx.Tx,
	eventID, outboxEventType string,
	proposal executionsafety.Proposal,
	at time.Time,
) error {
	eventType, err := proposalLifecycleEventType(outboxEventType)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(proposalLifecycleAuditPayload{
		EventID: eventID, EventType: eventType, OccurredAt: at,
		Identity: proposalLifecycleAuditScope{
			TenantID: proposal.TenantID, RunID: proposal.RunID, TurnID: proposal.TurnID,
		},
		ProposalID: proposal.ID, ProposalVersion: proposal.Version,
		IntentRevision: proposal.IntentRevision, State: proposal.State,
		ActionRequestDigest: proposal.ActionRequestDigest,
	})
	if err != nil {
		return fmt.Errorf("marshal redacted Proposal lifecycle audit: %w", err)
	}
	// payload_digest is the canonical ActionRequestDigest fingerprint, not
	// the hash of the redacted metadata JSON; do not treat it as a Permit.
	_, err = tx.Exec(ctx, `
		INSERT INTO runtime_security_audit_events (
			tenant_id, event_id, run_id, event_type, occurred_at,
			source, proposal_id, guard_operation_id, payload_digest, payload
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
	`, proposal.TenantID, eventID, proposal.RunID, string(eventType), at,
		proposalAuditSource, proposal.ID, proposal.GuardOperationID,
		proposal.ActionRequestDigest, string(payload))
	if err != nil {
		return fmt.Errorf("append immutable Proposal lifecycle security audit: %w", err)
	}
	return nil
}
