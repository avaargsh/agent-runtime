package acp

import (
	"context"
	"encoding/json"
	"errors"
)

// SessionCreationStore is an optional durable capability of the authoritative
// BindingStore. Begin must commit UNKNOWN before returning (true, nil).
// Neither a process-local store nor an Agent listing may supply this authority.
type SessionCreationStore interface {
	ClaimHarnessSession(context.Context, SessionClaim) (SessionClaimRecord, error)
	BeginHarnessSessionDispatch(context.Context, SessionClaim) (bool, error)
	ConfirmHarnessSession(context.Context, SessionClaim, string) (SessionClaimRecord, error)
}

// ErrSessionCreationUncertain requires reconciliation, not another session/new.
var ErrSessionCreationUncertain = errors.New("ACP session creation outcome uncertain; reconcile")

// CreateSession accepts only trusted Runtime-derived claims. It returns
// durable binding evidence, never a prompt or protected-effect authorization.
// Only a committed Begin grant authorizes the one session/new call. An
// unacknowledged confirmation is not success, even if it committed remotely.
func (c *Client) CreateSession(ctx context.Context, claim SessionClaim) (SessionClaimRecord, error) {
	var empty SessionClaimRecord
	if _, err := c.negotiated(); err != nil {
		return empty, err
	}
	if err := claim.Validate(); err != nil || claim.HarnessInstanceID != c.harnessInstanceID {
		return empty, ErrBindingInvalid
	}
	store, ok := c.store.(SessionCreationStore)
	if !ok || missingDependency(store) {
		return empty, ErrInvalidConfiguration
	}
	record, err := store.ClaimHarnessSession(ctx, claim)
	if err != nil {
		return empty, err
	}
	if err := record.Matches(claim); err != nil {
		return empty, err
	}
	switch record.State {
	case ClaimConfirmed:
		if record.Created || !validIdentifier(record.AgentSessionID) {
			return empty, ErrBindingInvalid
		}
		return record, nil
	case ClaimUnknown:
		if record.Created || record.AgentSessionID != "" {
			return empty, ErrBindingInvalid
		}
		return record, ErrSessionCreationUncertain
	case ClaimPrepared:
		if record.AgentSessionID != "" {
			return empty, ErrBindingInvalid
		}
	default:
		return empty, ErrBindingInvalid
	}

	allowed, err := store.BeginHarnessSessionDispatch(ctx, claim)
	if err != nil || !allowed {
		// Even if the durable Begin committed, no acknowledged grant exists.
		// Do not assert a persisted state that was not acknowledged.
		return empty, ErrSessionCreationUncertain
	}
	unknown := SessionClaimRecord{SessionClaim: claim, State: ClaimUnknown}
	if ctx.Err() != nil {
		return unknown, ErrSessionCreationUncertain
	}
	params := struct {
		CWD        string `json:"cwd"`
		MCPServers []any  `json:"mcpServers"`
	}{claim.WorkingDir, []any{}}
	var response map[string]json.RawMessage
	if err := c.rpc.Call(ctx, "session/new", params, &response); err != nil {
		return unknown, ErrSessionCreationUncertain
	}
	// Do not accept missing/null or case-folded aliases of sessionId.
	var sessionID string
	if err := json.Unmarshal(response["sessionId"], &sessionID); err != nil || !validIdentifier(sessionID) {
		return unknown, ErrSessionCreationUncertain
	}
	confirmed, err := store.ConfirmHarnessSession(ctx, claim, sessionID)
	if err != nil {
		return unknown, ErrSessionCreationUncertain
	}
	if confirmed.Matches(claim) != nil || confirmed.State != ClaimConfirmed ||
		confirmed.Created || confirmed.AgentSessionID != sessionID {
		return unknown, ErrSessionCreationUncertain
	}
	return confirmed, nil
}
