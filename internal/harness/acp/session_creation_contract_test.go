package acp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Assert the public adapter behavior without making unrelated packages fail
// to compile during the test-first phase.
type sessionCreationClient interface {
	CreateSession(context.Context, SessionClaim) (SessionClaimRecord, error)
}

type creationFixtureStore struct {
	record         SessionClaimRecord
	beginACKLost   bool
	confirmACKLost bool
}

func (s *creationFixtureStore) LookupBinding(context.Context, string, string) (Binding, error) {
	return Binding{}, ErrBindingInvalid
}

func (s *creationFixtureStore) ClaimHarnessSession(_ context.Context, c SessionClaim) (SessionClaimRecord, error) {
	if s.record.State == "" {
		s.record = SessionClaimRecord{SessionClaim: c, State: ClaimPrepared}
		r := s.record
		r.Created = true
		return r, nil
	}
	if err := s.record.Matches(c); err != nil {
		return SessionClaimRecord{}, err
	}
	return s.record, nil
}

func (s *creationFixtureStore) BeginHarnessSessionDispatch(_ context.Context, c SessionClaim) (bool, error) {
	if err := s.record.Matches(c); err != nil {
		return false, err
	}
	if s.record.State != ClaimPrepared {
		return false, nil
	}
	s.record.State = ClaimUnknown
	if s.beginACKLost {
		return false, errors.New("begin commit ACK lost")
	}
	return true, nil
}

func (s *creationFixtureStore) ConfirmHarnessSession(_ context.Context, c SessionClaim, id string) (SessionClaimRecord, error) {
	if err := s.record.Matches(c); err != nil {
		return SessionClaimRecord{}, err
	}
	if s.record.State != ClaimUnknown {
		return SessionClaimRecord{}, ErrBindingInvalid
	}
	s.record.State = ClaimConfirmed
	s.record.AgentSessionID = id
	if s.confirmACKLost {
		return SessionClaimRecord{}, errors.New("confirmation commit ACK lost")
	}
	return s.record, nil
}

type creationFixtureRPC struct {
	t          *testing.T
	store      *creationFixtureStore
	response   string
	ackLost    bool
	dispatches int
}

func (r *creationFixtureRPC) Call(_ context.Context, method string, params any, result any) error {
	switch method {
	case "initialize":
		return json.Unmarshal([]byte(`{"protocolVersion":1}`), result)
	case "session/new":
		r.dispatches++
		if r.store.record.State != ClaimUnknown {
			r.t.Error("session/new emitted before durable UNKNOWN")
			return ErrBindingInvalid
		}
		raw, err := json.Marshal(params)
		if err != nil {
			return err
		}
		var request struct {
			CWD        string `json:"cwd"`
			MCPServers []any  `json:"mcpServers"`
		}
		if err := json.Unmarshal(raw, &request); err != nil {
			return err
		}
		if request.CWD != r.store.record.WorkingDir || request.MCPServers == nil || len(request.MCPServers) != 0 {
			r.t.Errorf("unsafe creation parameters: %s", raw)
			return ErrBindingInvalid
		}
		if r.ackLost {
			return errors.New("session/new ACK lost")
		}
		return json.Unmarshal([]byte(r.response), result)
	default:
		r.t.Errorf("unexpected external method: %s", method)
		return ErrBindingInvalid
	}
}

func (r *creationFixtureRPC) Notify(context.Context, string, any) error {
	r.t.Error("unexpected notification during creation")
	return ErrBindingInvalid
}

func newCreationFixtureClient(t *testing.T, rpc RPC, store BindingStore) sessionCreationClient {
	t.Helper()
	c, err := NewClient(rpc, store, "worker-codex-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	creator, ok := any(c).(sessionCreationClient)
	if !ok {
		t.Fatal("Client has no durable CreateSession adapter")
	}
	return creator
}

func TestCreateSessionDurableDispatchAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		name           string
		response       string
		beginACKLost   bool
		rpcACKLost     bool
		confirmACKLost bool
		wantState      ClaimState
		wantCalls      int
		wantErr        bool
	}{
		{name: "confirmed", response: `{"sessionId":"session-1"}`, wantState: ClaimConfirmed, wantCalls: 1},
		{name: "begin-commit-ack-lost", beginACKLost: true, wantState: ClaimUnknown, wantErr: true},
		{name: "session-ack-lost", rpcACKLost: true, wantState: ClaimUnknown, wantCalls: 1, wantErr: true},
		{name: "confirm-commit-ack-lost", response: `{"sessionId":"session-1"}`, confirmACKLost: true, wantState: ClaimConfirmed, wantCalls: 1, wantErr: true},
		{name: "missing-session-id", response: `{}`, wantState: ClaimUnknown, wantCalls: 1, wantErr: true},
		{name: "null-session-id", response: `{"sessionId":null}`, wantState: ClaimUnknown, wantCalls: 1, wantErr: true},
		{name: "casefold-session-id", response: `{"SessionId":"session-1"}`, wantState: ClaimUnknown, wantCalls: 1, wantErr: true},
		{name: "invalid-session-id", response: `{"sessionId":"session\n1"}`, wantState: ClaimUnknown, wantCalls: 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			claim := SessionClaim{TenantID: "tenant-a", RunID: "11111111-1111-4111-8111-111111111111",
				AttemptID: "22222222-2222-4222-8222-222222222222", HarnessInstanceID: "worker-codex-1",
				AgentReleaseID: "release-1", PolicyRevision: "policy-1",
				RequestDigest: "sha256:" + strings.Repeat("a", 64), WorkingDir: "/workspace/project"}
			store := &creationFixtureStore{beginACKLost: tc.beginACKLost, confirmACKLost: tc.confirmACKLost}
			rpc := &creationFixtureRPC{t: t, store: store, response: tc.response, ackLost: tc.rpcACKLost}
			client := newCreationFixtureClient(t, rpc, store)
			got, err := client.CreateSession(ctx, claim)
			if (err != nil) != tc.wantErr || store.record.State != tc.wantState || rpc.dispatches != tc.wantCalls {
				t.Fatalf("unexpected creation outcome: state=%s dispatches=%d err=%v", store.record.State, rpc.dispatches, err)
			}
			if tc.wantErr {
				if got.State == ClaimConfirmed || got.AgentSessionID != "" {
					t.Fatalf("unacknowledged result reported as confirmed: %+v", got)
				}
			} else if got.State != ClaimConfirmed || got.AgentSessionID != "session-1" || got.SessionClaim != claim {
				t.Fatalf("missing durable confirmed evidence: %+v", got)
			}

			// Reconstruct the adapter using the same persisted fixture. Never
			// emit a second session/new, even after a lost confirmation ACK.
			restarted := newCreationFixtureClient(t, rpc, store)
			got, err = restarted.CreateSession(ctx, claim)
			if rpc.dispatches != tc.wantCalls {
				t.Fatalf("restart repeated session/new: %d", rpc.dispatches)
			}
			if tc.wantState == ClaimConfirmed {
				if err != nil || got.State != ClaimConfirmed || got.AgentSessionID != "session-1" || got.SessionClaim != claim || got.Created {
					t.Fatalf("confirmed replay did not return historical evidence: %+v %v", got, err)
				}
			} else if err == nil || got.State == ClaimConfirmed || got.AgentSessionID != "" || store.record.State != ClaimUnknown {
				t.Fatalf("unknown replay manufactured confirmation: %+v %v", got, err)
			}
		})
	}
}
