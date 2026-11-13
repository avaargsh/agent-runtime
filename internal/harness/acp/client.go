// Package acp contains the Agent Client Protocol v1 Harness adapter boundary.
// It is deliberately separate from acphttp (agent-control-panel authority).
// Loading a session never proves the outcome of a lost prompt or tool ACK.
package acp

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"unicode/utf8"
)

const ProtocolVersion = 1

var (
	ErrInvalidConfiguration = errors.New("ACP harness adapter requires a transport and authoritative binding store")
	ErrNotInitialized       = errors.New("ACP v1 initialization not completed")
	ErrUnsupportedVersion   = errors.New("unsupported Agent Client Protocol version")
	ErrBindingInvalid       = errors.New("invalid or mismatched persisted ACP harness binding")
)

// RPC is a bidirectional ACP JSON-RPC v1 transport. It MUST deliver agent
// requests/notifications while a Call is pending (notably session/update and
// session/request_permission), rather than deadlocking on a prompt/load reply.
// It MUST NOT auto-approve permission requests or expose filesystem/terminal
// access without an independently authenticated and authorized executor.
type RPC interface {
	Call(context.Context, string, any, any) error
	Notify(context.Context, string, any) error
}

// BindingStore must perform an authoritative, tenant-scoped read from durable
// Runtime storage, not a process-local map or a third-party Agent session list.
// It must return only a committed binding and must not mint a new binding here.
type BindingStore interface {
	LookupBinding(context.Context, string, string) (Binding, error)
}

// Binding correlates a Runtime-owned Run/Attempt with one Harness session.
// Control-plane SessionIdentity, Runtime Run and AgentSessionID are distinct.
// Confirmed means session/new was durably bound after a confirmed response;
// it says nothing about the outcome of a later session/prompt.
type Binding struct {
	TenantID string
	RunID    string
	// RunStatus is sampled from authoritative Runtime storage at lookup time.
	// It is not an external execution grant or a fence against later cancellation.
	RunStatus         string
	AttemptID         string
	HarnessInstanceID string
	AgentSessionID    string
	WorkingDir        string
	Confirmed         bool
}

func validIdentifier(v string) bool {
	return v != "" && len(v) <= 255 && strings.TrimSpace(v) == v &&
		utf8.ValidString(v) && !strings.ContainsAny(v, "\x00\r\n\t")
}

func (b Binding) validate(tenantID, runID, harnessInstanceID string) error {
	if !b.Confirmed || b.TenantID != tenantID || b.RunID != runID ||
		!validIdentifier(tenantID) || !validIdentifier(runID) ||
		!validIdentifier(b.AttemptID) || !validIdentifier(b.HarnessInstanceID) ||
		b.HarnessInstanceID != harnessInstanceID || !validIdentifier(b.AgentSessionID) ||
		!filepath.IsAbs(b.WorkingDir) || filepath.Clean(b.WorkingDir) != b.WorkingDir ||
		!utf8.ValidString(b.WorkingDir) ||
		strings.ContainsRune(b.WorkingDir, '\x00') {
		return ErrBindingInvalid
	}
	return nil
}

type Capabilities struct {
	LoadSession bool
}

type RecoveryStatus string

const (
	// RecoveryUnknown forbids re-running session/new or session/prompt.
	RecoveryUnknown RecoveryStatus = "UNKNOWN_RECONCILE"
	// RecoveryLoaded does NOT make an in-flight prompt safe to replay.
	RecoveryLoaded RecoveryStatus = "SESSION_LOADED_OUTCOME_UNCERTAIN"
	// CancelSent denotes a one-way notification, NOT process termination.
	CancelSent RecoveryStatus = "CANCEL_SENT_UNCONFIRMED"
)

type Client struct {
	rpc               RPC
	store             BindingStore
	harnessInstanceID string
	mu                sync.RWMutex
	ready             bool
	caps              Capabilities
}

// Interfaces containing typed-nil pointers are non-nil interface values.
// Reject them before the adapter can try an external RPC or durable lookup.
func missingDependency(v any) bool {
	if v == nil {
		return true
	}
	value := reflect.ValueOf(v)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

func NewClient(rpc RPC, store BindingStore, harnessInstanceID string) (*Client, error) {
	if missingDependency(rpc) || missingDependency(store) || !validIdentifier(harnessInstanceID) {
		return nil, ErrInvalidConfiguration
	}
	return &Client{rpc: rpc, store: store, harnessInstanceID: harnessInstanceID}, nil
}

// Initialize requests only v1 and advertises no filesystem, terminal or
// automated permission-grant capability. Unknown optional Agent fields are
// ignored for forward compatibility. A v2 reply fails closed.
func (c *Client) Initialize(ctx context.Context) (Capabilities, error) {
	var response struct {
		ProtocolVersion   int `json:"protocolVersion"`
		AgentCapabilities struct {
			LoadSession bool `json:"loadSession"`
		} `json:"agentCapabilities"`
	}
	request := struct {
		ProtocolVersion    int            `json:"protocolVersion"`
		ClientCapabilities map[string]any `json:"clientCapabilities"`
		ClientInfo         struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	}{ProtocolVersion: ProtocolVersion, ClientCapabilities: map[string]any{}}
	request.ClientInfo.Name = "agent-runtime-harness-acp"
	request.ClientInfo.Version = "0.1.0"

	c.mu.Lock()
	defer c.mu.Unlock()
	// A failed renegotiation must invalidate previously cached capabilities.
	c.ready = false
	c.caps = Capabilities{}
	if err := c.rpc.Call(ctx, "initialize", request, &response); err != nil {
		return Capabilities{}, fmt.Errorf("ACP initialize: %w", err)
	}
	if response.ProtocolVersion != ProtocolVersion {
		return Capabilities{}, ErrUnsupportedVersion
	}
	c.caps = Capabilities{LoadSession: response.AgentCapabilities.LoadSession}
	c.ready = true
	return c.caps, nil
}

func (c *Client) negotiated() (Capabilities, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.ready {
		return Capabilities{}, ErrNotInitialized
	}
	return c.caps, nil
}

// Recover attempts an existing session/load only after durable binding lookup.
// Missing/uncertain bindings and lack of loadSession capability remain UNKNOWN.
// It never starts a new session, replays a prompt or maps a timeout to FAILED.
func (c *Client) Recover(ctx context.Context, tenantID, runID string) (RecoveryStatus, error) {
	caps, err := c.negotiated()
	if err != nil {
		return RecoveryUnknown, err
	}
	if !validIdentifier(tenantID) || !validIdentifier(runID) {
		return RecoveryUnknown, ErrBindingInvalid
	}
	binding, err := c.store.LookupBinding(ctx, tenantID, runID)
	if err != nil {
		return RecoveryUnknown, fmt.Errorf("ACP binding read: %w", err)
	}
	if err := binding.validate(tenantID, runID, c.harnessInstanceID); err != nil {
		return RecoveryUnknown, err
	}
	// A confirmed Agent session may outlive its Runtime Run. A cancelled or
	// completed Run may be cancelled, but must never be loaded again.
	if binding.RunStatus != "RUNNING" {
		return RecoveryUnknown, ErrBindingInvalid
	}
	if !caps.LoadSession {
		return RecoveryUnknown, nil
	}
	params := struct {
		SessionID  string `json:"sessionId"`
		CWD        string `json:"cwd"`
		MCPServers []any  `json:"mcpServers"`
	}{binding.AgentSessionID, binding.WorkingDir, []any{}}
	var result struct{}
	if err := c.rpc.Call(ctx, "session/load", params, &result); err != nil {
		return RecoveryUnknown, fmt.Errorf("ACP session/load outcome uncertain: %w", err)
	}
	return RecoveryLoaded, nil
}

// Cancel sends only the ACP v1 session/cancel notification after checking a
// durable tenant-bound session. Delivery is not proof of cancellation, tool
// termination, Guard revocation or external-effect rollback.
func (c *Client) Cancel(ctx context.Context, tenantID, runID string) (RecoveryStatus, error) {
	if _, err := c.negotiated(); err != nil {
		return RecoveryUnknown, err
	}
	if !validIdentifier(tenantID) || !validIdentifier(runID) {
		return RecoveryUnknown, ErrBindingInvalid
	}
	binding, err := c.store.LookupBinding(ctx, tenantID, runID)
	if err != nil {
		return RecoveryUnknown, fmt.Errorf("ACP binding read: %w", err)
	}
	if err := binding.validate(tenantID, runID, c.harnessInstanceID); err != nil {
		return RecoveryUnknown, err
	}
	if err := c.rpc.Notify(ctx, "session/cancel", struct {
		SessionID string `json:"sessionId"`
	}{SessionID: binding.AgentSessionID}); err != nil {
		return RecoveryUnknown, fmt.Errorf("ACP session/cancel delivery uncertain: %w", err)
	}
	return CancelSent, nil
}
