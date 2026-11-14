package acp

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type fakeRPC struct {
	version   int
	load      bool
	callErr   error
	notifyErr error
	methods   []string
	calls     []map[string]any
	notifies  []map[string]any
}

func (f *fakeRPC) Call(_ context.Context, method string, params any, result any) error {
	f.methods = append(f.methods, method)
	b, _ := json.Marshal(params)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	f.calls = append(f.calls, m)
	if f.callErr != nil {
		return f.callErr
	}
	if method == "initialize" {
		data, _ := json.Marshal(map[string]any{"protocolVersion": f.version, "agentCapabilities": map[string]any{"loadSession": f.load}, "agentInfo": map[string]any{"name": "fixture"}})
		return json.Unmarshal(data, result)
	}
	return nil
}

func (f *fakeRPC) Notify(_ context.Context, method string, params any) error {
	f.methods = append(f.methods, method)
	b, _ := json.Marshal(params)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	f.notifies = append(f.notifies, m)
	return f.notifyErr
}

type fakeStore struct {
	binding Binding
	err     error
	reads   int
}

func (s *fakeStore) LookupBinding(_ context.Context, _, _ string) (Binding, error) {
	s.reads++
	return s.binding, s.err
}

func confirmedBinding() Binding {
	return Binding{TenantID: "tenant-a", RunID: "run-1", RunStatus: "RUNNING", AttemptID: "attempt-1", HarnessInstanceID: "worker-codex-1", AgentSessionID: "agent-session-1", WorkingDir: "/workspace", Confirmed: true}
}

func readyClient(t *testing.T, load bool) (*Client, *fakeRPC, *fakeStore) {
	t.Helper()
	rpc := &fakeRPC{version: 1, load: load}
	store := &fakeStore{binding: confirmedBinding()}
	c, err := NewClient(rpc, store, "worker-codex-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c, rpc, store
}

func TestInitializeProtocolV1DoesNotAdvertisePrivilegedCapabilities(t *testing.T) {
	c, rpc, _ := readyClient(t, true)
	caps, err := c.negotiated()
	if err != nil || !caps.LoadSession {
		t.Fatalf("caps: %+v %v", caps, err)
	}
	if rpc.calls[0]["protocolVersion"] != float64(1) {
		t.Fatal("requested wrong protocol version")
	}
	if len(rpc.calls[0]["clientCapabilities"].(map[string]any)) != 0 {
		t.Fatal("privileged capabilities advertised")
	}
}

func TestUnsupportedV2CannotBeUsed(t *testing.T) {
	rpc := &fakeRPC{version: 2, load: true}
	c, _ := NewClient(rpc, &fakeStore{binding: confirmedBinding()}, "worker-codex-1")
	if _, err := c.Initialize(context.Background()); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("unexpected: %v", err)
	}
	if _, err := c.Recover(context.Background(), "tenant-a", "run-1"); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestRecoverSessionLoadIsCapabilityGated(t *testing.T) {
	c, rpc, store := readyClient(t, false)
	status, err := c.Recover(context.Background(), "tenant-a", "run-1")
	if err != nil || status != RecoveryUnknown {
		t.Fatalf("got %s %v", status, err)
	}
	if store.reads != 1 || !reflect.DeepEqual(rpc.methods, []string{"initialize"}) {
		t.Fatal("session/load sent despite absent capability")
	}
}

func TestRecoverUsesOnlyCommittedTenantBoundBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Binding)
	}{
		{"unconfirmed", func(b *Binding) { b.Confirmed = false }},
		{"cross-tenant", func(b *Binding) { b.TenantID = "tenant-b" }},
		{"wrong-run", func(b *Binding) { b.RunID = "run-2" }},
		{"missing-session", func(b *Binding) { b.AgentSessionID = "" }},
		{"relative-cwd", func(b *Binding) { b.WorkingDir = "relative/path" }},
		{"unclean-absolute-cwd", func(b *Binding) { b.WorkingDir = "/workspace/../etc" }},
		{"missing-attempt", func(b *Binding) { b.AttemptID = "" }},
		{"wrong-harness-instance", func(b *Binding) { b.HarnessInstanceID = "worker-claude-2" }},
		{"missing-harness-instance", func(b *Binding) { b.HarnessInstanceID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, rpc, store := readyClient(t, true)
			tc.mutate(&store.binding)
			status, err := c.Recover(context.Background(), "tenant-a", "run-1")
			if status != RecoveryUnknown || !errors.Is(err, ErrBindingInvalid) {
				t.Fatalf("got %s %v", status, err)
			}
			if len(rpc.methods) != 1 {
				t.Fatal("unexpected external operation")
			}
		})
	}
}

func TestRecoverRejectsNonRunningRunButPreservesCancellation(t *testing.T) {
	for _, state := range []string{"", "ACCEPTED", "CANCELLED", "COMPLETED", "FAILED"} {
		t.Run(state, func(t *testing.T) {
			c, rpc, store := readyClient(t, true)
			store.binding.RunStatus = state
			status, err := c.Recover(context.Background(), "tenant-a", "run-1")
			if status != RecoveryUnknown || !errors.Is(err, ErrBindingInvalid) {
				t.Fatalf("unsafe recovery of %q Run: status=%s err=%v", state, status, err)
			}
			if !reflect.DeepEqual(rpc.methods, []string{"initialize"}) {
				t.Fatalf("non-RUNNING Run sent ACP method: %v", rpc.methods)
			}
			if state == "CANCELLED" {
				status, err := c.Cancel(context.Background(), "tenant-a", "run-1")
				if status != CancelSent || err != nil || !reflect.DeepEqual(rpc.methods, []string{"initialize", "session/cancel"}) {
					t.Fatalf("CANCELLED Run lost safe cancel notification: status=%s err=%v methods=%v", status, err, rpc.methods)
				}
			}
		})
	}
}

func TestRecoverLoadNeverMeansPromptSafeToReplay(t *testing.T) {
	c, rpc, _ := readyClient(t, true)
	status, err := c.Recover(context.Background(), "tenant-a", "run-1")
	if err != nil || status != RecoveryLoaded {
		t.Fatalf("got %s %v", status, err)
	}
	if !reflect.DeepEqual(rpc.methods, []string{"initialize", "session/load"}) {
		t.Fatal(rpc.methods)
	}
	if rpc.calls[1]["sessionId"] != "agent-session-1" || rpc.calls[1]["cwd"] != "/workspace" {
		t.Fatal("wrong binding used")
	}
	if len(rpc.calls[1]["mcpServers"].([]any)) != 0 {
		t.Fatal("unexpected tool access")
	}
}

func TestRecoverMissingStoreOrTransportACKRemainsUnknown(t *testing.T) {
	c, rpc, store := readyClient(t, true)
	store.err = errors.New("db unavailable")
	if status, err := c.Recover(context.Background(), "tenant-a", "run-1"); status != RecoveryUnknown || err == nil {
		t.Fatalf("got %s %v", status, err)
	}
	if len(rpc.methods) != 1 {
		t.Fatal("called agent despite DB outage")
	}
	store.err = nil
	rpc.callErr = errors.New("ACK lost")
	if status, err := c.Recover(context.Background(), "tenant-a", "run-1"); status != RecoveryUnknown || err == nil {
		t.Fatalf("got %s %v", status, err)
	}
}

func TestCancelIsNotificationNotTermination(t *testing.T) {
	c, rpc, _ := readyClient(t, true)
	status, err := c.Cancel(context.Background(), "tenant-a", "run-1")
	if err != nil || status != CancelSent {
		t.Fatalf("got %s %v", status, err)
	}
	if !reflect.DeepEqual(rpc.methods, []string{"initialize", "session/cancel"}) {
		t.Fatal(rpc.methods)
	}
	if rpc.notifies[0]["sessionId"] != "agent-session-1" {
		t.Fatal(rpc.notifies)
	}
	rpc.notifyErr = errors.New("transport lost")
	if status, err := c.Cancel(context.Background(), "tenant-a", "run-1"); status != RecoveryUnknown || err == nil {
		t.Fatalf("got %s %v", status, err)
	}
}

func TestNewClientRejectsMissingHarnessIdentity(t *testing.T) {
	rpc := &fakeRPC{version: 1, load: true}
	store := &fakeStore{binding: confirmedBinding()}
	for _, bad := range []string{"", " ", "worker\nother"} {
		client, err := NewClient(rpc, store, bad)
		if client != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("unsafe Harness instance identity accepted: %q, client=%v err=%v", bad, client, err)
		}
	}
}

func TestNewClientRejectsTypedNilDependencies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rpc   RPC
		store BindingStore
	}{
		{"nil RPC", nil, &fakeStore{}},
		{"typed nil RPC", (*fakeRPC)(nil), &fakeStore{}},
		{"nil binding store", &fakeRPC{}, nil},
		{"typed nil binding store", &fakeRPC{}, (*fakeStore)(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(tc.rpc, tc.store, "worker-codex-1")
			if client != nil || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("invalid ACP v1 dependencies accepted: client=%v err=%v", client, err)
			}
		})
	}
}
