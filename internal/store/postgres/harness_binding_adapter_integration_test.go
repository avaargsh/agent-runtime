package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
)

type durableHarnessRPCProbe struct {
	methods       []string
	notifications []string
	loadedSession string
	loadedCWD     string
	cancelSession string
}

func (p *durableHarnessRPCProbe) Call(_ context.Context, method string, params any, result any) error {
	p.methods = append(p.methods, method)
	switch method {
	case "initialize":
		return json.Unmarshal([]byte(`{"protocolVersion":1,"agentCapabilities":{"loadSession":true}}`), result)
	case "session/load":
		var input struct {
			SessionID  string `json:"sessionId"`
			CWD        string `json:"cwd"`
			MCPServers []any  `json:"mcpServers"`
		}
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &input); err != nil {
			return err
		}
		p.loadedSession, p.loadedCWD = input.SessionID, input.CWD
		if len(input.MCPServers) != 0 {
			return errors.New("unexpected privileged MCP server capability")
		}
		return nil
	default:
		return errors.New("unexpected ACP method: " + method)
	}
}

func (p *durableHarnessRPCProbe) Notify(_ context.Context, method string, params any) error {
	p.notifications = append(p.notifications, method)
	if method != "session/cancel" {
		return errors.New("unexpected ACP notification: " + method)
	}
	b, err := json.Marshal(params)
	if err != nil {
		return err
	}
	var input struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(b, &input); err != nil {
		return err
	}
	p.cancelSession = input.SessionID
	return nil
}

// This is a real PostgreSQL binding-to-ACP-adapter test with a fake RPC:
// it never starts a subprocess or invokes session/new/session/prompt.
func TestACPV1AdapterUsesOnlyCommittedPostgresHarnessBinding(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx := context.Background()
	rpc := &durableHarnessRPCProbe{}
	client, err := acp.NewClient(rpc, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	recoverUnknown := func(phase string) {
		t.Helper()
		status, err := client.Recover(ctx, claim.TenantID, claim.RunID)
		if status != acp.RecoveryUnknown || !errors.Is(err, acp.ErrBindingInvalid) {
			t.Fatalf("%s: unsafe recovery outcome=%s err=%v", phase, status, err)
		}
		if !reflect.DeepEqual(rpc.methods, []string{"initialize"}) {
			t.Fatalf("%s: ACP sent session/load without a confirmed binding: %v", phase, rpc.methods)
		}
	}
	recoverUnknown("absent claim")
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	recoverUnknown("prepared claim")
	if granted, err := store.BeginHarnessSessionDispatch(ctx, claim); !granted || err != nil {
		t.Fatalf("persist UNKNOWN: allowed=%t err=%v", granted, err)
	}
	recoverUnknown("unknown claim")
	if _, err := store.ConfirmHarnessSession(ctx, claim, "agent-session-durable"); err != nil {
		t.Fatal(err)
	}
	status, err := client.Recover(ctx, claim.TenantID, claim.RunID)
	if err != nil || status != acp.RecoveryLoaded ||
		!reflect.DeepEqual(rpc.methods, []string{"initialize", "session/load"}) ||
		rpc.loadedSession != "agent-session-durable" || rpc.loadedCWD != claim.WorkingDir {
		t.Fatalf("confirmed binding failed guarded load: status=%s err=%v rpc=%+v", status, err, rpc)
	}
	if _, err := pool.Exec(ctx, `UPDATE runs SET status='CANCELLED', updated_at=now()
		WHERE tenant_id=$1 AND run_id=$2::uuid`, claim.TenantID, claim.RunID); err != nil {
		t.Fatal(err)
	}
	cancelStatus, err := client.Cancel(ctx, claim.TenantID, claim.RunID)
	if err != nil || cancelStatus != acp.CancelSent ||
		!reflect.DeepEqual(rpc.notifications, []string{"session/cancel"}) ||
		rpc.cancelSession != "agent-session-durable" {
		t.Fatalf("cancel did not use durable session: status=%s err=%v rpc=%+v", cancelStatus, err, rpc)
	}
}
