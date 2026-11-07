package postgres_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// This test crosses a real PostgreSQL binding, the existing ACP v1 Client and
// actual newline-framed JSON-RPC bytes over a bidirectional in-memory pipe.
// It does NOT spawn an Agent or authorize an external tool side effect.
func TestConfirmedPostgresBindingOverBoundedACPStreamDeniesPermission(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	clientConn, agentConn := net.Pipe()
	defer clientConn.Close()
	defer agentConn.Close()
	if err := agentConn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}

	var sessionLoads atomic.Int32
	serverDone := make(chan error, 1)
	go func() {
		wire := bufio.NewReader(agentConn)
		for {
			line, err := wire.ReadBytes('\n')
			if err != nil {
				serverDone <- fmt.Errorf("agent fixture read: %w", err)
				return
			}
			var message map[string]any
			if err := json.Unmarshal(line, &message); err != nil {
				serverDone <- err
				return
			}
			method, _ := message["method"].(string)
			send := func(payload map[string]any) error {
				line, err := json.Marshal(payload)
				if err != nil {
					return err
				}
				_, err = agentConn.Write(append(line, '\n'))
				return err
			}
			switch method {
			case "initialize":
				if err := send(map[string]any{"jsonrpc": "2.0", "id": message["id"],
					"result": map[string]any{"protocolVersion": 1, "agentCapabilities": map[string]any{"loadSession": true}}}); err != nil {
					serverDone <- err
					return
				}
			case "session/load":
				sessionLoads.Add(1)
				params, _ := message["params"].(map[string]any)
				if params["sessionId"] != "wire-confirmed-session" || params["cwd"] != claim.WorkingDir {
					serverDone <- fmt.Errorf("loaded wrong confirmed session: %+v", params)
					return
				}
				// A malicious Agent asks for an allow-once option *while*
				// session/load is in flight; the transport must deny it.
				if err := send(map[string]any{"jsonrpc": "2.0", "id": 911,
					"method": "session/request_permission", "params": map[string]any{
						"sessionId": "wire-confirmed-session",
						"toolCall": map[string]any{"toolCallId": "external-effect"},
						"options": []any{map[string]any{"optionId": "allow-once", "kind": "allow_once", "name": "Allow"}},
					}}); err != nil {
					serverDone <- err
					return
				}
				responseLine, err := wire.ReadBytes('\n')
				if err != nil {
					serverDone <- err
					return
				}
				var response map[string]any
				if err := json.Unmarshal(responseLine, &response); err != nil {
					serverDone <- err
					return
				}
				result, ok := response["result"].(map[string]any)
				if !ok || response["id"] != float64(911) {
					serverDone <- fmt.Errorf("permission not answered: %+v", response)
					return
				}
				outcome, ok := result["outcome"].(map[string]any)
				if !ok || outcome["outcome"] != "cancelled" {
					serverDone <- fmt.Errorf("permission was granted: %+v", response)
					return
				}
				if err := send(map[string]any{"jsonrpc": "2.0", "id": message["id"], "result": map[string]any{}}); err != nil {
					serverDone <- err
					return
				}
			case "session/cancel":
				params, _ := message["params"].(map[string]any)
				if params["sessionId"] != "wire-confirmed-session" {
					serverDone <- fmt.Errorf("cancelled wrong Agent session: %+v", params)
					return
				}
				serverDone <- nil
				return
			default:
				serverDone <- errors.New("unexpected Agent operation: " + method)
				return
			}
		}
	}()

	rpc, err := acp.NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	client, err := acp.NewClient(rpc, postgres.New(pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if status, err := client.Recover(ctx, claim.TenantID, claim.RunID); status != acp.RecoveryUnknown || !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("absent claim loaded over wire: status=%s err=%v", status, err)
	}
	if _, err := store.ClaimHarnessSession(ctx, claim); err != nil {
		t.Fatal(err)
	}
	if granted, err := store.BeginHarnessSessionDispatch(ctx, claim); !granted || err != nil {
		t.Fatalf("initial creation grant: %t err=%v", granted, err)
	}
	if status, err := client.Recover(ctx, claim.TenantID, claim.RunID); status != acp.RecoveryUnknown || !errors.Is(err, acp.ErrBindingInvalid) {
		t.Fatalf("UNKNOWN loaded over wire: status=%s err=%v", status, err)
	}
	if sessionLoads.Load() != 0 {
		t.Fatal("unconfirmed session/load crossed JSON-RPC stream")
	}
	if _, err := store.ConfirmHarnessSession(ctx, claim, "wire-confirmed-session"); err != nil {
		t.Fatal(err)
	}
	if status, err := client.Recover(ctx, claim.TenantID, claim.RunID); status != acp.RecoveryLoaded || err != nil {
		t.Fatalf("confirmed guarded session/load failed: status=%s err=%v", status, err)
	}
	if sessionLoads.Load() != 1 {
		t.Fatalf("session/load attempts = %d, want 1", sessionLoads.Load())
	}
	if _, err := pool.Exec(ctx, `UPDATE runs SET status='CANCELLED', updated_at=now()
		WHERE tenant_id=$1 AND run_id=$2::uuid`, claim.TenantID, claim.RunID); err != nil {
		t.Fatal(err)
	}
	if status, err := client.Cancel(ctx, claim.TenantID, claim.RunID); status != acp.CancelSent || err != nil {
		t.Fatalf("confirmed session/cancel failed: status=%s err=%v", status, err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("fake agent did not receive session/cancel")
	}
}
