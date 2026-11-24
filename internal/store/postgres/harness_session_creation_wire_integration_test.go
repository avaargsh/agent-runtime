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

// Real PostgreSQL plus framed JSON-RPC over a controlled peer. Closing the
// peer after receipt models transport loss, not a real Agent process restart.
func TestHarnessCreateSessionPostgresWireACKRecovery(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "confirmed"
		if lost {
			name = "lost-ack"
		}
		t.Run(name, func(t *testing.T) {
			pool, store, claim := harnessFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var dispatches atomic.Int32

			// Each reconstructed Client has an independent wire and Store.
			connect := func() (*acp.Client, func()) {
				t.Helper()
				clientConn, agentConn := net.Pipe()
				if err := agentConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					defer agentConn.Close()
					wire := bufio.NewReader(agentConn)
					for {
						line, err := wire.ReadBytes('\n')
						if err != nil {
							done <- nil
							return
						}
						var request struct {
							ID     json.RawMessage `json:"id"`
							Method string          `json:"method"`
							Params json.RawMessage `json:"params"`
						}
						if err := json.Unmarshal(line, &request); err != nil {
							done <- err
							return
						}
						var result any
						switch request.Method {
						case "initialize":
							result = map[string]any{"protocolVersion": 1}
						case "session/new":
							dispatches.Add(1)
							record, err := postgres.New(pool).ReadHarnessSessionClaim(ctx, claim)
							if err != nil || record.State != acp.ClaimUnknown || record.AgentSessionID != "" {
								done <- fmt.Errorf("wire request without committed UNKNOWN: %+v %v", record, err)
								return
							}
							var params struct {
								CWD        string `json:"cwd"`
								MCPServers []any  `json:"mcpServers"`
							}
							if err := json.Unmarshal(request.Params, &params); err != nil || params.CWD != claim.WorkingDir || params.MCPServers == nil || len(params.MCPServers) != 0 {
								done <- errors.New("unsafe session/new parameters")
								return
							}
							if lost {
								done <- nil
								return
							}
							result = map[string]any{"sessionId": "wire-created-session"}
						default:
							done <- fmt.Errorf("unexpected ACP operation: %s", request.Method)
							return
						}
						reply, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
						if err == nil {
							_, err = agentConn.Write(append(reply, '\n'))
						}
						if err != nil {
							done <- err
							return
						}
					}
				}()
				rpc, err := acp.NewStreamRPC(clientConn)
				if err != nil {
					clientConn.Close()
					agentConn.Close()
					t.Fatal(err)
				}
				closeWire := func() {
					rpc.Close()
					clientConn.Close()
					agentConn.Close()
					select {
					case err := <-done:
						if err != nil {
							t.Error(err)
						}
					case <-time.After(2 * time.Second):
						t.Error("controlled wire peer did not terminate")
					}
				}
				t.Cleanup(closeWire)
				client, err := acp.NewClient(rpc, postgres.New(pool), claim.HarnessInstanceID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.Initialize(ctx); err != nil {
					t.Fatal(err)
				}
				return client, func() { rpc.Close() }
			}

			client, disconnect := connect()
			got, err := client.CreateSession(ctx, claim)
			disconnect()
			want := acp.ClaimConfirmed
			if lost {
				want = acp.ClaimUnknown
				if !errors.Is(err, acp.ErrSessionCreationUncertain) || got.AgentSessionID != "" {
					t.Fatalf("lost ACK reported confirmation: %+v %v", got, err)
				}
			} else if err != nil || got.State != want || got.AgentSessionID != "wire-created-session" {
				t.Fatalf("creation did not confirm: %+v %v", got, err)
			}
			persisted, err := store.ReadHarnessSessionClaim(ctx, claim)
			if err != nil || persisted.State != want || dispatches.Load() != 1 {
				t.Fatalf("wrong durable outcome: %+v dispatches=%d err=%v", persisted, dispatches.Load(), err)
			}
			restarted, _ := connect()
			got, err = restarted.CreateSession(ctx, claim)
			if dispatches.Load() != 1 {
				t.Fatalf("adapter reconstruction repeated wire dispatch: %d", dispatches.Load())
			}
			if lost {
				if !errors.Is(err, acp.ErrSessionCreationUncertain) || got.State != acp.ClaimUnknown || got.AgentSessionID != "" {
					t.Fatalf("unknown replay did not hold: %+v %v", got, err)
				}
			} else if err != nil || got != persisted {
				t.Fatalf("confirmed replay changed durable evidence: %+v %v", got, err)
			}
		})
	}
}
