package postgres_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

type creationProcessWire struct {
	stdout io.ReadCloser
	stdin  io.WriteCloser
}

func (w *creationProcessWire) Read(p []byte) (int, error)  { return w.stdout.Read(p) }
func (w *creationProcessWire) Write(p []byte) (int, error) { return w.stdin.Write(p) }
func (w *creationProcessWire) Close() error {
	_ = w.stdin.Close()
	return w.stdout.Close()
}

// Controlled test subprocess, not a production coding Agent. After observing
// session/new, the first process emits a receipt notification but no RPC ACK.
// A reconstructed process fails if any further operation follows initialize.
func TestHarnessCreationProcessFixture(t *testing.T) {
	mode := os.Getenv("RUNTIME_HARNESS_CREATION_PROCESS_FIXTURE")
	if mode == "" {
		return
	}
	wire := bufio.NewReader(os.Stdin)
	die := func(message string) {
		_, _ = fmt.Fprintln(os.Stderr, message)
		os.Exit(37)
	}
	read := func() map[string]any {
		line, err := wire.ReadBytes('\n')
		if err != nil {
			die("fixture could not read request")
		}
		var request map[string]any
		if err := json.Unmarshal(line, &request); err != nil || request["jsonrpc"] != "2.0" {
			die("invalid fixture request")
		}
		return request
	}
	send := func(payload map[string]any) {
		raw, err := json.Marshal(payload)
		if err != nil {
			die("fixture response encoding failed")
		}
		if _, err := os.Stdout.Write(append(raw, '\n')); err != nil {
			die("fixture response write failed")
		}
	}
	initialize := read()
	if initialize["method"] != "initialize" {
		die("expected initialization")
	}
	send(map[string]any{"jsonrpc": "2.0", "id": initialize["id"],
		"result": map[string]any{"protocolVersion": 1}})
	if mode == "replay" {
		if line, err := wire.ReadBytes('\n'); len(line) != 0 || !errors.Is(err, io.EOF) {
			die("reconstructed process received unexpected dispatch")
		}
		os.Exit(0)
	}
	if mode != "first" {
		die("invalid fixture mode")
	}
	creation := read()
	params, ok := creation["params"].(map[string]any)
	if creation["method"] != "session/new" || !ok || params["cwd"] != "/workspace/project" {
		die("invalid creation request")
	}
	servers, ok := params["mcpServers"].([]any)
	if !ok || len(servers) != 0 {
		die("unexpected MCP servers")
	}
	send(map[string]any{"jsonrpc": "2.0", "method": "session/update",
		"params": map[string]any{"sessionId": "unacknowledged-fixture-session",
			"update": map[string]any{"sessionUpdate": "creation-received-proof"}}})
	_, _ = io.Copy(io.Discard, wire)
	die("first process exited before explicit kill")
}

func TestHarnessCreateSessionPostgresProcessKillRetainsUnknown(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	start := func(mode string) (*acp.Client, *acp.StreamRPC, func(bool) error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHarnessCreationProcessFixture$")
		cmd.Env = append(os.Environ(), "RUNTIME_HARNESS_CREATION_PROCESS_FIXTURE="+mode)
		cmd.Stderr = os.Stderr
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waited := false
		wait := func(kill bool) error {
			if kill {
				if err := cmd.Process.Kill(); err != nil {
					return err
				}
			}
			err := cmd.Wait()
			waited = true
			return err
		}
		t.Cleanup(func() {
			if !waited {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		rpc, err := acp.NewStreamRPC(&creationProcessWire{stdout: stdout, stdin: stdin})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = rpc.Close() })
		client, err := acp.NewClient(rpc, postgres.New(pool), claim.HarnessInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		return client, rpc, wait
	}

	client, rpc, wait := start("first")
	if err := rpc.Call(ctx, "session/new", nil, nil); !errors.Is(err, acp.ErrRPCMethodDenied) {
		t.Fatalf("public transport bypassed durable grant: %v", err)
	}
	type outcome struct {
		record acp.SessionClaimRecord
		err    error
	}
	result := make(chan outcome, 1)
	go func() {
		record, err := client.CreateSession(ctx, claim)
		result <- outcome{record, err}
	}()
	select {
	case got := <-result:
		t.Fatalf("creation finished before process received request: %+v", got)
	case update, open := <-rpc.Updates():
		var evidence struct {
			SessionID string `json:"sessionId"`
			Update    struct {
				SessionUpdate string `json:"sessionUpdate"`
			} `json:"update"`
		}
		if !open || json.Unmarshal(update, &evidence) != nil ||
			evidence.SessionID != "unacknowledged-fixture-session" ||
			evidence.Update.SessionUpdate != "creation-received-proof" {
			t.Fatal("missing controlled process receipt evidence")
		}
	case <-ctx.Done():
		t.Fatal("process did not receive creation request")
	}
	persisted, err := store.ReadHarnessSessionClaim(ctx, claim)
	if err != nil || persisted.State != acp.ClaimUnknown || persisted.AgentSessionID != "" {
		t.Fatalf("request crossed process boundary without durable UNKNOWN: %+v %v", persisted, err)
	}
	if err := wait(true); err == nil {
		t.Fatal("process kill did not produce unsuccessful exit")
	} else {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ProcessState.Success() {
			t.Fatalf("process kill was not observed: %v", err)
		}
	}
	select {
	case got := <-result:
		if !errors.Is(got.err, acp.ErrSessionCreationUncertain) || got.record.State != acp.ClaimUnknown || got.record.AgentSessionID != "" {
			t.Fatalf("lost process ACK manufactured confirmation: %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("creation remained blocked after process termination")
	}
	restarted, nextRPC, nextWait := start("replay")
	got, err := restarted.CreateSession(ctx, claim)
	if !errors.Is(err, acp.ErrSessionCreationUncertain) || got != persisted {
		t.Fatalf("reconstructed process changed UNKNOWN evidence: %+v %v", got, err)
	}
	_ = nextRPC.Close()
	if err := nextWait(false); err != nil {
		t.Fatalf("reconstructed process observed unexpected RPC: %v", err)
	}
	after, err := postgres.New(pool).ReadHarnessSessionClaim(ctx, claim)
	if err != nil || after != persisted {
		t.Fatalf("process reconstruction mutated durable claim: %+v %v", after, err)
	}
}
