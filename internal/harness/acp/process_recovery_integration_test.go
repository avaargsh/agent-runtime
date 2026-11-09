package acp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

// subprocessHarnessStream joins real OS pipes without exposing process launch
// or process ownership through the production ACP transport.
type subprocessHarnessStream struct {
	stdout io.ReadCloser
	stdin  io.WriteCloser
}

func (p *subprocessHarnessStream) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *subprocessHarnessStream) Write(b []byte) (int, error) { return p.stdin.Write(b) }
func (p *subprocessHarnessStream) Close() error {
	_ = p.stdin.Close()
	return p.stdout.Close()
}

// This helper is a separately launched Go test executable, not an actual
// production coding Agent. Stdout contains ONLY the newline-delimited ACP v1
// JSON-RPC traffic. Its permission check fails the subprocess on any approval.
func TestACPSubprocessHarnessFixture(t *testing.T) {
	if os.Getenv("ACP_HARNESS_PROCESS_FIXTURE") != "1" {
		return
	}
	wire := bufio.NewReader(os.Stdin)
	die := func(msg string) {
		_, _ = fmt.Fprintln(os.Stderr, msg)
		os.Exit(37)
	}
	read := func() map[string]any {
		line, err := wire.ReadBytes('\n')
		if err != nil {
			die(fmt.Sprintf("fixture stdin read: %v", err))
		}
		var envelope map[string]any
		if err := json.Unmarshal(line, &envelope); err != nil {
			die(fmt.Sprintf("fixture request JSON: %v", err))
		}
		if envelope["jsonrpc"] != "2.0" {
			die("missing JSON-RPC 2.0 envelope")
		}
		return envelope
	}
	send := func(msg map[string]any) {
		data, err := json.Marshal(msg)
		if err != nil {
			die(fmt.Sprintf("fixture outbound JSON: %v", err))
		}
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			die(fmt.Sprintf("fixture stdout write: %v", err))
		}
	}

	initialize := read()
	if initialize["method"] != "initialize" {
		die("first RPC was not initialize")
	}
	send(map[string]any{
		"jsonrpc": "2.0", "id": initialize["id"],
		"result": map[string]any{
			"protocolVersion": 1,
			"agentCapabilities": map[string]any{"loadSession": true},
		},
	})

	load := read()
	if load["method"] != "session/load" {
		die(fmt.Sprintf("unexpected external RPC method: %v", load["method"]))
	}
	params, ok := load["params"].(map[string]any)
	if !ok || params["sessionId"] != "agent-session-1" || params["cwd"] != "/workspace" {
		die(fmt.Sprintf("session/load did not use trusted binding: %v", load["params"]))
	}
	send(map[string]any{
		"jsonrpc": "2.0", "id": 177, "method": "session/request_permission",
		"params": map[string]any{
			"sessionId": "agent-session-1",
			"options": []any{map[string]any{"optionId": "allow-once", "kind": "allow_once"}},
		},
	})
	permission := read()
	reply, ok := permission["result"].(map[string]any)
	if !ok || permission["id"] != float64(177) {
		die("permission request was not answered")
	}
	outcome, ok := reply["outcome"].(map[string]any)
	if !ok || outcome["outcome"] != "cancelled" {
		die("Runtime attempted to grant a privileged permission")
	}
	if _, selected := outcome["optionId"]; selected {
		die("Runtime chose an approval option")
	}
	// Prove that the permission response was handled while session/load was
	// outstanding. Do NOT send session/load's response; the parent kills us
	// after receiving this independent notification.
	send(map[string]any{
		"jsonrpc": "2.0", "method": "session/update",
		"params": map[string]any{
			"sessionId": "agent-session-1",
			"update": map[string]any{"sessionUpdate": "permission-denied-proof"},
		},
	})
	_, _ = io.Copy(io.Discard, wire)
	die("fixture exited before explicit process kill")
}

func TestACPRealSubprocessKilledDuringLoadRetainsUnknown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACPSubprocessHarnessFixture$")
	cmd.Env = append(os.Environ(), "ACP_HARNESS_PROCESS_FIXTURE=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
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
	defer func() {
		_ = cmd.Process.Kill()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	rpc, err := NewStreamRPC(&subprocessHarnessStream{stdout: stdout, stdin: stdin})
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	client, err := NewClient(rpc, &fakeStore{binding: confirmedBinding()}, "worker-codex-1")
	if err != nil {
		t.Fatal(err)
	}
	caps, err := client.Initialize(ctx)
	if err != nil || !caps.LoadSession {
		t.Fatalf("subprocess ACP initialize failed: %v, caps=%+v, stderr=%s", err, caps, stderr.String())
	}
	recovered := make(chan struct {
		status RecoveryStatus
		err    error
	}, 1)
	go func() {
		status, err := client.Recover(ctx, "tenant-a", "run-1")
		recovered <- struct {
			status RecoveryStatus
			err    error
		}{status, err}
	}()
	select {
	case unexpected := <-recovered:
		t.Fatalf("session/load ended before process crash: %+v, stderr=%s", unexpected, stderr.String())
	case update, open := <-rpc.Updates():
		if !open {
			t.Fatalf("subprocess closed before permission denial: %s", stderr.String())
		}
		var evidence struct {
			SessionID string `json:"sessionId"`
			Update    struct {
				SessionUpdate string `json:"sessionUpdate"`
			} `json:"update"`
		}
		if err := json.Unmarshal(update, &evidence); err != nil ||
			evidence.SessionID != "agent-session-1" ||
			evidence.Update.SessionUpdate != "permission-denied-proof" {
			t.Fatalf("unexpected agent permission proof: %s (%v)", update, err)
		}
	case <-ctx.Done():
		t.Fatalf("subprocess did not respond to permission while load pending: %v, stderr=%s", ctx.Err(), stderr.String())
	}

	// Force an actual OS process termination after its permission-denial
	// notification and before a session/load ACK. This is not net.Pipe.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("unable to terminate subprocess: %v", err)
	}
	processErr := cmd.Wait()
	waited = true
	if processErr == nil || cmd.ProcessState.Success() {
		t.Fatal("subprocess unexpectedly exited successfully, crash not proven")
	}
	select {
	case result := <-recovered:
		if result.status != RecoveryUnknown || result.err == nil {
			t.Fatalf("lost process ACK must remain UNKNOWN: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("lost process ACK left recovery blocked")
	}
	if status, err := client.Cancel(context.Background(), "tenant-a", "run-1"); status != RecoveryUnknown || !errors.Is(err, ErrRPCStreamClosed) {
		t.Fatalf("crashed Agent stream was reused for cancellation: status=%s err=%v", status, err)
	}
}
