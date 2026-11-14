package acp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// A bounded ACP seam does not need multiple outstanding request/reply calls.
// A second session/load must fail promptly without sending another JSON-RPC
// frame or killing the first in-flight load. One-way cancellation remains valid.
func TestStreamRPCRejectsSecondInFlightCallWithoutRetiringFirst(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer clientConn.Close()
	defer agentConn.Close()
	if err := agentConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rpc, err := NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first := make(chan error, 1)
	go func() {
		var result struct{}
		first <- rpc.Call(ctx, "session/load", map[string]any{"sessionId": "bound-session"}, &result)
	}()
	wire := bufio.NewReader(agentConn)
	request := readRPCLine(t, wire)
	if request["method"] != "session/load" {
		t.Fatalf("first ACP call not dispatched: %+v", request)
	}

	second := make(chan error, 1)
	go func() {
		var result struct{}
		second <- rpc.Call(ctx, "session/load", map[string]any{"sessionId": "reentrant-session"}, &result)
	}()
	select {
	case err := <-second:
		if !errors.Is(err, ErrRPCInFlight) {
			t.Fatalf("second outstanding load was not rejected with bounded error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("second outstanding load blocked rather than being rejected promptly")
	}

	cancelDone := make(chan error, 1)
	go func() {
		cancelDone <- rpc.Notify(ctx, "session/cancel", map[string]any{"sessionId": "bound-session"})
	}()
	notification := readRPCLine(t, wire)
	if notification["method"] != "session/cancel" {
		t.Fatalf("one-way cancellation was blocked by pending load: %+v", notification)
	}
	select {
	case err := <-cancelDone:
		if err != nil {
			t.Fatalf("cancel notification failed during pending load: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("cancel notification never completed")
	}
	writeRPCLine(t, agentConn, map[string]any{"jsonrpc": "2.0", "id": request["id"], "result": map[string]any{}})
	select {
	case err := <-first:
		if err != nil {
			t.Fatalf("rejected second call retired the first: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("first call never completed")
	}
}

func TestStreamRPCV1HandlesPermissionDenyWhileLoadPending(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer agentConn.Close()
	defer clientConn.Close()
	if err := agentConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rpc, err := NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	complete := make(chan error, 1)
	go func() {
		var response struct{}
		complete <- rpc.Call(ctx, "session/load", map[string]any{
			"sessionId": "session-1", "cwd": "/workspace", "mcpServers": []any{},
		}, &response)
	}()

	wire := bufio.NewReader(agentConn)
	request := readRPCLine(t, wire)
	if request["method"] != "session/load" {
		t.Fatalf("unexpected method: %+v", request)
	}
	id := request["id"]
	writeRPCLine(t, agentConn, map[string]any{
		"jsonrpc": "2.0", "method": "session/update",
		"params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "agent_message_chunk"}},
	})
	writeRPCLine(t, agentConn, map[string]any{
		"jsonrpc": "2.0", "id": 95, "method": "session/request_permission",
		"params": map[string]any{
			"sessionId": "session-1", "toolCall": map[string]any{"toolCallId": "danger"},
			"options": []any{map[string]any{"optionId": "allow-once", "kind": "allow_once", "name": "Allow once"}},
		},
	})
	denial := readRPCLine(t, wire)
	if denial["id"] != float64(95) {
		t.Fatalf("permission response ID mismatch: %+v", denial)
	}
	result, ok := denial["result"].(map[string]any)
	if !ok {
		t.Fatalf("permission request was not answered with outcome: %+v", denial)
	}
	outcome, ok := result["outcome"].(map[string]any)
	if !ok || outcome["outcome"] != "cancelled" {
		t.Fatalf("Agent permission was not denied: %+v", denial)
	}
	if _, approved := outcome["optionId"]; approved {
		t.Fatalf("transport selected an approval option: %+v", denial)
	}
	writeRPCLine(t, agentConn, map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{}})
	select {
	case err := <-complete:
		if err != nil {
			t.Fatalf("pending load blocked despite answering permission request: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("pending load deadlocked on inbound permission")
	}
	// The transport has no authority to create sessions, prompt the Agent or
	// expose a client-side terminal, even if callers attempt to bypass Client.
	if err := rpc.Call(ctx, "session/new", nil, new(struct{})); !errors.Is(err, ErrRPCMethodDenied) {
		t.Fatalf("unfenced new session was sent: %v", err)
	}
	if err := rpc.Notify(ctx, "terminal/create", nil); !errors.Is(err, ErrRPCMethodDenied) {
		t.Fatalf("client terminal method was sent: %v", err)
	}
}

func TestStreamRPCRejectsInboundFilesystemAndTerminalRequests(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer agentConn.Close()
	defer clientConn.Close()
	if err := agentConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rpc, err := NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	wire := bufio.NewReader(agentConn)
	for _, method := range []string{"fs/read_text_file", "fs/write_text_file", "terminal/create"} {
		writeRPCLine(t, agentConn, map[string]any{"jsonrpc": "2.0", "id": method, "method": method, "params": map[string]any{"path": "/secret"}})
		answer := readRPCLine(t, wire)
		errObj, ok := answer["error"].(map[string]any)
		if !ok || errObj["code"] != float64(-32601) || answer["id"] != method {
			t.Fatalf("unexpected privileged method response: %+v", answer)
		}
	}
}

func TestStreamRPCOversizeResponseFailsPendingCallClosed(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer agentConn.Close()
	defer clientConn.Close()
	if err := agentConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rpc, err := NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	complete := make(chan error, 1)
	go func() {
		var response struct{}
		complete <- rpc.Call(ctx, "initialize", map[string]any{"protocolVersion": 1}, &response)
	}()
	wire := bufio.NewReader(agentConn)
	_ = readRPCLine(t, wire)
	// Untrusted stdout cannot cause unlimited memory growth or a successful
	// initialization. A transport fault must not be treated as a safe ACK.
	_, _ = agentConn.Write([]byte(strings.Repeat("x", MaxACPFrameBytes+100) + "\n"))
	select {
	case err := <-complete:
		if err == nil {
			t.Fatal("oversized Agent frame was treated as a successful response")
		}
	case <-ctx.Done():
		t.Fatal("oversized Agent frame did not fail closed")
	}
}

// Duplicate top-level JSON-RPC ACK keys are ambiguous even when their values
// match: encoding/json silently keeps the last occurrence. A malicious Agent
// must not be able to turn that ambiguity into a confirmed session/load.
func TestStreamRPCDuplicateTopLevelACKFieldsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame string
	}{
		{"duplicate-result", `{"jsonrpc":"2.0","id":__ID__,"result":{},"result":{}}`},
		{"duplicate-id", `{"jsonrpc":"2.0","id":__ID__,"id":__ID__,"result":{}}`},
		{"duplicate-version", `{"jsonrpc":"2.0","jsonrpc":"2.0","id":__ID__,"result":{}}`},
		{"nested-duplicate-version", `{"jsonrpc":"2.0","id":__ID__,"result":{"protocolVersion":2,"protocolVersion":1}}`},
		{"nested-casefold-protocol-version", `{"jsonrpc":"2.0","id":__ID__,"result":{"protocolVersion":2,"ProtocolVersion":1}}`},
		{"nested-casefold-capability", `{"jsonrpc":"2.0","id":__ID__,"result":{"agentCapabilities":{"loadSession":false,"LoadSession":true}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, agentConn := net.Pipe()
			defer clientConn.Close()
			defer agentConn.Close()
			if err := agentConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			rpc, err := NewStreamRPC(clientConn)
			if err != nil {
				t.Fatal(err)
			}
			defer rpc.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				var reply struct{}
				finished <- rpc.Call(ctx, "session/load", map[string]any{
					"sessionId": "existing-session",
				}, &reply)
			}()
			request := readRPCLine(t, bufio.NewReader(agentConn))
			id, err := json.Marshal(request["id"])
			if err != nil {
				t.Fatal(err)
			}
			raw := strings.ReplaceAll(tc.frame, "__ID__", string(id)) + "\n"
			if _, err := agentConn.Write([]byte(raw)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				if !errors.Is(err, ErrRPCStreamClosed) {
					t.Fatalf("ambiguous Agent ACK was accepted: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("ambiguous Agent ACK did not close the pending RPC")
			}
			if err := rpc.Notify(context.Background(), "session/cancel", nil); !errors.Is(err, ErrRPCStreamClosed) {
				t.Fatalf("ambiguous ACK left StreamRPC reusable: %v", err)
			}
		})
	}
}

func readRPCLine(t *testing.T, reader *bufio.Reader) map[string]any {
	t.Helper()
	data, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("malformed outgoing JSON-RPC: %v: %s", err, data)
	}
	if payload["jsonrpc"] != "2.0" {
		t.Fatalf("wrong JSON-RPC version: %+v", payload)
	}
	return payload
}

func writeRPCLine(t *testing.T, conn net.Conn, payload any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRPCCancelUnblocksStalledWriteAndFailsClosed(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer agentConn.Close()
	defer clientConn.Close()
	// Deliberately never read the Agent end: net.Pipe.Write blocks until
	// the peer consumes the bytes or the transport closes.
	rpc, err := NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		var result struct{}
		finished <- rpc.Call(ctx, "initialize", map[string]any{"protocolVersion": 1}, &result)
	}()
	select {
	case err := <-finished:
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrRPCStreamClosed) {
			t.Fatalf("stalled write must fail closed on cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ACP outbound Call hung on a non-reading Agent despite context deadline")
	}
	// Once a write was ambiguous, the stream must never be reused to
	// dispatch a second command to a possibly desynchronized Agent.
	if err := rpc.Notify(context.Background(), "session/cancel", nil); err == nil {
		t.Fatal("ambiguous cancelled write left the transport reusable")
	}
}

func TestStreamRPCRejectsAmbiguousAgentResponseAndRetiresStream(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply func(any) map[string]any
	}{
		{"both result and error", func(id any) map[string]any {
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{},
				"error": map[string]any{"code": -32000, "message": "failed"}}
		}},
		{"neither result nor error", func(id any) map[string]any {
			return map[string]any{"jsonrpc": "2.0", "id": id}
		}},
		{"null result", func(id any) map[string]any {
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": nil}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, agentConn := net.Pipe()
			defer clientConn.Close()
			defer agentConn.Close()
			if err := agentConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			rpc, err := NewStreamRPC(clientConn)
			if err != nil {
				t.Fatal(err)
			}
			defer rpc.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				var response struct{}
				finished <- rpc.Call(ctx, "initialize", map[string]any{"protocolVersion": 1}, &response)
			}()
			wire := bufio.NewReader(agentConn)
			request := readRPCLine(t, wire)
			writeRPCLine(t, agentConn, tc.reply(request["id"]))
			select {
			case err := <-finished:
				if !errors.Is(err, ErrRPCStreamClosed) {
					t.Fatalf("ambiguous response accepted: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("ambiguous response blocked pending RPC")
			}
			if err := rpc.Notify(context.Background(), "session/cancel", nil); !errors.Is(err, ErrRPCStreamClosed) {
				t.Fatalf("ambiguous response left connection reusable: %v", err)
			}
		})
	}
}

// Agent-controlled JSON-RPC error text is not a trusted Runtime diagnostic.
// Preserve the numeric code for triage without copying secrets or log-control
// characters into errors that callers may persist in audit/log records.
func TestStreamRPCDoesNotExposeAgentErrorText(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer clientConn.Close()
	defer agentConn.Close()
	if err := agentConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rpc, err := NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		var result struct{}
		finished <- rpc.Call(ctx, "session/load", map[string]any{"sessionId": "existing-session"}, &result)
	}()
	request := readRPCLine(t, bufio.NewReader(agentConn))
	writeRPCLine(t, agentConn, map[string]any{
		"jsonrpc": "2.0", "id": request["id"],
		"error": map[string]any{
			"code":    -32042,
			"message": "AGENT_UNTRUSTED_CANARY\nFORGED_AUDIT_LINE",
		},
	})
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("Agent JSON-RPC error was treated as successful load")
		}
		if strings.Contains(err.Error(), "AGENT_UNTRUSTED_CANARY") ||
			strings.Contains(err.Error(), "FORGED_AUDIT_LINE") ||
			strings.Contains(err.Error(), "\n") {
			t.Fatalf("untrusted Agent error content escaped transport: %v", err)
		}
		if !strings.Contains(err.Error(), "-32042") {
			t.Fatalf("safe JSON-RPC error code was lost: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Agent JSON-RPC error did not finish pending call")
	}
}

func TestStreamRPCMalformedResultRetiresConnection(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer clientConn.Close()
	defer agentConn.Close()
	if err := agentConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rpc, err := NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		var result struct{}
		finished <- rpc.Call(ctx, "session/load", map[string]any{"sessionId": "session-1"}, &result)
	}()
	request := readRPCLine(t, bufio.NewReader(agentConn))
	writeRPCLine(t, agentConn, map[string]any{
		"jsonrpc": "2.0", "id": request["id"], "result": []any{"invalid-object"},
	})
	select {
	case err := <-finished:
		if !errors.Is(err, ErrRPCStreamClosed) {
			t.Fatalf("invalid result type did not fail closed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("invalid result type blocked session/load")
	}
	if err := rpc.Notify(context.Background(), "session/cancel", nil); !errors.Is(err, ErrRPCStreamClosed) {
		t.Fatalf("malformed result left stream reusable: %v", err)
	}
}

func TestStreamRPCCancelAfterSendRetiresConnection(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer clientConn.Close()
	defer agentConn.Close()
	if err := agentConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rpc, err := NewStreamRPC(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() {
		var result struct{}
		finished <- rpc.Call(ctx, "session/load", map[string]any{"sessionId": "session-1"}, &result)
	}()
	_ = readRPCLine(t, bufio.NewReader(agentConn))
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrRPCStreamClosed) {
			t.Fatalf("cancelled session/load returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled session/load blocked")
	}
	// The retired stream retains its cancellation cause. A second call with
	// a fresh context cannot dispatch, whether the sentinel or cause is returned.
	if err := rpc.Notify(context.Background(), "session/cancel", nil); !errors.Is(err, ErrRPCStreamClosed) && !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled RPC left connection reusable: %v", err)
	}
}
