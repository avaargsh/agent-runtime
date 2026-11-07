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
		name string
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
