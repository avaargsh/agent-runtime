package acp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
)

const MaxACPFrameBytes = 1 << 20

var (
	ErrRPCMethodDenied = errors.New("ACP v1 method is not permitted by this Runtime transport")
	ErrRPCStreamClosed = errors.New("ACP v1 transport is closed or untrusted")
)

// StreamRPC is a deliberately narrow, bounded JSON-RPC 2.0 transport.
// It does not launch processes or implement a general Agent harness. The caller
// supplies the already-isolated byte stream, and owns process authentication,
// isolation, limits, credentials and termination.
//
// Only initialize/session-load calls and session-cancel notifications can
// leave this adapter. Agent permission requests are always cancelled. No
// terminal, filesystem, session/new, session/prompt or protected effect can be
// initiated here. Updates are buffered only, NOT durable evidence.
type StreamRPC struct {
	stream io.ReadWriteCloser

	writeMu sync.Mutex
	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan streamReply
	updates chan json.RawMessage
	stopped error
}

type streamReply struct {
	result json.RawMessage
	err    error
}

type streamEnvelope struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

var _ RPC = (*StreamRPC)(nil)

// NewStreamRPC starts one inbound reader so Agent-initiated permission
// requests never block behind the outbound Call waiting for its result.
// A successful transport constructor does not authenticate or start an Agent.
func NewStreamRPC(stream io.ReadWriteCloser) (*StreamRPC, error) {
	if missingDependency(stream) {
		return nil, ErrInvalidConfiguration
	}
	s := &StreamRPC{
		stream:  stream,
		pending: make(map[int64]chan streamReply),
		updates: make(chan json.RawMessage, 32),
	}
	go s.readLoop()
	return s, nil
}

// Updates exposes untrusted, bounded session/update notification bytes. They
// require validation and durable Inbox handling by an eventual runtime owner.
// Failure to consume them closes the transport rather than silently dropping
// messages or allowing unbounded allocations.
func (s *StreamRPC) Updates() <-chan json.RawMessage {
	return s.updates
}

func (s *StreamRPC) Call(ctx context.Context, method string, params any, result any) error {
	if method != "initialize" && method != "session/load" {
		return ErrRPCMethodDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.stopped != nil {
		err := s.stopped
		s.mu.Unlock()
		return err
	}
	s.nextID++
	id := s.nextID
	resultCh := make(chan streamReply, 1)
	s.pending[id] = resultCh
	s.mu.Unlock()

	// A blocked Write on an uncooperative Agent cannot be interrupted by
	// selecting on ctx.Done after send returns. Close the entire stream on
	// cancellation: a partially written frame has an ambiguous outcome and
	// must never be followed by another command on the same connection.
	stopCancellation := context.AfterFunc(ctx, func() { s.fail(ctx.Err()) })
	defer stopCancellation()

	frame := map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	}
	if err := s.send(frame); err != nil {
		s.forget(id)
		return err
	}
	select {
	case response := <-resultCh:
		if response.err != nil {
			return response.err
		}
		if len(response.result) == 0 {
			return fmt.Errorf("%w: missing ACP response result", ErrRPCStreamClosed)
		}
		if result != nil {
			if err := json.Unmarshal(response.result, result); err != nil {
				return fmt.Errorf("%w: malformed ACP response: %v", ErrRPCStreamClosed, err)
			}
		}
		return nil
	case <-ctx.Done():
		s.forget(id)
		return ctx.Err()
	}
}

func (s *StreamRPC) Notify(ctx context.Context, method string, params any) error {
	if method != "session/cancel" {
		return ErrRPCMethodDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Notify also performs a potentially blocking Write. Treat cancelled
	// delivery as UNKNOWN and retire the connection, never as a sent ACK.
	stopCancellation := context.AfterFunc(ctx, func() { s.fail(ctx.Err()) })
	defer stopCancellation()
	return s.send(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func (s *StreamRPC) forget(id int64) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

func (s *StreamRPC) send(frame any) error {
	data, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("%w: invalid outbound JSON-RPC frame: %v", ErrRPCStreamClosed, err)
	}
	if len(data)+1 > MaxACPFrameBytes {
		return fmt.Errorf("%w: oversized outbound frame", ErrRPCStreamClosed)
	}
	data = append(data, '\n')
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped != nil {
		return stopped
	}
	n, err := s.stream.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.fail(fmt.Errorf("%w: write failed: %v", ErrRPCStreamClosed, err))
		return fmt.Errorf("%w: write failed: %v", ErrRPCStreamClosed, err)
	}
	return nil
}

func (s *StreamRPC) readLoop() {
	reader := bufio.NewScanner(s.stream)
	reader.Buffer(make([]byte, 4096), MaxACPFrameBytes+1)
	for reader.Scan() {
		var message streamEnvelope
		if err := json.Unmarshal(reader.Bytes(), &message); err != nil {
			s.fail(fmt.Errorf("%w: malformed Agent JSON: %v", ErrRPCStreamClosed, err))
			return
		}
		if message.Version != "2.0" {
			s.fail(fmt.Errorf("%w: Agent JSON-RPC version mismatch", ErrRPCStreamClosed))
			return
		}
		if message.Method != "" {
			if err := s.handleAgentMethod(message); err != nil {
				s.fail(err)
				return
			}
			continue
		}
		if err := s.handleAgentReply(message); err != nil {
			s.fail(err)
			return
		}
	}
	if err := reader.Err(); err != nil {
		s.fail(fmt.Errorf("%w: Agent frame read: %v", ErrRPCStreamClosed, err))
		return
	}
	s.fail(fmt.Errorf("%w: Agent stream ended", ErrRPCStreamClosed))
}

func validWireID(id json.RawMessage) bool {
	if len(id) == 0 || string(id) == "null" {
		return false
	}
	var value any
	if err := json.Unmarshal(id, &value); err != nil {
		return false
	}
	switch value.(type) {
	case string, float64:
		return true
	default:
		return false
	}
}

func (s *StreamRPC) handleAgentMethod(message streamEnvelope) error {
	if len(message.ID) > 0 {
		if !validWireID(message.ID) {
			return fmt.Errorf("%w: invalid Agent request ID", ErrRPCStreamClosed)
		}
		if message.Method == "session/request_permission" {
			// ACP v1's safe refusal. Never select even a caller-supplied
			// reject/allow option: this boundary has no approval authority.
			return s.send(map[string]any{
				"jsonrpc": "2.0", "id": message.ID,
				"result": map[string]any{
					"outcome": map[string]any{"outcome": "cancelled"},
				},
			})
		}
		// Methods requiring filesystem/terminal/interactive authority are
		// deliberately unsupported. Never invoke the host OS here.
		return s.send(map[string]any{
			"jsonrpc": "2.0", "id": message.ID,
			"error": map[string]any{"code": -32601, "message": "method not available"},
		})
	}
	if message.Method == "session/update" {
		s.mu.Lock()
		if s.stopped != nil {
			s.mu.Unlock()
			return s.stopped
		}
		copyOfUpdate := append(json.RawMessage(nil), message.Params...)
		select {
		case s.updates <- copyOfUpdate:
			s.mu.Unlock()
			return nil
		default:
			s.mu.Unlock()
			return fmt.Errorf("%w: Agent update backlog exceeded", ErrRPCStreamClosed)
		}
	}
	// Unknown notifications cannot grant capabilities. They have no response.
	return nil
}

func (s *StreamRPC) handleAgentReply(message streamEnvelope) error {
	if !validWireID(message.ID) {
		return fmt.Errorf("%w: response without valid ID", ErrRPCStreamClosed)
	}
	// JSON-RPC 2.0 requires exactly one of result and error. An absent,
	// null or contradictory response cannot be promoted to a successful
	// Agent ACK. Retire the stream so later calls cannot rely on its state.
	hasResult := len(message.Result) > 0 && string(message.Result) != "null"
	hasError := len(message.Error) > 0 && string(message.Error) != "null"
	if hasResult == hasError {
		return fmt.Errorf("%w: malformed or ambiguous Agent response", ErrRPCStreamClosed)
	}
	id, err := strconv.ParseInt(string(message.ID), 10, 64)
	if err != nil {
		// Our outbound request IDs are always integer, never Agent strings.
		return nil
	}
	reply := streamReply{result: message.Result}
	if len(message.Error) > 0 && string(message.Error) != "null" {
		var rpcError struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(message.Error, &rpcError); err != nil {
			return fmt.Errorf("%w: malformed Agent RPC error", ErrRPCStreamClosed)
		}
		reply.err = fmt.Errorf("ACP method failed (JSON-RPC %d): %s", rpcError.Code, rpcError.Message)
	}
	s.mu.Lock()
	pending := s.pending[id]
	delete(s.pending, id)
	if pending != nil {
		pending <- reply // one buffered response, never blocks the inbound pump
	}
	s.mu.Unlock()
	return nil
}

func (s *StreamRPC) fail(err error) {
	s.mu.Lock()
	if s.stopped != nil {
		s.mu.Unlock()
		return
	}
	s.stopped = err
	for id, pending := range s.pending {
		pending <- streamReply{err: err}
		delete(s.pending, id)
	}
	close(s.updates)
	s.mu.Unlock()
	_ = s.stream.Close()
}

func (s *StreamRPC) Close() error {
	s.fail(ErrRPCStreamClosed)
	return nil
}
