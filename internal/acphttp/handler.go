// Package acphttp exposes the trusted Control Plane to Runtime RunIntent
// acceptance boundary. Client authentication must be enforced by verified
// mutual TLS; an HTTP forwarded identity is never accepted as authority.
package acphttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/avaargsh/agent-runtime/internal/run"
)

const (
	maxBodyBytes = 256*1024 + 4096
	acceptPath   = "/internal/v1/run-intents:accept"
	inspectPath  = "/internal/v1/run-intents/"
)

type Store interface {
	AcceptIntent(context.Context, run.IntentStartRequest) (run.IntentReceipt, error)
	LookupIntent(context.Context, string, string, string) (run.IntentReceipt, error)
}

type handler struct {
	store    Store
	identity string
}

// NewHandler refuses to expose a privileged Run creation endpoint without
// an exact trusted SPIFFE workload identity and a durable Store.
func NewHandler(store Store, expectedSPIFFEID string) (http.Handler, error) {
	u, err := url.Parse(expectedSPIFFEID)
	if store == nil || err != nil || u.Scheme != "spiffe" || u.Host == "" ||
		u.Path == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.String() != expectedSPIFFEID {
		return nil, errors.New("invalid ACP trust configuration")
	}
	h := &handler{store: store, identity: expectedSPIFFEID}
	return http.HandlerFunc(h.serve), nil
}

// verifyPeer trusts only a peer in the transport's verified certificate
// chains. This does not itself verify certificates: the TLS server must use
// tls.RequireAndVerifyClientCert with a configured ClientCAs trust store.
func (h *handler) verifyPeer(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 ||
		len(r.TLS.VerifiedChains) == 0 {
		return false
	}
	leaf := r.TLS.PeerCertificates[0]
	verified := false
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) == 0 {
			continue
		}
		c := chain[0]
		if c == leaf || (len(c.Raw) > 0 && bytes.Equal(c.Raw, leaf.Raw)) {
			verified = true
			break
		}
	}
	if !verified {
		return false
	}
	for _, uri := range leaf.URIs {
		if uri != nil && uri.String() == h.identity {
			return true
		}
	}
	return false
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	if !h.verifyPeer(r) {
		writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	if r.URL.Path == acceptPath {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		h.accept(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, inspectPath) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		h.inspect(w, r)
		return
	}
	writeError(w, http.StatusNotFound, "NOT_FOUND")
}

type requestWire struct {
	TenantID       string          `json:"tenant_id"`
	RunIntentID    string          `json:"run_intent_id"`
	RequestDigest  string          `json:"request_digest"`
	AgentID        string          `json:"agent_id"`
	AgentReleaseID string          `json:"agent_release_id"`
	SessionID      string          `json:"session_id"`
	Input          json.RawMessage `json:"input"`
}

func (h *handler) accept(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil || len(raw) == 0 || !utf8.Valid(raw) ||
		validateUniqueJSON(raw) != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire requestWire
	if err := decoder.Decode(&wire); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if _, err := decoder.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	command := run.IntentStartRequest{
		TenantID: wire.TenantID, RunIntentID: wire.RunIntentID,
		RequestDigest: wire.RequestDigest, AgentID: wire.AgentID,
		AgentReleaseID: wire.AgentReleaseID, SessionID: wire.SessionID,
		Input: wire.Input,
	}
	if err := command.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	receipt, err := h.store.AcceptIntent(r.Context(), command)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusOK
	if receipt.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, foundResponse(receipt))
}

func (h *handler) inspect(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, inspectPath)
	queries, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(queries) != 2 ||
		len(queries["tenant_id"]) != 1 || len(queries["request_digest"]) != 1 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	tenant := queries.Get("tenant_id")
	digest := queries.Get("request_digest")
	command := run.IntentStartRequest{
		TenantID: tenant, RunIntentID: id, RequestDigest: digest,
		AgentID: "lookup", AgentReleaseID: "lookup", SessionID: "lookup",
	}
	if err := command.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	receipt, err := h.store.LookupIntent(r.Context(), tenant, id, digest)
	if errors.Is(err, run.ErrIntentNotFound) {
		// No durable final-absence barrier has been proven; 404 would be
		// misinterpreted by clients as final absent and can cause duplicate Run.
		writeJSON(w, http.StatusOK, map[string]string{"status": "ABSENT_UNCERTAIN"})
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, foundResponse(receipt))
}

func foundResponse(r run.IntentReceipt) map[string]any {
	return map[string]any{
		"status": "FOUND", "tenant_id": r.TenantID,
		"run_intent_id": r.RunIntentID, "request_digest": r.RequestDigest,
		"run_id": r.RunID, "workflow_id": r.WorkflowID, "created": r.Created,
	}
}
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, run.ErrInvalidRequest):
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
	case errors.Is(err, run.ErrIdempotencyConflict):
		writeError(w, http.StatusConflict, "INTENT_CONFLICT")
	default:
		writeError(w, http.StatusServiceUnavailable, "STORE_UNAVAILABLE")
	}
}
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// validateUniqueJSON rejects unknown JSON shape ambiguity even inside input.
// Depth is bounded independently of the overall body-size guard.
func validateUniqueJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting limit exceeded")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		open, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch open {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate JSON key")
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return errors.New("invalid JSON end")
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return errors.New("invalid array end")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
