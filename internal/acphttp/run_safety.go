package acphttp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
)

const RunSafetyPathPrefix = "/internal/v1/runs/"
const runSafetySchema = "runtime.run-safety.v1"

type RunSafetyReader interface {
	GetTrustedGuardRunSafetySnapshot(context.Context, string, string) (run.GuardRunSafetySnapshot, error)
}

// NewRunSafetyHandler authorizes a single explicitly provisioned service
// identity for a single tenant. Do not derive tenant from HTTP headers,
// query strings, JSON, or the requested Run ID. No delegated multi-tenant
// identity is supported until the owning authority ratifies that contract.
func NewRunSafetyHandler(store RunSafetyReader, peer, tenant string) (http.Handler, error) {
	if store == nil || !validWorkloadIdentity(peer) || tenant == "" ||
		len(tenant) > 255 || strings.TrimSpace(tenant) != tenant || !utf8.ValidString(tenant) ||
		strings.ContainsAny(tenant, "\x00\r\n\t") {
		return nil, errors.New("invalid Runtime safety authority configuration")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if !verifyWorkloadPeer(r, peer) {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		// A TLS keepalive must not extend the peer's credential validity.
		now := time.Now()
		leaf := r.TLS.PeerCertificates[0]
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" ||
			r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
			!strings.HasPrefix(r.URL.Path, RunSafetyPathPrefix) || !strings.HasSuffix(r.URL.Path, "/safety") {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, RunSafetyPathPrefix), "/safety")
		u, err := uuid.Parse(id)
		if err != nil || u.String() != id {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		snapshot, err := store.GetTrustedGuardRunSafetySnapshot(r.Context(), tenant, id)
		if errors.Is(err, run.ErrRunNotFound) || errors.Is(err, run.ErrInvalidIdentity) {
			writeError(w, http.StatusForbidden, "RUN_SAFETY_DENIED")
			return
		}
		if err != nil {
			// A missing/malformed breaker is indistinguishable here from an
			// unavailable authority. No stale snapshot or internal SQL leaks.
			writeError(w, http.StatusServiceUnavailable, "RUN_SAFETY_UNAVAILABLE")
			return
		}
		if snapshot.Identity.TenantID != tenant || snapshot.Identity.RunID != id || !snapshot.EligibleForGuardSubmission() {
			writeError(w, http.StatusForbidden, "RUN_SAFETY_DENIED")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			SchemaVersion  string `json:"schema_version"`
			TenantID       string `json:"tenant_id"`
			RunID          string `json:"run_id"`
			AgentID        string `json:"agent_id"`
			AgentReleaseID string `json:"agent_release_id"`
			SessionID      string `json:"session_id"`
			Status         string `json:"status"`
			BreakerState   string `json:"breaker_state"`
			BreakerEpoch   uint64 `json:"breaker_epoch"`
			BreakerVersion uint64 `json:"breaker_version"`
		}{runSafetySchema, tenant, id, snapshot.Identity.AgentID, snapshot.Identity.AgentReleaseID,
			snapshot.Identity.SessionID, string(snapshot.Status), snapshot.BreakerState,
			snapshot.BreakerEpoch, snapshot.BreakerVersion})
	}), nil
}
