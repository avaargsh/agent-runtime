package acphttp

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
)

const GuardExecutionAuthorityPathPrefix = "/internal/v1/guard-execution-authority/"

type GuardExecutionAuthorityReader interface {
	GetTrustedGuardExecutionAuthority(context.Context, string, string, string) (run.GuardExecutionAuthority, error)
}

// NewGuardExecutionAuthorityHandler binds one exact Guard workload identity
// and one provisioned tenant. Run/Turn IDs in the path are selectors only;
// Runtime resolves their canonical Attempt/Turn binding from PostgreSQL.
func NewGuardExecutionAuthorityHandler(reader GuardExecutionAuthorityReader, peer, tenant string) (http.Handler, error) {
	if reader == nil || !validWorkloadIdentity(peer) || tenant == "" ||
		len(tenant) > 255 || strings.TrimSpace(tenant) != tenant ||
		strings.ContainsAny(tenant, "\x00\r\n\t") {
		return nil, errors.New("invalid Guard execution authority configuration")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if !verifyWorkloadPeer(r, peer) {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		now := time.Now()
		clientAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth
		}
		if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
			leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !clientAuth {
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
			!strings.HasPrefix(r.URL.Path, GuardExecutionAuthorityPathPrefix) {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, GuardExecutionAuthorityPathPrefix), "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		for _, value := range parts {
			id, err := uuid.Parse(value)
			if err != nil || id.String() != value {
				writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		authority, err := reader.GetTrustedGuardExecutionAuthority(ctx, tenant, parts[0], parts[1])
		if errors.Is(err, run.ErrGuardExecutionAuthorityDenied) {
			writeError(w, http.StatusForbidden, "GUARD_EXECUTION_AUTHORITY_DENIED")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "GUARD_EXECUTION_AUTHORITY_UNAVAILABLE")
			return
		}
		if authority.Validate() != nil || authority.TenantID != tenant ||
			authority.RunID != parts[0] || authority.TurnID != parts[1] {
			writeError(w, http.StatusForbidden, "GUARD_EXECUTION_AUTHORITY_DENIED")
			return
		}
		writeJSON(w, http.StatusOK, authority)
	}), nil
}
