package acphttp

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
)

const DecisionAuthorityPath = "/internal/v1/decision-authority/"

type DecisionAuthorityReader interface {
	GetDecisionAuthority(context.Context, string, string, string) (run.DecisionAuthority, error)
}

// NewDecisionAuthorityHandler is a dedicated read-only listener. The
// operator binds an exact authenticated Decision peer and tenant; it
// never grants access to Runtime's privileged ACP acceptance endpoints.
func NewDecisionAuthorityHandler(reader DecisionAuthorityReader, peer, tenant string) (http.Handler, error) {
	u, err := url.Parse(peer)
	if reader == nil || err != nil || u.Scheme != "spiffe" || u.Host == "" ||
		u.Port() != "" || u.Path == "" || u.Path == "/" || u.User != nil ||
		u.Opaque != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.String() != peer || tenant == "" || len(tenant) > 255 ||
		strings.TrimSpace(tenant) != tenant || strings.ContainsAny(tenant, "\x00\r\n\t ") {
		return nil, errors.New("invalid Decision authority trust configuration")
	}
	h := &handler{identity: peer}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.verifyPeer(r) {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		if leaf.IsCA || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) ||
			leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		clientAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth
		}
		if !clientAuth {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, DecisionAuthorityPath)
		q, err := url.ParseQuery(r.URL.RawQuery)
		canonical := func(value string) bool {
			parsed, err := uuid.Parse(value)
			return err == nil && parsed.String() == value
		}
		if err != nil || !strings.HasPrefix(r.URL.Path, DecisionAuthorityPath) || r.URL.RawPath != "" ||
			r.URL.ForceQuery || len(q) != 1 || len(q["invocation_id"]) != 1 ||
			!canonical(id) || !canonical(q.Get("invocation_id")) ||
			r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		a, err := reader.GetDecisionAuthority(ctx, tenant, id, q.Get("invocation_id"))
		switch {
		case errors.Is(err, run.ErrDecisionPreparationDenied):
			writeError(w, http.StatusForbidden, "DECISION_AUTHORITY_DENIED")
		case err != nil || a.Validate() != nil || a.TenantID != tenant || a.RunID != id || a.InvocationID != q.Get("invocation_id"):
			writeError(w, http.StatusServiceUnavailable, "DECISION_AUTHORITY_UNAVAILABLE")
		default:
			writeJSON(w, http.StatusOK, a)
		}
	}), nil
}
