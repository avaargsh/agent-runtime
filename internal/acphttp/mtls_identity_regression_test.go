package acphttp_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/acphttp"
	"github.com/avaargsh/agent-runtime/internal/run"
)

// The HTTP boundary must not accept a merely populated VerifiedChains slice
// unless the handshake is complete and the identity SAN is unambiguous.
func TestACPIdentityRejectsAmbiguousOrIncompleteTLS(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{
			name: "incomplete TLS handshake",
			mutate: func(r *http.Request) {
				r.TLS.HandshakeComplete = false
			},
		},
		{
			name: "TLS 1.2 is not an accepted transport",
			mutate: func(r *http.Request) {
				r.TLS.Version = tls.VersionTLS12
			},
		},
		{
			name: "additional URI SAN is ambiguous",
			mutate: func(r *http.Request) {
				other, _ := url.Parse("spiffe://other.example/ns/control/sa/other")
				r.TLS.PeerCertificates[0].URIs = append(r.TLS.PeerCertificates[0].URIs, other)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newHandler(t)
			r := httptest.NewRequest(http.MethodPost, "/internal/v1/run-intents:accept", strings.NewReader(body()))
			r.Header.Set("Content-Type", "application/json")
			authorized(r)
			tc.mutate(r)
			w := httptest.NewRecorder()
			app.h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("untrusted TLS state accepted: status=%d", w.Code)
			}
			if len(app.store.receipts) != 0 {
				t.Fatal("untrusted TLS state persisted a Run")
			}
		})
	}
}

func TestACPIdentityConfigurationRejectsEmptyQueryMarker(t *testing.T) {
	app := newHandler(t)
	if _, err := acphttp.NewHandler(app.store, acpID+"?"); err == nil {
		t.Fatal("empty-query SPIFFE URI must not become an accepted principal")
	}
}

// The Safety and ACP mTLS handlers must share an exact SPIFFE workload ID
// contract, including no explicit port or root-only path.
type inertSafetyReader struct{}

func (inertSafetyReader) GetTrustedGuardRunSafetySnapshot(context.Context, string, string) (run.GuardRunSafetySnapshot, error) {
	return run.GuardRunSafetySnapshot{}, run.ErrRunNotFound
}

func TestSafetyAndACPRejectNoncanonicalWorkloadID(t *testing.T) {
	store := newHandler(t).store
	for _, peer := range []string{
		"spiffe://agent.example:443/ns/control/sa/guard",
		"spiffe://agent.example/",
	} {
		t.Run(peer, func(t *testing.T) {
			if _, err := acphttp.NewHandler(store, peer); err == nil {
				t.Fatalf("ACP accepted noncanonical SPIFFE identity %q", peer)
			}
			if _, err := acphttp.NewRunSafetyHandler(inertSafetyReader{}, peer, "tenant-1"); err == nil {
				t.Fatalf("Safety accepted noncanonical SPIFFE identity %q", peer)
			}
		})
	}
	if _, err := acphttp.NewRunSafetyHandler(inertSafetyReader{}, "spiffe://agent.example/ns/guard/sa/guard", "tenant-1"); err != nil {
		t.Fatalf("canonical Safety workload identity rejected: %v", err)
	}
}
