package decisioncontinuation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
)

const decisionPeer = "spiffe://example.org/agent-decision"

type acceptanceProbe struct {
	calls   int
	receipt run.DecisionContinuationReceipt
}

func (p *acceptanceProbe) AcceptDecisionContinuation(_ context.Context, expected run.DecisionAuthority, receipt run.DecisionContinuationReceipt) (run.DecisionContinuationReceipt, error) {
	p.calls++
	if receipt.Authority != expected {
		return run.DecisionContinuationReceipt{}, run.ErrDecisionPreparationDenied
	}
	p.receipt = receipt
	return receipt, nil
}

func fixtureAuthority() run.DecisionAuthority {
	id := "11111111-1111-4111-8111-111111111111"
	turn := "55555555-5555-4555-8555-555555555555"
	return run.DecisionAuthority{
		SchemaVersion: run.DecisionAuthoritySchema,
		TenantID:      "tenant-1", RunID: id,
				RunIntentID:       "22222222-2222-4222-8222-222222222222",
		RequestDigest:     "sha256:" + strings.Repeat("a", 64),
		WorkflowID:        "agent-run/v1/" + id,
		ExecutionID:       "33333333-3333-4333-8333-333333333333",
		AttemptID:         "44444444-4444-4444-8444-444444444444",
		AttemptGeneration: 1,
		TurnID:            turn, InvocationID: turn,
		AgentID: "agent-1", AgentReleaseID: "release-1", SessionID: "session-1",
		ProjectID: "project-1", SubjectID: "subject-1", ActorID: "subject-1",
		PolicyRevision: "policy-1", ConfigDigest: "sha256:" + strings.Repeat("b", 64),
		InputDigest: "sha256:" + strings.Repeat("c", 64),
		Phase:       run.DecisionWaitingAuthority, Status: "RUNNING", BreakerState: "CLOSED",
		BreakerEpoch: 1, BreakerVersion: 1,
	}
}

func fixtureReceipt(t *testing.T, a run.DecisionAuthority) run.DecisionContinuationReceipt {
	t.Helper()
	identity, err := json.Marshal(struct{ TenantID, InvocationID string }{a.TenantID, a.InvocationID})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(identity)
	return run.DecisionContinuationReceipt{
		SchemaVersion: run.DecisionContinuationSchema, Authority: a,
		DecisionID:   "dec_" + hex.EncodeToString(sum[:]),
		RecordSHA256: strings.Repeat("d", 64), PlanHash: strings.Repeat("e", 64),
	}
}

// Exercise real TLS 1.3 server identity and mutual authentication, not an
// injected TLS-state mock. A valid CA-signed but wrong SPIFFE peer must fail.
func tlsDecisionFixture(t *testing.T, peer string, handler http.Handler) (string, *http.Client) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, uri string, use x509.ExtKeyUsage, server bool) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		san, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{use},
			URIs: []*url.URL{san},
		}
		if server {
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	serverCert := issue(2, peer, x509.ExtKeyUsageServerAuth, true)
	clientCert := issue(3, "spiffe://example.org/agent-runtime", x509.ExtKeyUsageClientAuth, false)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool, Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: pool,
			Certificates: []tls.Certificate{clientCert},
		}},
	}
	t.Cleanup(client.CloseIdleConnections)
	return server.URL, client
}

func TestVerifiedDecisionContinuationAcceptsOnlyExactFreshAuthenticatedReceipt(t *testing.T) {
	a := fixtureAuthority()
	if err := a.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	receipt := fixtureReceipt(t, a)
	if err := receipt.Validate(); err != nil {
		t.Fatalf("receipt invalid: %v", err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	expectedPath := "/internal/v1/decision-turns/" + a.RunID + "/" + a.InvocationID + "/verify"
	var observedPath string
	serverURL, client := tlsDecisionFixture(t, decisionPeer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedPath = r.URL.Path
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Accept") != "application/json" {
			t.Error("unsafe Decision receipt request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	}))
	reader, err := NewClient(serverURL, client, decisionPeer)
	if err != nil {
		t.Fatal(err)
	}
	store := &acceptanceProbe{}
	got, err := reader.VerifyAndAccept(context.Background(), a, store)
	if err != nil || got != receipt || store.calls != 1 || store.receipt != receipt {
		t.Fatalf("verified CAS failed: %v %+v %+v", err, got, store)
	}
	if observedPath != expectedPath {
		t.Fatalf("verification path %q", observedPath)
	}
}

func TestDecisionContinuationFailClosedOnWrongPeerAndResponse(t *testing.T) {
	a := fixtureAuthority()
	valid := fixtureReceipt(t, a)
	changed := valid
	changed.Authority.BreakerVersion++
	tests := []struct {
		name        string
		peer        string
		status      int
		body        []byte
		ctype       string
		cache       string
		unavailable bool
	}{
		{name: "wrong SPIFFE server", peer: "spiffe://example.org/attacker", status: 200, body: mustJSON(t, valid), ctype: "application/json", cache: "no-store"},
		{name: "stale breaker", peer: decisionPeer, status: 200, body: mustJSON(t, changed), ctype: "application/json", cache: "no-store"},
		{name: "missing decision is uncertain", peer: decisionPeer, status: 404, body: []byte("{}"), ctype: "application/json", cache: "no-store", unavailable: true},
		{name: "revoked authority", peer: decisionPeer, status: 403, body: []byte("{}"), ctype: "application/json", cache: "no-store"},
		{name: "wrong content type", peer: decisionPeer, status: 200, body: mustJSON(t, valid), ctype: "text/plain", cache: "no-store"},
		{name: "cached response", peer: decisionPeer, status: 200, body: mustJSON(t, valid), ctype: "application/json", cache: "public, max-age=100"},
		{name: "oversize response", peer: decisionPeer, status: 200, body: []byte(strings.Repeat("x", 32769)), ctype: "application/json", cache: "no-store"},
		{name: "server error", peer: decisionPeer, status: 503, body: []byte("{}"), ctype: "application/json", cache: "no-store", unavailable: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverURL, httpClient := tlsDecisionFixture(t, tc.peer, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.ctype)
				w.Header().Set("Cache-Control", tc.cache)
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.body)
			}))
			reader, err := NewClient(serverURL, httpClient, decisionPeer)
			if err != nil {
				t.Fatal(err)
			}
			store := &acceptanceProbe{}
			_, err = reader.VerifyAndAccept(context.Background(), a, store)
			if err == nil || store.calls != 0 {
				t.Fatalf("invalid receipt reached CAS: %v %+v", err, store)
			}
			if tc.unavailable && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("transient absence/outage should stay unavailable: %v", err)
			}
		})
	}
}

func TestDecisionContinuationRejectsUntrustedEndpoints(t *testing.T) {
	tests := []string{"", "http://example.org", "https://example.org/path", "https://example.org/?x=1", "https://example.org/#x", "https://user@example.org"}
	for _, endpoint := range tests {
		if _, err := NewClient(endpoint, &http.Client{}, decisionPeer); err == nil {
			t.Fatalf("unsafe endpoint accepted: %q", endpoint)
		}
	}
	if _, err := NewClient("https://example.org", nil, decisionPeer); err == nil {
		t.Fatal("nil client accepted")
	}
	if _, err := NewClient("https://example.org", &http.Client{}, "spiffe://example.org/"); err == nil {
		t.Fatal("root SPIFFE identity accepted")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var _ io.Reader
