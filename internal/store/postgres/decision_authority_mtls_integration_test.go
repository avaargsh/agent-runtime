package postgres_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/acphttp"
	"github.com/avaargsh/agent-runtime/internal/run"
)

// A real TLS connection, PostgreSQL authority and independently scoped client
// certificate. No fake RunSafetyAuthority participates in this test.
func TestDecisionAuthorityRealMTLSAndPostgreSQL(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command := testIntent()
	command.Input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"errors"}`)
	accepted, err := store.AcceptIntentWithPrincipal(ctx, command, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	foreign := command
	foreign.TenantID = "foreign-tenant"
	foreign.RunIntentID = "22222222-2222-4222-8222-222222222222"
	other, err := store.AcceptIntentWithPrincipal(ctx, foreign, trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	legacy, _, err := store.CreateOrGet(ctx, candidate("99999999-9999-4999-8999-999999999999"))
	if err != nil {
		t.Fatal(err)
	}

	const peer = "spiffe://example.org/decision/tenant-1"
	handler, err := acphttp.NewDecisionAuthorityHandler(store, peer, accepted.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
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
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	serial := int64(2)
	cert := func(ids ...string) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var uris []*url.URL
		for _, id := range ids {
			u, err := url.Parse(id)
			if err != nil {
				t.Fatal(err)
			}
			uris = append(uris, u)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			URIs: uris,
		}
		serial++
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(server.Certificate())
	makeClient := func(certs ...tls.Certificate) *http.Client {
		h := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: serverRoots, Certificates: certs},
		}}
		t.Cleanup(h.CloseIdleConnections)
		return h
	}
	valid := makeClient(cert(peer))
	call := func(c *http.Client, path string) (int, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("X-Tenant-ID", foreign.TenantID)
		req.Header.Set("X-Forwarded-Client-Cert", peer)
		res, err := c.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("safety read allowed cached authority")
		}
		return res.StatusCode, string(b), err
	}
	path := func(id, invocation string) string { return acphttp.DecisionAuthorityPath + id + "?invocation_id=" + invocation }
	assertStatus := func(c *http.Client, p string, want int) string {
		t.Helper()
		code, body, err := call(c, p)
		if err != nil || code != want {
			t.Fatalf("Decision authority read: %d want %d: %s %v", code, want, body, err)
		}
		return body
	}
	const execution = "11111111-2222-4333-8444-555555555555"
	assertStatus(valid, path(accepted.RunID, execution), http.StatusForbidden)
	ref := run.AcceptedDecisionRef{TenantID: accepted.TenantID, RunID: accepted.RunID, RunIntentID: accepted.RunIntentID,
		WorkflowID: accepted.WorkflowID, RequestDigest: accepted.RequestDigest}
	cp, err := store.PrepareAcceptedDecision(ctx, ref, execution)
	if err != nil {
		t.Fatal(err)
	}
	target := path(accepted.RunID, cp.TurnID)
	body := assertStatus(valid, target, http.StatusOK)
	var result run.DecisionAuthority
	if json.Unmarshal([]byte(body), &result) != nil || result.Validate() != nil ||
		result.RunID != accepted.RunID || result.InvocationID != cp.TurnID || result.InputDigest != cp.InputDigest ||
		result.AttemptID != cp.AttemptID || result.ExecutionID != execution ||
		strings.Contains(body, "permit") || strings.Contains(body, "payments") {
		t.Fatalf("invalid Decision authority response: %s", body)
	}
	notFound := assertStatus(valid, path(accepted.RunID, execution), http.StatusForbidden)
	if assertStatus(valid, path(other.RunID, cp.TurnID), http.StatusForbidden) != notFound ||
		assertStatus(valid, path(legacy.ID, cp.TurnID), http.StatusForbidden) != notFound {
		t.Fatal("foreign/legacy authority existence leaked")
	}
	assertStatus(valid, target+"&tenant_id="+foreign.TenantID, http.StatusBadRequest)
	assertStatus(valid, target+"&invocation_id="+cp.TurnID, http.StatusBadRequest)
	assertStatus(makeClient(cert("spiffe://example.org/other")), target, http.StatusUnauthorized)
	assertStatus(makeClient(cert(peer, "spiffe://example.org/other")), target, http.StatusUnauthorized)
	if _, _, err := call(makeClient(), target); err == nil {
		t.Fatal("network server accepted no client certificate")
	}
	if err := store.CancelPreparedDecision(ctx, ref, execution); err != nil {
		t.Fatal(err)
	}
	assertStatus(valid, target, http.StatusForbidden)
	pool.Close()
	assertStatus(valid, target, http.StatusServiceUnavailable)
	t.Logf("actual Runtime Decision authority for Run %s invocation %s verified and then cancelled", ref.RunID, cp.TurnID)
}
