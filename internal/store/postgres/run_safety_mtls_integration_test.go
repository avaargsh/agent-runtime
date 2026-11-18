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
)

// A real TLS connection, PostgreSQL authority and independently scoped client
// certificate. No fake RunSafetyAuthority participates in this test.
func TestGuardSafetyAuthorityRealMTLSAndPostgreSQL(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	accepted, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	foreign := testIntent()
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

	const peer = "spiffe://example.org/guard/tenant-1"
	handler, err := acphttp.NewRunSafetyHandler(store, peer, accepted.TenantID)
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
	path := func(id string) string { return "/internal/v1/runs/" + id + "/safety" }
	assertStatus := func(c *http.Client, p string, want int) string {
		t.Helper()
		code, body, err := call(c, p)
		if err != nil || code != want {
			t.Fatalf("safety read %s: %d, want %d: %s %v", p, code, want, body, err)
		}
		return body
	}
	assertStatus(valid, path(accepted.RunID), http.StatusForbidden)
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='RUNNING',updated_at=clock_timestamp()"); err != nil {
		t.Fatal(err)
	}
	body := assertStatus(valid, path(accepted.RunID), http.StatusOK)
	var result map[string]any
	if json.Unmarshal([]byte(body), &result) != nil ||
		result["schema_version"] != "runtime.run-safety.v1" || result["tenant_id"] != accepted.TenantID ||
		result["run_id"] != accepted.RunID || result["status"] != "RUNNING" ||
		result["breaker_state"] != "CLOSED" || result["breaker_epoch"] != float64(1) || len(result) != 10 ||
		strings.Contains(body, "permit") || strings.Contains(body, "message") {
		t.Fatalf("invalid safety snapshot: %s", body)
	}
	notFound := assertStatus(valid, path("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), http.StatusForbidden)
	if assertStatus(valid, path(other.RunID), http.StatusForbidden) != notFound ||
		assertStatus(valid, path(legacy.ID), http.StatusForbidden) != notFound {
		t.Fatal("cross-tenant/legacy existence leakage")
	}
	assertStatus(valid, path(accepted.RunID)+"?tenant_id="+foreign.TenantID, http.StatusBadRequest)
	assertStatus(makeClient(cert("spiffe://example.org/other")), path(accepted.RunID), http.StatusUnauthorized)
	assertStatus(makeClient(cert(peer, "spiffe://example.org/other")), path(accepted.RunID), http.StatusUnauthorized)
	if _, _, err := call(makeClient(), path(accepted.RunID)); err == nil {
		t.Fatal("network server accepted no client certificate")
	}
	initial, err := store.GetRunBreaker(ctx, accepted.TenantID, accepted.RunID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := initial.Trip("UNAUTHORIZED_EGRESS", "guard-safety-test", initial.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapBreaker(ctx, initial.Version, opened); err != nil {
		t.Fatal(err)
	}
	assertStatus(valid, path(accepted.RunID), http.StatusForbidden)
	if _, err := pool.Exec(ctx, "UPDATE runs SET status='CANCELLED',updated_at=clock_timestamp() WHERE run_id=$1::uuid", accepted.RunID); err != nil {
		t.Fatal(err)
	}
	assertStatus(valid, path(accepted.RunID), http.StatusForbidden)
	pool.Close()
	assertStatus(valid, path(accepted.RunID), http.StatusServiceUnavailable)
}
