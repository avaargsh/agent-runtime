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

func TestGuardExecutionAuthorityRealMTLSAndPostgreSQL(t *testing.T) {
	pool, store, receipt := runningPrincipalRun(t)
	ctx := context.Background()
	first, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID, receipt.WorkflowID, guardAuthorityExecutionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	const peer = "spiffe://example.org/ns/guard/sa/issuer"
	handler, err := acphttp.NewGuardExecutionAuthorityHandler(store, peer, receipt.TenantID)
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
	clientCert := func(ids ...string) tls.Certificate {
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
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			URIs:        uris,
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
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: serverRoots, Certificates: certs},
		}}
		t.Cleanup(client.CloseIdleConnections)
		return client
	}
	path := func(runID, turnID string) string {
		return acphttp.GuardExecutionAuthorityPathPrefix + runID + "/" + turnID
	}
	call := func(client *http.Client, method, p string) (int, string, http.Header, error) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, server.URL+p, nil)
		if err != nil {
			return 0, "", nil, err
		}
		req.Header.Set("X-Tenant-ID", "attacker-controlled-tenant")
		req.Header.Set("X-Forwarded-Client-Cert", peer)
		res, err := client.Do(req)
		if err != nil {
			return 0, "", nil, err
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		return res.StatusCode, string(body), res.Header, err
	}
	valid := makeClient(clientCert(peer))
	status, body, headers, err := call(valid, http.MethodGet, path(receipt.RunID, first.TurnID))
	if err != nil || status != http.StatusOK || headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("valid Guard execution authority: status=%d headers=%v body=%s err=%v", status, headers, body, err)
	}
	var authority run.GuardExecutionAuthority
	if json.Unmarshal([]byte(body), &authority) != nil || authority.Validate() != nil ||
		authority.TenantID != receipt.TenantID || authority.RunID != receipt.RunID ||
		authority.RunAttemptID != first.RunAttemptID || authority.TurnID != first.TurnID ||
		strings.Contains(strings.ToLower(body), "permit") || strings.Contains(strings.ToLower(body), "approval") {
		t.Fatalf("invalid or over-broad Guard authority response: %s", body)
	}
	second, err := store.GetOrCreateTemporalTurn(ctx, receipt.TenantID, receipt.RunID, receipt.WorkflowID, guardAuthorityExecutionID, 2)
	if err != nil {
		t.Fatal(err)
	}
	status, _, _, err = call(valid, http.MethodGet, path(receipt.RunID, first.TurnID))
	if err != nil || status != http.StatusForbidden {
		t.Fatalf("superseded Turn must be denied: status=%d err=%v", status, err)
	}
	status, body, _, err = call(valid, http.MethodGet, path(receipt.RunID, second.TurnID))
	if err != nil || status != http.StatusOK || !strings.Contains(body, second.TurnID) {
		t.Fatalf("current Turn must be returned: status=%d body=%s err=%v", status, body, err)
	}
	status, _, _, err = call(valid, http.MethodGet, path(receipt.RunID, second.TurnID)+"?tenant_id=other")
	if err != nil || status != http.StatusBadRequest {
		t.Fatalf("query parameters must be rejected: status=%d err=%v", status, err)
	}
	status, _, _, err = call(valid, http.MethodPost, path(receipt.RunID, second.TurnID))
	if err != nil || status != http.StatusMethodNotAllowed {
		t.Fatalf("non-GET method must be rejected: status=%d err=%v", status, err)
	}
	status, _, _, err = call(makeClient(clientCert("spiffe://example.org/ns/other/sa/issuer")), http.MethodGet, path(receipt.RunID, second.TurnID))
	if err != nil || status != http.StatusUnauthorized {
		t.Fatalf("wrong Guard peer must be rejected: status=%d err=%v", status, err)
	}
	if _, _, _, err := call(makeClient(), http.MethodGet, path(receipt.RunID, second.TurnID)); err == nil {
		t.Fatal("mTLS listener accepted a client without a certificate")
	}
	pool.Close()
	status, body, _, err = call(valid, http.MethodGet, path(receipt.RunID, second.TurnID))
	if err != nil || status != http.StatusServiceUnavailable || !strings.Contains(body, "GUARD_EXECUTION_AUTHORITY_UNAVAILABLE") {
		t.Fatalf("database outage must remain unavailable: status=%d body=%s err=%v", status, body, err)
	}
}
