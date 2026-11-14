package acphttp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestRealNetworkMTLS verifies the transport boundary using an actual TLS 1.3
// listener and certificates chained to a test CA, not a fabricated r.TLS.
// The Store is still a fake; this does not claim production ACP/PG deployment.
func TestRealNetworkMTLS(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serial := int64(2)
	issueClient := func(identities ...string) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		uris := make([]*url.URL, 0, len(identities))
		for _, id := range identities {
			u, err := url.Parse(id)
			if err != nil {
				t.Fatal(err)
			}
			uris = append(uris, u)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			URIs:        uris,
		}
		serial++
		der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}

	app := newHandler(t)
	srv := httptest.NewUnstartedServer(app.h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
	}
	srv.StartTLS()
	defer srv.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(srv.Certificate())
	makeClient := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:   tls.VersionTLS13,
					RootCAs:      serverRoots,
					Certificates: certs,
				},
			},
		}
	}
	sendNetwork := func(c *http.Client, method, path, payload string) (int, string, error) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(payload))
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-Client-Cert", acpID)
		resp, err := c.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out), err
	}

	valid := makeClient(issueClient(acpID))
	status, response, err := sendNetwork(valid, http.MethodPost, "/internal/v1/run-intents:accept", body())
	if err != nil || status != http.StatusCreated || !strings.Contains(response, "\"FOUND\"") {
		t.Fatalf("trusted network ACP accept: status=%d response=%q err=%v", status, response, err)
	}
	status, _, err = sendNetwork(valid, http.MethodPost, "/internal/v1/run-intents:accept", body())
	if err != nil || status != http.StatusOK {
		t.Fatalf("trusted network replay: status=%d err=%v", status, err)
	}
	if _, _, err := sendNetwork(makeClient(), http.MethodPost, "/internal/v1/run-intents:accept", body()); err == nil {
		t.Fatal("TLS listener accepted missing client certificate")
	}
	for _, identities := range [][]string{
		{"spiffe://agent.example/ns/control/sa/untrusted"},
		{acpID, "spiffe://agent.example/ns/control/sa/other"},
	} {
		untrusted := makeClient(issueClient(identities...))
		status, _, err := sendNetwork(untrusted, http.MethodPost, "/internal/v1/run-intents:accept", body())
		if err != nil || status != http.StatusUnauthorized {
			t.Fatalf("wrong or ambiguous identity accepted: %v status=%d err=%v", identities, status, err)
		}
	}
	if len(app.store.receipts) != 1 {
		t.Fatalf("untrusted network requests mutated store, records=%d", len(app.store.receipts))
	}
}
