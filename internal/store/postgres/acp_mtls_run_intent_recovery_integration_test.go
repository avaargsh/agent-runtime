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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/acphttp"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

const recoveryACPWorkloadID = "spiffe://agent.example/ns/control/sa/agent-control-panel"

// TestAuthenticatedACPRecoversSameRunAfterRuntimeHandlerAndPoolRestart joins
// the real TLS 1.3/mTLS network boundary to PostgreSQL 17 persistence. The
// first Runtime handler accepts a principal-bound Run; after that handler and
// its connection pool are replaced, the authenticated ACP workload inspects
// and replays the same RunIntent and must recover the exact Run/Workflow IDs.
//
// This proves a Runtime process/client-pool restart against a persistent DB.
// It does not simulate a PostgreSQL server restart or a deployed ACP service.
func TestAuthenticatedACPRecoversSameRunAfterRuntimeHandlerAndPoolRestart(t *testing.T) {
	pool, _ := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	caCert, caPool, serverCert, clientCert := recoveryMTLSCertificates(t)
	newServer := func(handler http.Handler) *httptest.Server {
		t.Helper()
		server := httptest.NewUnstartedServer(handler)
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.TLS = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}
	newClient := func() *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	send := func(client *http.Client, server *httptest.Server, path string, payload []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, strings.NewReader(string(payload)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		// This header is deliberately present but is not used as identity.
		req.Header.Set("X-Forwarded-Client-Cert", "spiffe://attacker.example/forged")
		response, err := client.Do(req)
		if err != nil {
			t.Fatalf("authenticated Runtime request: %v", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}

	command := testIntent()
	principal := trustedSnapshot()
	principal.IssuerSPIFFEID = recoveryACPWorkloadID
	envelope, err := json.Marshal(struct {
		TenantID       string          `json:"tenant_id"`
		RunIntentID    string          `json:"run_intent_id"`
		RequestDigest  string          `json:"request_digest"`
		AgentID        string          `json:"agent_id"`
		AgentReleaseID string          `json:"agent_release_id"`
		SessionID      string          `json:"session_id"`
		Input          json.RawMessage `json:"input"`
		Principal      struct {
			Version        string `json:"version"`
			ProjectID      string `json:"project_id"`
			SubjectID      string `json:"subject_id"`
			ActorID        string `json:"actor_id"`
			PolicyRevision string `json:"policy_revision"`
			ConfigDigest   string `json:"config_digest"`
		} `json:"principal_context"`
	}{
		TenantID: command.TenantID, RunIntentID: command.RunIntentID,
		RequestDigest: command.RequestDigest, AgentID: command.AgentID,
		AgentReleaseID: command.AgentReleaseID, SessionID: command.SessionID,
		Input: json.RawMessage(command.Input),
		Principal: struct {
			Version        string `json:"version"`
			ProjectID      string `json:"project_id"`
			SubjectID      string `json:"subject_id"`
			ActorID        string `json:"actor_id"`
			PolicyRevision string `json:"policy_revision"`
			ConfigDigest   string `json:"config_digest"`
		}{
			Version: principal.Version, ProjectID: principal.ProjectID,
			SubjectID: principal.SubjectID, ActorID: principal.ActorID,
			PolicyRevision: principal.PolicyRevision, ConfigDigest: principal.ConfigDigest,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	firstHandler, err := acphttp.NewHandler(postgres.New(pool), recoveryACPWorkloadID)
	if err != nil {
		t.Fatal(err)
	}
	firstServer := newServer(firstHandler)
	firstClient := newClient()
	status, response := send(firstClient, firstServer, "/internal/v2/run-intents:accept", envelope)
	if status != http.StatusCreated {
		t.Fatalf("initial authenticated acceptance: status=%d body=%s", status, response)
	}
	var accepted struct {
		Status      string `json:"status"`
		TenantID    string `json:"tenant_id"`
		RunIntentID string `json:"run_intent_id"`
		RunID       string `json:"run_id"`
		WorkflowID  string `json:"workflow_id"`
		Created     bool   `json:"created"`
	}
	if err := json.Unmarshal(response, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Status != "FOUND" || !accepted.Created || accepted.RunID == "" ||
		accepted.WorkflowID != run.ACPWorkflowPrefix+accepted.RunID ||
		accepted.TenantID != command.TenantID || accepted.RunIntentID != command.RunIntentID {
		t.Fatalf("invalid initial acceptance receipt: %+v", accepted)
	}
	firstServer.Close()
	firstClient.CloseIdleConnections()

	// A fresh pool and handler model a Runtime process restart. The test
	// database/schema remains durable and is reached through a new pool.
	restartedPool, err := pgxpool.NewWithConfig(ctx, pool.Config())
	if err != nil {
		t.Fatalf("recreate Runtime PostgreSQL pool: %v", err)
	}
	t.Cleanup(restartedPool.Close)
	if err := restartedPool.Ping(ctx); err != nil {
		t.Fatalf("new Runtime pool cannot read durable PostgreSQL state: %v", err)
	}
	restartedHandler, err := acphttp.NewHandler(postgres.New(restartedPool), recoveryACPWorkloadID)
	if err != nil {
		t.Fatal(err)
	}
	restartedServer := newServer(restartedHandler)
	restartedClient := newClient()

	status, response = send(restartedClient, restartedServer, "/internal/v2/run-intents:inspect", envelope)
	if status != http.StatusOK {
		t.Fatalf("authenticated post-restart inspection: status=%d body=%s", status, response)
	}
	var inspected struct {
		Status     string `json:"status"`
		RunID      string `json:"run_id"`
		WorkflowID string `json:"workflow_id"`
		Created    bool   `json:"created"`
	}
	if err := json.Unmarshal(response, &inspected); err != nil {
		t.Fatal(err)
	}
	if inspected.Status != "FOUND" || inspected.Created ||
		inspected.RunID != accepted.RunID || inspected.WorkflowID != accepted.WorkflowID {
		t.Fatalf("post-restart inspection changed canonical identity: accepted=%+v inspected=%+v", accepted, inspected)
	}

	status, response = send(restartedClient, restartedServer, "/internal/v2/run-intents:accept", envelope)
	if status != http.StatusOK {
		t.Fatalf("authenticated post-restart replay: status=%d body=%s", status, response)
	}
	var replayed struct {
		Status     string `json:"status"`
		RunID      string `json:"run_id"`
		WorkflowID string `json:"workflow_id"`
		Created    bool   `json:"created"`
	}
	if err := json.Unmarshal(response, &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.Status != "FOUND" || replayed.Created ||
		replayed.RunID != accepted.RunID || replayed.WorkflowID != accepted.WorkflowID {
		t.Fatalf("post-restart replay minted or changed identity: %+v", replayed)
	}

	var runs, outbox, principals int
	if err := restartedPool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM runs WHERE run_intent_id=$1::uuid),
			(SELECT count(*) FROM runtime_outbox WHERE aggregate_id=$2::uuid AND event_type='RUN_START_REQUESTED'),
			(SELECT count(*) FROM runtime_run_principal_snapshots WHERE run_id=$2::uuid)
	`, command.RunIntentID, accepted.RunID).Scan(&runs, &outbox, &principals); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || outbox != 1 || principals != 1 {
		t.Fatalf("restart/replay duplicated or partially persisted authority: runs=%d outbox=%d principals=%d",
			runs, outbox, principals)
	}

	_ = caCert // keep the parsed root explicit in this test's trust setup.
}

func recoveryMTLSCertificates(t *testing.T) (*x509.Certificate, *x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
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

	issue := func(serial int64, usage x509.ExtKeyUsage, dns []string, ips []net.IP, identities []string) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		uris := make([]*url.URL, 0, len(identities))
		for _, identity := range identities {
			parsed, err := url.Parse(identity)
			if err != nil {
				t.Fatal(err)
			}
			uris = append(uris, parsed)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			DNSNames: dns, IPAddresses: ips, URIs: uris,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}

	serverCert := issue(2, x509.ExtKeyUsageServerAuth, nil,
		[]net.IP{net.ParseIP("127.0.0.1")}, nil)
	clientCert := issue(3, x509.ExtKeyUsageClientAuth, nil, nil,
		[]string{recoveryACPWorkloadID})
	return caCert, caPool, serverCert, clientCert
}
