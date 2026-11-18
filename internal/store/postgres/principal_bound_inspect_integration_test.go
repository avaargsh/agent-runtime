package postgres_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/acphttp"
	"github.com/avaargsh/agent-runtime/internal/run"
)

func TestPrincipalBoundInspectionRejectsConflictingAcceptanceWithoutWrites(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	command, principal := testIntent(), trustedSnapshot()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, command, principal)
	if err != nil {
		t.Fatal(err)
	}
	h, err := acphttp.NewHandler(store, principal.IssuerSPIFFEID)
	if err != nil {
		t.Fatal(err)
	}
	// This test exercises the actual HTTP handler and PostgreSQL store.
	// A separate cross-service test must prove the real TLS handshake.
	call := func(c run.IntentStartRequest, p run.PrincipalSnapshot) *httptest.ResponseRecorder {
		t.Helper()
		payload, err := json.Marshal(map[string]any{
			"tenant_id": c.TenantID, "run_intent_id": c.RunIntentID, "request_digest": c.RequestDigest,
			"agent_id": c.AgentID, "agent_release_id": c.AgentReleaseID, "session_id": c.SessionID,
			"input": json.RawMessage(c.Input),
			"principal_context": map[string]string{
				"version": p.Version, "project_id": p.ProjectID, "subject_id": p.SubjectID,
				"actor_id": p.ActorID, "policy_revision": p.PolicyRevision, "config_digest": p.ConfigDigest,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/internal/v2/run-intents:inspect", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		uri, _ := url.Parse(principal.IssuerSPIFFEID)
		cert := &x509.Certificate{URIs: []*url.URL{uri}}
		req.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
			PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	w := call(command, principal)
	var found struct {
		Status  string `json:"status"`
		RunID   string `json:"run_id"`
		Created bool   `json:"created"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &found) != nil ||
		found.Status != "FOUND" || found.RunID != receipt.RunID || found.Created {
		t.Fatalf("matching inspection must return the original Run: %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		name string
		edit func(*run.IntentStartRequest, *run.PrincipalSnapshot)
	}{
		{"subject", func(_ *run.IntentStartRequest, p *run.PrincipalSnapshot) { p.SubjectID = "other-subject" }},
		{"actor", func(_ *run.IntentStartRequest, p *run.PrincipalSnapshot) { p.ActorID = "other-actor" }},
		{"policy", func(_ *run.IntentStartRequest, p *run.PrincipalSnapshot) { p.PolicyRevision = "other-policy" }},
		{"project", func(_ *run.IntentStartRequest, p *run.PrincipalSnapshot) { p.ProjectID = "other-project" }},
		{"release", func(c *run.IntentStartRequest, _ *run.PrincipalSnapshot) { c.AgentReleaseID = "other-release" }},
		{"agent", func(c *run.IntentStartRequest, _ *run.PrincipalSnapshot) { c.AgentID = "other-agent" }},
		{"session", func(c *run.IntentStartRequest, _ *run.PrincipalSnapshot) { c.SessionID = "other-session" }},
		{"input", func(c *run.IntentStartRequest, _ *run.PrincipalSnapshot) { c.Input = []byte(`{"message":"wrong"}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, p := command, principal
			tc.edit(&c, &p)
			if got := call(c, p); got.Code != http.StatusConflict {
				t.Fatalf("conflicting binding falsely recovered: %d %s", got.Code, got.Body.String())
			}
		})
	}
	foreign := command
	foreign.TenantID = "other-tenant"
	w = call(foreign, principal)
	if w.Code != http.StatusOK || w.Body.String() != "{\"status\":\"ABSENT_UNCERTAIN\"}\n" {
		t.Fatalf("foreign tenant leaked existence: %d %s", w.Code, w.Body.String())
	}
	var runs, events int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM runs), (SELECT count(*) FROM runtime_outbox)").Scan(&runs, &events); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || events != 1 {
		t.Fatalf("inspection performed a write: %d/%d", runs, events)
	}
}
