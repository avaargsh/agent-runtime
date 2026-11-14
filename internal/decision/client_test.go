package decision

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/dataprotection"
	"github.com/avaargsh/agent-runtime/internal/run"
)

func sample() Turn {
	return Turn{ProtocolVersion: "v0.1", InvocationID: "inv-1", TenantID: "tenant-1", AgentID: "agent-1", RunID: "run-1", TurnID: "turn-1", UserInput: "hello"}
}

func sampleIdentity() run.Identity {
	return run.Identity{
		RunID:          "run-1",
		TenantID:       "tenant-1",
		AgentID:        "agent-1",
		AgentReleaseID: "release-1",
		SessionID:      "session-1",
	}
}

type passThroughProtector struct{}

func (passThroughProtector) ProtectOutbound(_ context.Context, _ dataprotection.Scope, _ string, payload []byte) ([]byte, error) {
	return append([]byte(nil), payload...), nil
}

func (passThroughProtector) RestoreInbound(_ context.Context, _ dataprotection.Scope, _, _ string, payload []byte) ([]byte, error) {
	return append([]byte(nil), payload...), nil
}

func setup(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return s.URL + "/api/v1/decision-turns"
}

func TestInvokeFinal(t *testing.T) {
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/decision-turns" {
			t.Error("unexpected request")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"ok"}`)
	})
	out, err := auditedClient(url, passThroughProtector{}).Invoke(decisionAuditContext(t), sample(), sampleIdentity())
	if err != nil || out.Text != "ok" {
		t.Fatalf("result=%+v err=%v", out, err)
	}
}

func TestInvalidResponses(t *testing.T) {
	cases := []string{
		`{"protocol_version":"v0.1","invocation_id":"wrong","kind":"final_response","text":"ok"}`,
		`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"ok","text":"dup"}`,
		`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"ok","extra":"bad"}`,
		`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response"}`,
		`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"ok"} garbage`,
		strings.Repeat(" ", 8200),
	}
	for i, body := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			url := setup(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, body)
			})
			if _, err := auditedClient(url, passThroughProtector{}).Invoke(decisionAuditContext(t), sample(), sampleIdentity()); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestRejectRedirect(t *testing.T) {
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.org/", http.StatusTemporaryRedirect)
	})
	if _, err := auditedClient(url, passThroughProtector{}).Invoke(decisionAuditContext(t), sample(), sampleIdentity()); err == nil {
		t.Fatal("redirect followed")
	}
}

func TestInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://example.org/api/v1/decision-turns", "file:///tmp/x", "http://user:secret@localhost:8081/", "https://example.org/x?token=secret"} {
		if err := validateEndpoint(endpoint); err == nil {
			t.Fatalf("accepted: %s", endpoint)
		}
	}
}

func TestInvokeRequiresDataProtectionBeforeExternalEgress(t *testing.T) {
	var requests int
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"ok"}`)
	})
	if _, err := (Client{Endpoint: url}).Invoke(context.Background(), sample(), sampleIdentity()); !errors.Is(err, ErrDataProtectionUnavailable) {
		t.Fatalf("Invoke() error = %v, want ErrDataProtectionUnavailable", err)
	}
	if requests != 0 {
		t.Fatalf("remote Decision requests = %d, want 0 when data protection is missing", requests)
	}
}

func TestInvokeRejectsMismatchedPersistedIdentityBeforeExternalEgress(t *testing.T) {
	var requests int
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
	})
	identity := sampleIdentity()
	identity.TenantID = "another-tenant"
	client := Client{Endpoint: url, Protector: passThroughProtector{}}
	if _, err := client.Invoke(context.Background(), sample(), identity); !errors.Is(err, ErrRunIdentityMismatch) {
		t.Fatalf("Invoke() error = %v, want ErrRunIdentityMismatch", err)
	}
	if requests != 0 {
		t.Fatalf("remote Decision requests = %d, want 0 for mismatched identity", requests)
	}
}

func TestInvalidInput(t *testing.T) {
	turn := sample()
	turn.ProtocolVersion = "v2"
	if err := turn.Validate(); err == nil {
		t.Fatal("expected version rejection")
	}
	turn = sample()
	turn.UserInput = strings.Repeat("é", 2500)
	if err := turn.Validate(); err == nil {
		t.Fatal("expected utf8 byte-bound rejection")
	}
}
