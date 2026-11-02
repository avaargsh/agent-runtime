package decision

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sample() Turn {
	return Turn{ProtocolVersion: "v0.1", InvocationID: "inv-1", TenantID: "tenant-1", AgentID: "agent-1", RunID: "run-1", TurnID: "turn-1", UserInput: "hello"}
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
		fmt.Fprint(w, `{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final","text":"ok"}`)
	})
	out, err := (Client{Endpoint: url}).Invoke(context.Background(), sample())
	if err != nil || out.Text != "ok" {
		t.Fatalf("result=%+v err=%v", out, err)
	}
}

func TestInvalidResponses(t *testing.T) {
	cases := []string{
		`{"protocol_version":"v0.1","invocation_id":"wrong","kind":"final","text":"ok"}`,
		`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final","text":"ok","text":"dup"}`,
		`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final","text":"ok","extra":"bad"}`,
		`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final"}`,
		`{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final","text":"ok"} garbage`,
		strings.Repeat(" ", 8200),
	}
	for i, body := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			url := setup(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, body)
			})
			if _, err := (Client{Endpoint: url}).Invoke(context.Background(), sample()); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestRejectRedirect(t *testing.T) {
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.org/", http.StatusTemporaryRedirect)
	})
	if _, err := (Client{Endpoint: url}).Invoke(context.Background(), sample()); err == nil {
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
