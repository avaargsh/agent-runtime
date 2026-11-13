package decision

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/audit"
	"github.com/avaargsh/agent-runtime/internal/securitycontext"
)

type boundaryAuditRecorder struct {
	mu       sync.Mutex
	events   []audit.Event
	err      error
	onAppend func()
}

func (r *boundaryAuditRecorder) Append(_ context.Context, event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, event)
	if r.onAppend != nil {
		r.onAppend()
	}
	return nil
}

func (r *boundaryAuditRecorder) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

func auditedClient(endpoint string, protector DataProtector) Client {
	return Client{Endpoint: endpoint, Protector: protector, Audit: &boundaryAuditRecorder{}}
}

func decisionAuditContext(t *testing.T) context.Context {
	t.Helper()
	identity, err := securitycontext.New(securitycontext.Claims{
		TenantID: "tenant-1", SubjectID: "subject-1", ActorID: "actor-1",
		AgentID: "agent-1", AgentReleaseID: "release-1", SessionID: "session-1",
		RunID: "run-1", RunAttemptID: "attempt-1", TurnID: "turn-1",
		PolicyRevision: "policy-7",
	})
	if err != nil {
		t.Fatal(err)
	}
	return securitycontext.WithContext(context.Background(), identity)
}

func TestDecisionClientAppendsCorrelatedAuditBeforeHTTPRequest(t *testing.T) {
	recorder := &boundaryAuditRecorder{}
	var requests atomic.Int32
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		if got := len(recorder.snapshot()); got != 1 {
			t.Errorf("HTTP request arrived before durable audit append: events=%d", got)
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"ok"}`)
	})
	client := Client{Endpoint: url, Protector: passThroughProtector{}, Audit: recorder}
	if _, err := client.Invoke(decisionAuditContext(t), sample(), sampleIdentity()); err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	events := recorder.snapshot()
	if requests.Load() != 1 || len(events) != 1 {
		t.Fatalf("HTTP requests/audit events = %d/%d, want 1/1", requests.Load(), len(events))
	}
	event := events[0]
	if event.Type != audit.EventModelRequestPrepared || event.Outcome != audit.OutcomePending ||
		event.Source != "agent-runtime/decision-client" ||
		event.Identity.TenantID() != "tenant-1" || event.Identity.SubjectID() != "subject-1" ||
		event.Identity.ActorID() != "actor-1" || event.Identity.PolicyRevision() != "policy-7" ||
		event.PayloadDigest == "" {
		t.Fatalf("incomplete model egress audit event: %+v", event)
	}
}

func TestDecisionClientFailsClosedWhenAuditIsMissingOrUnavailable(t *testing.T) {
	var requests atomic.Int32
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"protocol_version":"v0.1","invocation_id":"inv-1","kind":"final_response","text":"ok"}`)
	})
	recorderErr := errors.New("audit database unavailable")
	for _, tc := range []struct {
		name     string
		recorder *boundaryAuditRecorder
	}{
		{name: "missing recorder"},
		{name: "append failure", recorder: &boundaryAuditRecorder{err: recorderErr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := Client{Endpoint: url, Protector: passThroughProtector{}, Audit: tc.recorder}
			_, err := client.Invoke(decisionAuditContext(t), sample(), sampleIdentity())
			if err == nil {
				t.Fatal("Decision request succeeded without a durable audit")
			}
			if tc.recorder != nil && !errors.Is(err, recorderErr) {
				t.Fatalf("Invoke() error = %v, want audit failure", err)
			}
			if requests.Load() != 0 {
				t.Fatalf("external Decision requests = %d, want zero", requests.Load())
			}
		})
	}
}

func TestDecisionClientRejectsMissingSecurityContextBeforeAuditAndEgress(t *testing.T) {
	var requests atomic.Int32
	url := setup(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
	recorder := &boundaryAuditRecorder{}
	client := Client{Endpoint: url, Protector: passThroughProtector{}, Audit: recorder}
	if _, err := client.Invoke(context.Background(), sample(), sampleIdentity()); err == nil {
		t.Fatal("Decision accepted an unbound Go context")
	}
	if len(recorder.snapshot()) != 0 || requests.Load() != 0 {
		t.Fatalf("untrusted call wrote audit or reached egress: events=%d requests=%d",
			len(recorder.snapshot()), requests.Load())
	}
}

var _ audit.Recorder = (*boundaryAuditRecorder)(nil)
