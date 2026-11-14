package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/dataprotection"
)

const testPII = "alice@example.com"

type emailDetector struct {
	err error
}

func (d emailDetector) Detect(_ context.Context, payload []byte) ([]dataprotection.Span, error) {
	if d.err != nil {
		return nil, d.err
	}
	start := bytes.Index(payload, []byte(testPII))
	if start < 0 {
		return nil, nil
	}
	return []dataprotection.Span{{
		Start: start,
		End:   start + len(testPII),
		Type:  dataprotection.DataTypeEmail,
	}}, nil
}

type memoryTokenRecord struct {
	dataType  dataprotection.DataType
	plaintext []byte
}

type memoryTokenVault struct {
	mu      sync.Mutex
	records map[string]memoryTokenRecord
	putErr  error
	getErr  error
}

func (v *memoryTokenVault) Put(_ context.Context, scope dataprotection.Scope, tokenID string, dataType dataprotection.DataType, plaintext []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.putErr != nil {
		return v.putErr
	}
	if v.records == nil {
		v.records = make(map[string]memoryTokenRecord)
	}
	key := fmt.Sprintf("%s\x00%s\x00%s", scope.TenantID, scope.RunID, tokenID)
	if _, exists := v.records[key]; exists {
		return errors.New("duplicate test token")
	}
	v.records[key] = memoryTokenRecord{dataType: dataType, plaintext: bytes.Clone(plaintext)}
	return nil
}

func (v *memoryTokenVault) Get(_ context.Context, scope dataprotection.Scope, tokenID string) (dataprotection.DataType, []byte, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.getErr != nil {
		return "", nil, false, v.getErr
	}
	key := fmt.Sprintf("%s\x00%s\x00%s", scope.TenantID, scope.RunID, tokenID)
	record, ok := v.records[key]
	return record.dataType, bytes.Clone(record.plaintext), ok, nil
}

type testRehydrationAuthorizer struct {
	err   error
	calls int
}

func (a *testRehydrationAuthorizer) Authorize(_ context.Context, _ dataprotection.Scope, _ dataprotection.DataType, audience, purpose string) error {
	a.calls++
	if audience != DecisionUserAudience || purpose != DecisionUserVisibleResponsePurpose {
		return fmt.Errorf("unexpected restoration policy context: audience=%q purpose=%q", audience, purpose)
	}
	return a.err
}

func newTestDataProtectionEngine(t *testing.T, detector dataprotection.Detector, vault dataprotection.Vault, authorizer dataprotection.RehydrationAuthorizer) *dataprotection.Engine {
	t.Helper()
	engine, err := dataprotection.NewEngine(detector, vault, authorizer)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func TestInvokeProtectsModelEgressAndRestoresAuthorizedUserResponse(t *testing.T) {
	authorizer := &testRehydrationAuthorizer{}
	engine := newTestDataProtectionEngine(t, emailDetector{}, &memoryTokenVault{}, authorizer)
	turn := sample()
	turn.UserInput = "Please contact " + testPII
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		var outbound Turn
		if err := json.NewDecoder(r.Body).Decode(&outbound); err != nil {
			t.Errorf("decode protected request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if strings.Contains(outbound.UserInput, testPII) {
			t.Errorf("raw PII crossed the model boundary: %q", outbound.UserInput)
		}
		if !strings.Contains(outbound.UserInput, "[[AGENT_TOKEN:") {
			t.Errorf("model request did not contain an opaque PII token: %q", outbound.UserInput)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{
			ProtocolVersion: "v0.1",
			InvocationID:    outbound.InvocationID,
			Kind:            "final_response",
			Text:            outbound.UserInput,
		})
	})

	client := auditedClient(url, engine)
	got, err := client.Invoke(decisionAuditContext(t), turn, sampleIdentity())
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if got.Text != turn.UserInput {
		t.Fatalf("restored response = %q, want original user-facing content %q", got.Text, turn.UserInput)
	}
	if authorizer.calls != 1 {
		t.Fatalf("rehydration authorization calls = %d, want exactly 1", authorizer.calls)
	}
}

func TestInvokeFailsClosedWhenProtectionFailsBeforeEgress(t *testing.T) {
	cases := []struct {
		name     string
		detector dataprotection.Detector
		vault    dataprotection.Vault
	}{
		{
			name:     "scanner failure",
			detector: emailDetector{err: errors.New("scanner unavailable")},
			vault:    &memoryTokenVault{},
		},
		{
			name:     "vault write failure",
			detector: emailDetector{},
			vault:    &memoryTokenVault{putErr: errors.New("vault unavailable")},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			url := setup(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
			})
			engine := newTestDataProtectionEngine(t, test.detector, test.vault, &testRehydrationAuthorizer{})
			turn := sample()
			turn.UserInput = "email " + testPII
			client := Client{Endpoint: url, Protector: engine}
			if _, err := client.Invoke(decisionAuditContext(t), turn, sampleIdentity()); err == nil {
				t.Fatal("Invoke() succeeded despite a data-protection dependency failure")
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("remote Decision requests = %d, want 0 after protection failure", got)
			}
		})
	}
}

func TestInvokeReturnsNoResultWhenResponseRehydrationIsDenied(t *testing.T) {
	authorizer := &testRehydrationAuthorizer{err: errors.New("user-visible restoration denied")}
	engine := newTestDataProtectionEngine(t, emailDetector{}, &memoryTokenVault{}, authorizer)
	turn := sample()
	turn.UserInput = testPII
	url := setup(t, func(w http.ResponseWriter, r *http.Request) {
		var outbound Turn
		if err := json.NewDecoder(r.Body).Decode(&outbound); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{
			ProtocolVersion: "v0.1",
			InvocationID:    outbound.InvocationID,
			Kind:            "final_response",
			Text:            outbound.UserInput,
		})
	})

	got, err := auditedClient(url, engine).Invoke(decisionAuditContext(t), turn, sampleIdentity())
	if err == nil {
		t.Fatal("Invoke() succeeded despite denied response rehydration")
	}
	if got != (Result{}) {
		t.Fatalf("Invoke() returned a partial or tokenized response after authorization failure: %+v", got)
	}
	if authorizer.calls != 1 {
		t.Fatalf("rehydration authorization calls = %d, want exactly 1", authorizer.calls)
	}
}
