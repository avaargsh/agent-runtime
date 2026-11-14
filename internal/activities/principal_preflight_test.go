package activities

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/run"
)

type principalFixtureReader struct {
	snapshot run.PrincipalSnapshot
	err      error
	calls    int
	tenantID string
	runID    string
}

func validPrincipalFixture() run.PrincipalSnapshot {
	return run.PrincipalSnapshot{
		Version: "acp-principal/v1", IssuerSPIFFEID: "spiffe://example.org/acp",
		ProjectID: "project-1", SubjectID: "subject-1", ActorID: "actor-1",
		PolicyRevision: "policy-1",
		ConfigDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
}

func (p *principalFixtureReader) GetRunPrincipalSnapshot(_ context.Context, tenantID, runID string) (run.PrincipalSnapshot, error) {
	p.calls++
	p.tenantID, p.runID = tenantID, runID
	return p.snapshot, p.err
}

func TestDecisionEgressRejectsMissingPrincipalStore(t *testing.T) {
	client := &immediateDecisionInvoker{}
	a := Activities{Client: client, Breakers: &fakeBreakerStore{records: []breaker.Record{closedRunBreaker(t)}}, Runs: testRunIdentityReader()}
	_, err := a.InvokeDecision(context.Background(), activityTurn())
	if !errors.Is(err, ErrRunPrincipalUnavailable) {
		t.Fatalf("missing trusted principal should be denied: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("Decision egress without principal store: %d", client.calls)
	}
}

func TestDecisionEgressRejectsMissingOrInvalidDurablePrincipal(t *testing.T) {
	cases := []struct {
		name     string
		snapshot run.PrincipalSnapshot
		err      error
	}{
		{"missing", run.PrincipalSnapshot{}, errors.New("principal row absent")},
		{"malformed", run.PrincipalSnapshot{Version: "acp-principal/v1", SubjectID: "spoofed"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &immediateDecisionInvoker{}
			reader := &principalFixtureReader{snapshot: tc.snapshot, err: tc.err}
			breakers := &fakeBreakerStore{records: []breaker.Record{closedRunBreaker(t)}}
			a := Activities{Client: client, Breakers: breakers, Runs: testRunIdentityReader(), Principals: reader}
			_, err := a.InvokeDecision(context.Background(), activityTurn())
			if err == nil {
				t.Fatal("unverified principal reached egress")
			}
			if reader.calls != 1 || reader.tenantID != "tenant-001" || reader.runID != temporalTestRunID {
				t.Fatalf("principal lookup failed to use persisted Run identity: %+v", reader)
			}
			if client.calls != 0 || breakers.callCount() != 0 {
				t.Fatalf("principal failure reached breaker/client: %d/%d", breakers.callCount(), client.calls)
			}
		})
	}
}

func TestDecisionEgressWithBoundSnapshotPreservesRunCorrelation(t *testing.T) {
	client := &immediateDecisionInvoker{}
	reader := &principalFixtureReader{snapshot: validPrincipalFixture()}
	a := Activities{
		Client: client, Breakers: &fakeBreakerStore{records: []breaker.Record{closedRunBreaker(t)}},
		Runs: testRunIdentityReader(), Principals: reader,
		Execution:     &fixedTemporalExecutionResolver{execution: temporalTestExecution()},
		TemporalTurns: &fixedTemporalTurnWriter{identity: temporalTestTurnIdentity()},
	}
	if _, err := a.InvokeDecision(context.Background(), activityTurn()); err != nil {
		t.Fatalf("valid persisted principal blocked: %v", err)
	}
	if client.calls != 1 || reader.calls != 1 || reader.tenantID != "tenant-001" || reader.runID != temporalTestRunID {
		t.Fatalf("wrong principal correlation: client=%d reader=%+v", client.calls, reader)
	}
}

// Tests that exercise the breaker/Decision path supply a persisted-principal
// fixture explicitly. The production worker always uses the PostgreSQL reader.
func testPrincipalReader() *principalFixtureReader {
	return &principalFixtureReader{snapshot: validPrincipalFixture()}
}
