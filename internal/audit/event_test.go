package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/securitycontext"
)

func validEvent() Event {
	identity, _ := securitycontext.New(securitycontext.Claims{
		TenantID:       "tenant-001",
		SubjectID:      "user-001",
		ActorID:        "actor-001",
		AgentID:        "agent-001",
		AgentReleaseID: "release-001",
		SessionID:      "session-001",
		RunID:          "run-001",
		RunAttemptID:   "attempt-001",
		TurnID:         "turn-001",
		PolicyRevision: "policy-7",
	})
	return Event{
		EventID:     "event-001",
		OccurredAt: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Type:        EventModelRequestSent,
		Identity:    identity,
		Source:      "model-interceptor",
		Action:      "model.request",
		Resource:    "provider/model",
		Outcome:     OutcomeDispatched,
		PayloadDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

type fakeRecorder struct {
	events []Event
	err    error
}

func (r *fakeRecorder) Append(_ context.Context, event Event) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, event)
	return nil
}

func TestEventValidateAcceptsCorrelatedModelAndToolEvidence(t *testing.T) {
	for _, eventType := range []EventType{
		EventRunStarted,
		EventModelRequestSent,
		EventModelResponseReceived,
		EventToolProposed,
		EventToolCallStarted,
		EventToolCallCompleted,
		EventSecurityDenied,
		EventBreakerTripped,
		EventBreakerRecovered,
	} {
		event := validEvent()
		event.Type = eventType
		if err := event.Validate(); err != nil {
			t.Fatalf("Validate(%s) error = %v", eventType, err)
		}
	}
}

func TestEventValidateRejectsMissingIdentityAndInvalidDigest(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "missing event id", mutate: func(e *Event) { e.EventID = "" }},
		{name: "missing time", mutate: func(e *Event) { e.OccurredAt = time.Time{} }},
		{name: "missing source", mutate: func(e *Event) { e.Source = "" }},
		{name: "invalid event type", mutate: func(e *Event) { e.Type = "MODEL_SECRET_DUMP" }},
		{name: "invalid digest", mutate: func(e *Event) { e.PayloadDigest = "not-a-digest" }},
		{name: "missing security context", mutate: func(e *Event) { e.Identity = securitycontext.Context{} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := validEvent()
			tc.mutate(&event)
			if err := event.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestAppendCheckedFailsClosedWhenRecorderUnavailableOrFails(t *testing.T) {
	event := validEvent()
	if err := AppendChecked(context.Background(), nil, event); !errors.Is(err, ErrRecorderUnavailable) {
		t.Fatalf("AppendChecked(nil) error = %v, want ErrRecorderUnavailable", err)
	}

	recorderErr := errors.New("audit database unavailable")
	recorder := &fakeRecorder{err: recorderErr}
	if err := AppendChecked(context.Background(), recorder, event); !errors.Is(err, recorderErr) {
		t.Fatalf("AppendChecked() error = %v, want %v", err, recorderErr)
	}
}

func TestAppendCheckedPersistsOnlyValidatedEvent(t *testing.T) {
	recorder := &fakeRecorder{}
	event := validEvent()
	if err := AppendChecked(context.Background(), recorder, event); err != nil {
		t.Fatalf("AppendChecked() error = %v", err)
	}
	if len(recorder.events) != 1 || recorder.events[0].EventID != event.EventID {
		t.Fatalf("recorded events = %+v, want one event %s", recorder.events, event.EventID)
	}
}
