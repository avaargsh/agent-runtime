package run_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

type fakeRepository struct {
	mu   sync.Mutex
	runs map[string]run.Run
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{runs: make(map[string]run.Run)}
}

func (r *fakeRepository) CreateOrGet(_ context.Context, candidate run.Run) (run.Run, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := candidate.TenantID + "\x00" + candidate.IdempotencyKey
	if existing, ok := r.runs[key]; ok {
		if existing.RequestDigest != candidate.RequestDigest {
			return run.Run{}, false, run.ErrIdempotencyConflict
		}
		return existing, false, nil
	}
	r.runs[key] = candidate
	return candidate, true, nil
}

func validRequest() run.StartRequest {
	return run.StartRequest{
		TenantID:        "tenant-1",
		AgentID:         "agent-1",
		AgentReleaseID:  "release-1",
		SessionID:       "session-1",
		IdempotencyKey:  "request-1",
		Input:           []byte(`{"message":"hello"}`),
	}
}

func TestStartRunReturnsStableRunForEquivalentJSON(t *testing.T) {
	service := run.NewService(newFakeRepository())

	first, err := service.Start(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if !first.Created {
		t.Fatal("first Start() must create the Run")
	}
	if first.Run.ID == "" {
		t.Fatal("Run ID must not be empty")
	}
	if first.Run.WorkflowID != "agent-run/"+first.Run.ID {
		t.Fatalf("Workflow ID = %q, want agent-run/%s", first.Run.WorkflowID, first.Run.ID)
	}

	secondRequest := validRequest()
	secondRequest.Input = []byte(`{ "message" : "hello" }`)
	second, err := service.Start(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	if second.Created {
		t.Fatal("equivalent request must not create a second Run")
	}
	if second.Run.ID != first.Run.ID {
		t.Fatalf("Run ID changed: first=%q second=%q", first.Run.ID, second.Run.ID)
	}
	if second.Run.WorkflowID != first.Run.WorkflowID {
		t.Fatalf("Workflow ID changed: first=%q second=%q", first.Run.WorkflowID, second.Run.WorkflowID)
	}
}

func TestStartRunRejectsChangedRequestForSameIdempotencyKey(t *testing.T) {
	service := run.NewService(newFakeRepository())
	if _, err := service.Start(context.Background(), validRequest()); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}

	changed := validRequest()
	changed.Input = []byte(`{"message":"different"}`)
	if _, err := service.Start(context.Background(), changed); !errors.Is(err, run.ErrIdempotencyConflict) {
		t.Fatalf("second Start() error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestStartRunRejectsInvalidInput(t *testing.T) {
	for _, input := range [][]byte{
		[]byte(`not-json`),
		[]byte(`["not","an","object"]`),
		[]byte(`{"message":"hello"} {"extra":true}`),
	} {
		t.Run(string(input), func(t *testing.T) {
			request := validRequest()
			request.Input = input
			if _, err := run.NewService(newFakeRepository()).Start(context.Background(), request); !errors.Is(err, run.ErrInvalidRequest) {
				t.Fatalf("Start() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestStartRunRequiresTenantAndIdempotencyKey(t *testing.T) {
	for name, mutate := range map[string]func(*run.StartRequest){
		"tenant": func(r *run.StartRequest) { r.TenantID = "" },
		"idempotency key": func(r *run.StartRequest) { r.IdempotencyKey = " " },
	} {
		t.Run(name, func(t *testing.T) {
			request := validRequest()
			mutate(&request)
			if _, err := run.NewService(newFakeRepository()).Start(context.Background(), request); !errors.Is(err, run.ErrInvalidRequest) {
				t.Fatalf("Start() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}
