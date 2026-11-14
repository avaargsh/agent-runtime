package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

func TestGetRunIdentityReturnsPersistedCanonicalBinding(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	candidateRun := candidate("00000000-0000-4000-8000-000000000501")
	created, ok, err := store.CreateOrGet(ctx, candidateRun)
	if err != nil || !ok {
		t.Fatalf("CreateOrGet() = (%+v, %v, %v), want created Run", created, ok, err)
	}

	got, err := store.GetRunIdentity(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRunIdentity() error = %v", err)
	}
	want := run.Identity{
		RunID:          created.ID,
		TenantID:       created.TenantID,
		AgentID:        created.AgentID,
		AgentReleaseID: created.AgentReleaseID,
		SessionID:      created.SessionID,
	}
	if got != want {
		t.Fatalf("GetRunIdentity() = %+v, want persisted identity %+v", got, want)
	}
}

func TestGetRunIdentityDoesNotResolveUnpersistedOrMalformedRuns(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.GetRunIdentity(ctx, "not-a-uuid"); !errors.Is(err, run.ErrInvalidRequest) {
		t.Fatalf("malformed Run ID error = %v, want ErrInvalidRequest", err)
	}
	if _, err := store.GetRunIdentity(ctx, "00000000-0000-4000-8000-000000000599"); !errors.Is(err, run.ErrRunNotFound) {
		t.Fatalf("unknown Run ID error = %v, want ErrRunNotFound", err)
	}
}
