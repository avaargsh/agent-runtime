package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

func TestMissingACPInputNeverPersistsRunOrOutbox(t *testing.T) {
	pool, store := newTestStore(t)
	request := testIntent()
	request.Input = nil

	_, err := store.AcceptIntent(context.Background(), request)
	if !errors.Is(err, run.ErrInvalidRequest) {
		t.Fatalf("missing ACP input was accepted: %v", err)
	}

	var runCount, outboxCount int
	err = pool.QueryRow(context.Background(),
		"SELECT (SELECT count(*) FROM runs), (SELECT count(*) FROM runtime_outbox)",
	).Scan(&runCount, &outboxCount)
	if err != nil {
		t.Fatal(err)
	}
	if runCount != 0 || outboxCount != 0 {
		t.Fatalf("rejected input left durable effects: runs=%d outbox=%d", runCount, outboxCount)
	}
}
