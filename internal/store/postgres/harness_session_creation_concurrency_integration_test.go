package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

type concurrentCreationRPC struct {
	store      *postgres.Store
	claim      acp.SessionClaim
	dispatches *atomic.Int32
	release    <-chan struct{}
}

func (r *concurrentCreationRPC) Call(ctx context.Context, method string, params any, result any) error {
	switch method {
	case "initialize":
		return json.Unmarshal([]byte(`{"protocolVersion":1}`), result)
	case "session/new":
		r.dispatches.Add(1)
		record, err := r.store.ReadHarnessSessionClaim(ctx, r.claim)
		if err != nil || record.State != acp.ClaimUnknown || record.AgentSessionID != "" {
			return fmt.Errorf("dispatch without durable UNKNOWN: %v", err)
		}
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return json.Unmarshal([]byte(`{"sessionId":"concurrent-session"}`), result)
	default:
		return fmt.Errorf("unexpected method %s", method)
	}
}

func (r *concurrentCreationRPC) Notify(context.Context, string, any) error {
	return errors.New("unexpected notification")
}

// Real PostgreSQL arbitrates distinct Clients and Store instances. Hold
// the winning RPC until all losing callers return, so this verifies the
// in-flight UNKNOWN window rather than only replay after confirmation.
func TestHarnessCreateSessionConcurrentClientsOneDispatch(t *testing.T) {
	pool, store, claim := harnessFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	const workers = 12
	var dispatches atomic.Int32
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer cancel()
	defer releaseOnce.Do(func() { close(release) })

	clients := make([]*acp.Client, workers)
	for i := range clients {
		independent := postgres.New(pool)
		rpc := &concurrentCreationRPC{store: independent, claim: claim, dispatches: &dispatches, release: release}
		client, err := acp.NewClient(rpc, independent, claim.HarnessInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		clients[i] = client
	}
	type outcome struct {
		record acp.SessionClaimRecord
		err    error
	}
	results := make(chan outcome, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		releaseOnce.Do(func() { close(release) })
		cancel()
		wg.Wait()
	}()
	for _, client := range clients {
		wg.Add(1)
		go func(c *acp.Client) {
			defer wg.Done()
			<-start
			record, err := c.CreateSession(ctx, claim)
			results <- outcome{record, err}
		}(client)
	}
	close(start)

	for i := 0; i < workers-1; i++ {
		select {
		case got := <-results:
			if !errors.Is(got.err, acp.ErrSessionCreationUncertain) || got.record.AgentSessionID != "" || got.record.State == acp.ClaimConfirmed {
				t.Fatalf("losing client obtained authority: %+v", got)
			}
		case <-ctx.Done():
			t.Fatal("losing clients did not return before winning RPC completed")
		}
	}
	pending, err := store.ReadHarnessSessionClaim(ctx, claim)
	if err != nil || pending.State != acp.ClaimUnknown || dispatches.Load() != 1 {
		t.Fatalf("in-flight durable authority: %+v dispatches=%d err=%v", pending, dispatches.Load(), err)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case got := <-results:
		if got.err != nil || got.record.State != acp.ClaimConfirmed || got.record.AgentSessionID != "concurrent-session" {
			t.Fatalf("winning client failed confirmation: %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("winning RPC did not complete")
	}
	after, err := postgres.New(pool).ReadHarnessSessionClaim(ctx, claim)
	if err != nil || after.State != acp.ClaimConfirmed || after.AgentSessionID != "concurrent-session" || dispatches.Load() != 1 {
		t.Fatalf("wrong final durable state: %+v dispatches=%d err=%v", after, dispatches.Load(), err)
	}
}
