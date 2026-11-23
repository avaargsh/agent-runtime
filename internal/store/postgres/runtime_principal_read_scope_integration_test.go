package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
)

// The same Runtime-issued Run and immutable ACP principal must not be
// addressable through caller-supplied aliases. The authority must reject
// noncanonical scope before it reads durable principal/policy claims.
func TestPrincipalReadRejectsNoncanonicalRunIDBeforeLookup(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	want := trustedSnapshot()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), want)
	if err != nil {
		t.Fatal(err)
	}
	reader := postgres.New(pool)
	got, err := reader.GetRunPrincipalSnapshot(ctx, receipt.TenantID, receipt.RunID)
	if err != nil || got != want {
		t.Fatalf("canonical Run principal read changed: %+v err=%v", got, err)
	}
	for name, alias := range map[string]string{
		"compact": strings.ReplaceAll(receipt.RunID, "-", ""),
		"braced":  "{" + receipt.RunID + "}",
		"urn":     "urn:uuid:" + receipt.RunID,
		"space":   receipt.RunID + " ",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := reader.GetRunPrincipalSnapshot(ctx, receipt.TenantID, alias)
			if !errors.Is(err, run.ErrInvalidRequest) {
				t.Fatalf("noncanonical Run alias %q: got %v, want ErrInvalidRequest", alias, err)
			}
		})
	}
}

// Malformed tenant bytes must fail at the application scope boundary rather
// than be passed to PostgreSQL and surfaced as an ambiguous database outage.
func TestPrincipalReadRejectsMalformedTenantBeforeLookup(t *testing.T) {
	pool, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant-" + string([]byte{0xff})
	_, err = postgres.New(pool).GetRunPrincipalSnapshot(ctx, tenant, receipt.RunID)
	if !errors.Is(err, run.ErrInvalidRequest) {
		t.Fatalf("invalid UTF-8 tenant reached persistence: %v", err)
	}
}
