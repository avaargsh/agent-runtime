package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/agent-runtime/internal/run"
)

// The authority transport already requires canonical Run IDs; the exported
// storage seam must enforce the same invariant instead of normalizing a
// caller-supplied alias into an eligible Guard safety snapshot.
func TestGuardRunSafetyReadersRejectNoncanonicalRunIDAliases(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	receipt, err := store.AcceptIntentWithPrincipal(ctx, testIntent(), trustedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetTrustedGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); err != nil {
		t.Fatalf("canonical trusted Run read: %v", err)
	}
	if _, err := store.GetGuardRunSafetySnapshot(ctx, receipt.TenantID, receipt.RunID); err != nil {
		t.Fatalf("canonical diagnostic Run read: %v", err)
	}
	aliases := []string{
		strings.ReplaceAll(receipt.RunID, "-", ""),
		"urn:uuid:" + receipt.RunID,
		"{" + receipt.RunID + "}",
		receipt.RunID + " ",
	}
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			for name, read := range map[string]func(context.Context, string, string) (run.GuardRunSafetySnapshot, error){
				"diagnostic": store.GetGuardRunSafetySnapshot,
				"trusted": store.GetTrustedGuardRunSafetySnapshot,
			} {
				_, err := read(ctx, receipt.TenantID, alias)
				if !errors.Is(err, run.ErrInvalidRequest) {
					t.Errorf("%s accepted noncanonical Run alias %q: %v", name, alias, err)
				}
			}
		})
	}
}

// Reject invalid tenant bytes before querying PostgreSQL or normalizing
// untrusted caller metadata; there must be an explicit invalid-scope result.
func TestGuardRunSafetyReadersRejectInvalidUTF8Tenant(t *testing.T) {
	_, store := newTestStore(t)
	ctx := context.Background()
	runID := "00000000-0000-4000-8000-000000000611"
	tenant := "tenant-" + string([]byte{0xff})
	for name, read := range map[string]func(context.Context, string, string) (run.GuardRunSafetySnapshot, error){
		"diagnostic": store.GetGuardRunSafetySnapshot,
		"trusted": store.GetTrustedGuardRunSafetySnapshot,
	} {
		_, err := read(ctx, tenant, runID)
		if !errors.Is(err, run.ErrInvalidRequest) {
			t.Errorf("%s failed to reject invalid UTF-8 tenant at the boundary: %v", name, err)
		}
	}
}
