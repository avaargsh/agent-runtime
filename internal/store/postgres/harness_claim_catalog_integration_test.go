package postgres_test

import (
	"context"
	"strings"
	"testing"
)

// An applied migration ledger is not proof that its guards are still active.
// All cases are repository-level tampering fixtures, not a claim of an
// independently confirmed production compromise.
func TestHarnessSessionCatalogAttestationFailsClosedOnProtectionDrift(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
	}{
		{
			name: "disabled immutable row trigger",
			statements: []string{
				"ALTER TABLE runtime_harness_session_claims DISABLE TRIGGER runtime_harness_claim_immutable",
			},
		},
		{
			name: "dropped TRUNCATE trigger",
			statements: []string{
				"DROP TRIGGER runtime_harness_claim_no_truncate ON runtime_harness_session_claims",
			},
		},
		{
			name: "replaced immutable trigger body",
			statements: []string{
				`CREATE OR REPLACE FUNCTION enforce_runtime_harness_claim_transition()
				    RETURNS trigger LANGUAGE plpgsql
				    AS $body$ BEGIN RETURN NEW; END $body$`,
			},
		},
		{
			name: "replaced TRUNCATE trigger body",
			statements: []string{
				`CREATE OR REPLACE FUNCTION reject_runtime_harness_claim_truncate()
				    RETURNS trigger LANGUAGE plpgsql
				    AS $body$ BEGIN RETURN NULL; END $body$`,
			},
		},
		{
			name: "UPDATE OF narrows immutable trigger",
			statements: []string{
				"DROP TRIGGER runtime_harness_claim_immutable ON runtime_harness_session_claims",
				`CREATE TRIGGER runtime_harness_claim_immutable
				    BEFORE UPDATE OF state OR DELETE ON runtime_harness_session_claims
				    FOR EACH ROW EXECUTE FUNCTION enforce_runtime_harness_claim_transition()`,
			},
		},
		{
			name: "WHEN false bypasses immutable trigger",
			statements: []string{
				"DROP TRIGGER runtime_harness_claim_immutable ON runtime_harness_session_claims",
				`CREATE TRIGGER runtime_harness_claim_immutable
				    BEFORE UPDATE OR DELETE ON runtime_harness_session_claims
				    FOR EACH ROW WHEN (false)
				    EXECUTE FUNCTION enforce_runtime_harness_claim_transition()`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, store := newTestStore(t)
			ctx := context.Background()
			for _, statement := range tc.statements {
				if _, err := pool.Exec(ctx, statement); err != nil {
					t.Fatalf("set up %q: %v", tc.name, err)
				}
			}
			if err := store.Migrate(ctx); err == nil {
				t.Fatal("schema v9 ledger masked dangerous Harness claim catalog drift")
			} else if !strings.Contains(err.Error(), "Harness claim catalog") {
				t.Fatalf("unexpected migration failure, want Harness claim catalog error: %v", err)
			}
		})
	}
}

func TestHarnessSessionCatalogAttestationAllowsIntactSchema(t *testing.T) {
	_, store := newTestStore(t)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("correct v9 schema should be accepted: %v", err)
	}
}
