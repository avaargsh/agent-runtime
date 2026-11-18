package postgres_test

import (
	"context"
	"testing"
)

// Reproduce v12 migration-ledger drift: intact immutable triggers do not
// establish that the JSON binding, referential or uniqueness fences survive.
func TestDecisionAcceptanceMigrationRejectsConstraintDrift(t *testing.T) {
	cases := []struct {
		name string
		ddl  []string
	}{
		{
			name: "same-name weakened record hash check",
			ddl: []string{
				"ALTER TABLE runtime_decision_acceptances DROP CONSTRAINT runtime_decision_acceptances_record_sha256_check",
				"ALTER TABLE runtime_decision_acceptances ADD CONSTRAINT runtime_decision_acceptances_record_sha256_check CHECK (TRUE)",
			},
		},
		{
			name: "missing turn reference",
			ddl:  []string{"ALTER TABLE runtime_decision_acceptances DROP CONSTRAINT runtime_decision_acceptances_turn_id_fkey"},
		},
		{
			name: "missing unique turn binding",
			ddl:  []string{"ALTER TABLE runtime_decision_acceptances DROP CONSTRAINT runtime_decision_acceptances_turn_id_key"},
		},
		{
			name: "nullable immutable receipt",
			ddl:  []string{"ALTER TABLE runtime_decision_acceptances ALTER COLUMN receipt DROP NOT NULL"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, store := newTestStore(t)
			ctx := context.Background()
			for _, statement := range tc.ddl {
				if _, err := pool.Exec(ctx, statement); err != nil {
					t.Fatalf("simulate drift %q: %v", statement, err)
				}
			}
			if err := store.Migrate(ctx); err == nil {
				t.Fatal("previously applied v12 migration concealed weakened acceptance schema")
			}
		})
	}
}
