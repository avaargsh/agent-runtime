package postgres

import (
	"context"
	"fmt"
)

// verifyCircuitBreakerTransitionCatalog attests the exact v15 state-machine
// trigger even on databases where the migration ledger already records v14.
// This is a point-in-time startup check, not protection against a privileged
// owner changing the catalog after startup.
func verifyCircuitBreakerTransitionCatalog(ctx context.Context, db harnessCatalogReader) error {
	migration, err := migrationFiles.ReadFile("migrations/0015_runtime_circuit_breaker_reopen_precision.up.sql")
	if err != nil {
		return fmt.Errorf("circuit breaker catalog: read v15 migration: %w", err)
	}
	expected, err := harnessMigrationFunctionSource(string(migration), "enforce_runtime_circuit_breaker_transition")
	if err != nil {
		return fmt.Errorf("circuit breaker catalog: extract transition function: %w", err)
	}
	var valid bool
	err = db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_trigger tg
			JOIN pg_catalog.pg_class rel ON rel.oid=tg.tgrelid
			JOIN pg_catalog.pg_namespace rel_ns ON rel_ns.oid=rel.relnamespace
			JOIN pg_catalog.pg_proc fn ON fn.oid=tg.tgfoid
			JOIN pg_catalog.pg_language lang ON lang.oid=fn.prolang
			WHERE rel_ns.nspname=current_schema()
			  AND rel.relname='runtime_circuit_breakers'
			  AND rel.relkind='r' AND rel.relpersistence='p'
			  AND tg.tgname='runtime_circuit_breaker_transition'
			  AND NOT tg.tgisinternal AND tg.tgenabled='A' AND tg.tgtype=23
			  AND tg.tgqual IS NULL AND tg.tgattr::text=''
			  AND tg.tgnargs=0 AND tg.tgconstraint=0
			  AND fn.pronamespace=rel_ns.oid
			  AND fn.proname='enforce_runtime_circuit_breaker_transition'
			  AND fn.prosrc=$1 AND NOT fn.prosecdef AND fn.pronargs=0
			  AND fn.prokind='f' AND lang.lanname='plpgsql'
			  AND fn.prorettype='pg_catalog.trigger'::regtype
			  AND fn.proconfig IS NULL
		)
	`, expected).Scan(&valid)
	if err != nil {
		return fmt.Errorf("verify Runtime circuit breaker transition catalog: %w", err)
	}
	if !valid {
		return fmt.Errorf("Runtime circuit breaker transition catalog drift")
	}
	return nil
}
