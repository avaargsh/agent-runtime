package postgres

import (
	"context"
	"fmt"
)

// verifyCircuitBreakerTransitionCatalog attests the complete v14-v16 breaker
// write boundary even when the migration ledger already records v16.
// This is a point-in-time startup check, not protection against a privileged
// owner changing the catalog after startup.
func verifyCircuitBreakerTransitionCatalog(ctx context.Context, db harnessCatalogReader) error {
	transitionMigration, err := migrationFiles.ReadFile("migrations/0015_runtime_circuit_breaker_reopen_precision.up.sql")
	if err != nil {
		return fmt.Errorf("circuit breaker catalog: read v15 migration: %w", err)
	}
	transitionSource, err := harnessMigrationFunctionSource(string(transitionMigration), "enforce_runtime_circuit_breaker_transition")
	if err != nil {
		return fmt.Errorf("circuit breaker catalog: extract v15 transition function: %w", err)
	}
	retentionMigration, err := migrationFiles.ReadFile("migrations/0016_runtime_circuit_breaker_retention_guard.up.sql")
	if err != nil {
		return fmt.Errorf("circuit breaker catalog: read v16 migration: %w", err)
	}
	retentionSource, err := harnessMigrationFunctionSource(string(retentionMigration), "reject_runtime_circuit_breaker_mutation")
	if err != nil {
		return fmt.Errorf("circuit breaker catalog: extract v16 retention function: %w", err)
	}

	specs := []struct {
		triggerName  string
		functionName string
		triggerType  int
		source       string
	}{
		{"runtime_circuit_breaker_transition", "enforce_runtime_circuit_breaker_transition", 23, transitionSource},
		{"runtime_circuit_breaker_no_delete", "reject_runtime_circuit_breaker_mutation", 11, retentionSource},
		{"runtime_circuit_breaker_no_truncate", "reject_runtime_circuit_breaker_mutation", 34, retentionSource},
	}

	var triggerCount int
	if err := db.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_catalog.pg_trigger tg
		JOIN pg_catalog.pg_class rel ON rel.oid=tg.tgrelid
		JOIN pg_catalog.pg_namespace rel_ns ON rel_ns.oid=rel.relnamespace
		WHERE rel_ns.nspname=current_schema()
		  AND rel.relname='runtime_circuit_breakers'
		  AND rel.relkind='r' AND rel.relpersistence='p'
		  AND NOT tg.tgisinternal
	`).Scan(&triggerCount); err != nil {
		return fmt.Errorf("inspect Runtime circuit breaker triggers: %w", err)
	}
	if triggerCount != len(specs) {
		return fmt.Errorf("Runtime circuit breaker trigger count drift: got %d want %d", triggerCount, len(specs))
	}

	for _, spec := range specs {
		var valid bool
		err := db.QueryRow(ctx, `
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
				  AND tg.tgname=$1
				  AND NOT tg.tgisinternal AND tg.tgenabled='A' AND tg.tgtype=$2
				  AND tg.tgqual IS NULL AND tg.tgattr::text=''
				  AND tg.tgnargs=0 AND tg.tgconstraint=0
				  AND fn.pronamespace=rel_ns.oid
				  AND fn.proname=$3 AND fn.prosrc=$4
				  AND NOT fn.prosecdef AND fn.pronargs=0
				  AND fn.prokind='f' AND lang.lanname='plpgsql'
				  AND fn.prorettype='pg_catalog.trigger'::regtype
				  AND fn.proconfig IS NULL
			)
		`, spec.triggerName, spec.triggerType, spec.functionName, spec.source).Scan(&valid)
		if err != nil {
			return fmt.Errorf("verify Runtime circuit breaker trigger %s: %w", spec.triggerName, err)
		}
		if !valid {
			return fmt.Errorf("Runtime circuit breaker catalog drift: trigger %s", spec.triggerName)
		}
	}
	return nil
}
