package postgres

import (
	"context"
	"fmt"
)

func verifyRuntimeAttemptAuthorityCatalog(ctx context.Context, db harnessCatalogReader) error {
	migration, err := migrationFiles.ReadFile("migrations/0013_runtime_run_attempt_authority.up.sql")
	if err != nil {
		return err
	}
	specs := []struct {
		triggerName  string
		functionName string
		triggerType  int
	}{
		{"runtime_run_attempt_authority_insert_guard", "enforce_runtime_run_attempt_authority_insert", 1 | 2 | 4},
		{"runtime_run_attempt_authority_no_mutation", "reject_runtime_run_attempt_authority_mutation", 1 | 2 | 8 | 16},
		{"runtime_run_attempt_authority_no_truncate", "reject_runtime_run_attempt_authority_mutation", 2 | 32},
	}
	for _, spec := range specs {
		expected, err := harnessMigrationFunctionSource(string(migration), spec.functionName)
		if err != nil {
			return err
		}
		var valid bool
		err = db.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger tg
				JOIN pg_catalog.pg_class rel ON rel.oid=tg.tgrelid
				JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
				JOIN pg_catalog.pg_proc fn ON fn.oid=tg.tgfoid
				JOIN pg_catalog.pg_language lang ON lang.oid=fn.prolang
				WHERE ns.nspname=current_schema()
				  AND rel.relname='runtime_run_attempt_authorities'
				  AND rel.relkind='r' AND rel.relpersistence='p'
				  AND tg.tgname=$1 AND NOT tg.tgisinternal AND tg.tgenabled='A'
				  AND tg.tgtype=$2 AND tg.tgqual IS NULL AND tg.tgattr::text=''
				  AND tg.tgnargs=0 AND tg.tgconstraint=0
				  AND fn.pronamespace=rel.relnamespace
				  AND fn.proname=$3 AND fn.prosrc=$4
				  AND NOT fn.prosecdef AND fn.pronargs=0
				  AND fn.prokind='f' AND lang.lanname='plpgsql'
				  AND fn.prorettype='pg_catalog.trigger'::regtype AND fn.proconfig IS NULL
			)
		`, spec.triggerName, spec.triggerType, spec.functionName, expected).Scan(&valid)
		if err != nil {
			return fmt.Errorf("verify Runtime Attempt authority catalog: %w", err)
		}
		if !valid {
			return fmt.Errorf("Runtime Attempt authority protection drift: %s", spec.triggerName)
		}
	}
	return nil
}
