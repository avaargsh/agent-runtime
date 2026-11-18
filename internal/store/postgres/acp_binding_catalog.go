package postgres

import (
	"context"
	"fmt"
)

// Verify the actual catalog rather than treating an applied migration as
// proof of integrity. This is not protection from a privileged DDL owner.
func verifyACPBindingCatalog(ctx context.Context, db harnessCatalogReader) error {
	migration, err := migrationFiles.ReadFile("migrations/0010_immutable_acp_run_binding.up.sql")
	if err != nil {
		return err
	}
	expected, err := harnessMigrationFunctionSource(string(migration), "enforce_immutable_acp_run_binding")
	if err != nil {
		return err
	}
	var valid bool
	err = db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_trigger tg
			JOIN pg_catalog.pg_class rel ON rel.oid=tg.tgrelid
			JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
			JOIN pg_catalog.pg_proc fn ON fn.oid=tg.tgfoid
			JOIN pg_catalog.pg_language lang ON lang.oid=fn.prolang
			WHERE ns.nspname=current_schema() AND rel.relname='runs'
			  AND rel.relkind='r' AND rel.relpersistence='p'
			  AND tg.tgname='runs_acp_binding_immutable' AND NOT tg.tgisinternal
			  AND tg.tgenabled='A' AND tg.tgtype=27
			  AND tg.tgqual IS NULL AND tg.tgattr::text=''
			  AND tg.tgnargs=0 AND tg.tgconstraint=0
			  AND fn.pronamespace=rel.relnamespace
			  AND fn.proname='enforce_immutable_acp_run_binding'
			  AND fn.prosrc=$1 AND NOT fn.prosecdef AND fn.pronargs=0
			  AND fn.prokind='f' AND lang.lanname='plpgsql'
			  AND fn.prorettype='pg_catalog.trigger'::regtype
			  AND fn.proconfig IS NULL
		)
	`, expected).Scan(&valid)
	if err != nil {
		return fmt.Errorf("verify immutable ACP Run binding catalog: %w", err)
	}
	if !valid {
		return fmt.Errorf("immutable ACP Run binding catalog drift")
	}
	return nil
}
