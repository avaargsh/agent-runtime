package postgres

import (
	"context"
	"fmt"
)

func verifyDecisionCheckpointCatalog(ctx context.Context, db harnessCatalogReader) error {
	return verifyDecisionFactCatalog(ctx, db, "runtime_decision_checkpoints", "runtime_decision_checkpoint")
}

func verifyDecisionAcceptanceCatalog(ctx context.Context, db harnessCatalogReader) error {
	return verifyDecisionFactCatalog(ctx, db, "runtime_decision_acceptances", "runtime_decision_acceptance")
}

func verifyDecisionFactCatalog(ctx context.Context, db harnessCatalogReader, table, triggerPrefix string) error {
	migration, err := migrationFiles.ReadFile("migrations/0011_runtime_decision_checkpoint.up.sql")
	if err != nil {
		return err
	}
	expected, err := harnessMigrationFunctionSource(string(migration), "reject_runtime_decision_checkpoint_mutation")
	if err != nil {
		return err
	}
	for _, spec := range []struct {
		name string
		mask int
	}{
		{triggerPrefix + "_no_mutation", 27},
		{triggerPrefix + "_no_truncate", 34},
	} {
		var valid bool
		err := db.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger tg
				JOIN pg_catalog.pg_class rel ON rel.oid=tg.tgrelid
				JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
				JOIN pg_catalog.pg_proc fn ON fn.oid=tg.tgfoid
				JOIN pg_catalog.pg_language lang ON lang.oid=fn.prolang
				WHERE ns.nspname=current_schema() AND rel.relname=$4
				  AND rel.relkind='r' AND rel.relpersistence='p'
				  AND tg.tgname=$1 AND NOT tg.tgisinternal AND tg.tgenabled='A'
				  AND tg.tgtype=$2 AND tg.tgqual IS NULL AND tg.tgattr::text=''
				  AND tg.tgnargs=0 AND tg.tgconstraint=0
				  AND fn.pronamespace=rel.relnamespace
				  AND fn.proname='reject_runtime_decision_checkpoint_mutation'
				  AND fn.prosrc=$3 AND NOT fn.prosecdef AND fn.pronargs=0
				  AND fn.prokind='f' AND lang.lanname='plpgsql'
				  AND fn.prorettype='pg_catalog.trigger'::regtype AND fn.proconfig IS NULL
			)
		`, spec.name, spec.mask, expected, table).Scan(&valid)
		if err != nil {
			return fmt.Errorf("verify decision checkpoint catalog: %w", err)
		}
		if !valid {
			return fmt.Errorf("decision checkpoint protection drift: %s", spec.name)
		}
	}
	return nil
}
