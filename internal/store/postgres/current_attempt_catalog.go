package postgres

import (
	"context"
	"fmt"
	"strings"
)

// verifyCurrentAttemptCatalog attests the generation-one shadow record at
// migration/startup, including already-applied v13 databases. This is not a
// fence against subsequent privileged DDL or a grant of execution authority.
func verifyCurrentAttemptCatalog(ctx context.Context, db harnessCatalogReader) error {
	const relation = "runtime_current_attempts"
	var columns, checks, keys int
	if err := db.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM pg_catalog.pg_attribute a WHERE a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped),
		  (SELECT count(*) FROM pg_catalog.pg_constraint c WHERE c.conrelid=r.oid AND c.contype='c'),
		  (SELECT count(*) FROM pg_catalog.pg_constraint c WHERE c.conrelid=r.oid AND c.contype IN ('p','u','f'))
		FROM pg_catalog.pg_class r JOIN pg_catalog.pg_namespace ns ON ns.oid=r.relnamespace
		WHERE ns.nspname=current_schema() AND r.relname=$1 AND r.relkind='r' AND r.relpersistence='p'
	`, relation).Scan(&columns, &checks, &keys); err != nil || columns != 5 || checks != 2 || keys != 2 {
		return fmt.Errorf("current Attempt catalog relation/count drift: columns=%d checks=%d keys=%d err=%v", columns, checks, keys, err)
	}
	for _, column := range []struct{ name, typ string }{
		{"tenant_id", "text"}, {"run_id", "uuid"}, {"attempt_id", "uuid"},
		{"generation", "bigint"}, {"breaker_epoch", "bigint"},
	} {
		var valid bool
		err := db.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_attribute a
				JOIN pg_catalog.pg_class r ON r.oid=a.attrelid
				JOIN pg_catalog.pg_namespace ns ON ns.oid=r.relnamespace
				WHERE ns.nspname=current_schema() AND r.relname=$1
				  AND a.attname=$2 AND a.atttypid=pg_catalog.to_regtype($3)
				  AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull
				  AND NOT a.atthasdef AND a.attgenerated='' AND a.attidentity=''
			)
		`, relation, column.name, column.typ).Scan(&valid)
		if err != nil || !valid {
			return fmt.Errorf("current Attempt catalog column drift: %s err=%v", column.name, err)
		}
	}
	for _, expected := range []string{"generation=1", "breaker_epoch=1"} {
		var count int
		err := db.QueryRow(ctx, `
			SELECT count(*) FROM pg_catalog.pg_constraint c
			WHERE c.conrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',current_schema(),$1::text))
			  AND c.contype='c' AND c.convalidated AND c.conislocal
			  AND NOT c.condeferrable AND NOT c.condeferred
			  AND pg_catalog.regexp_replace(pg_catalog.pg_get_expr(c.conbin,c.conrelid),'[[:space:]()]','','g')=$2
		`, relation, expected).Scan(&count)
		if err != nil || count != 1 {
			return fmt.Errorf("current Attempt catalog CHECK drift: %s err=%v", expected, err)
		}
	}
	for _, key := range []struct{ kind, local, remote string }{
		{"p", "tenant_id,run_id", ""},
		{"f", "tenant_id,run_id,attempt_id", "tenant_id,run_id,run_attempt_id"},
	} {
		var valid bool
		err := db.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_constraint c
				JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
				JOIN pg_catalog.pg_namespace ns ON ns.oid=r.relnamespace
				WHERE ns.nspname=current_schema() AND r.relname=$1
				  AND c.contype=$2 AND c.convalidated AND c.conislocal
				  AND NOT c.condeferrable AND NOT c.condeferred
				  AND c.conkey=(
					SELECT pg_catalog.array_agg(a.attnum ORDER BY n.pos)::smallint[]
					FROM pg_catalog.unnest(pg_catalog.string_to_array($3,',')) WITH ORDINALITY n(name,pos)
					JOIN pg_catalog.pg_attribute a ON a.attrelid=r.oid AND a.attname=n.name AND NOT a.attisdropped
				  )
				  AND ((c.contype='p' AND c.confrelid=0 AND EXISTS (
					SELECT 1 FROM pg_catalog.pg_index i WHERE i.indexrelid=c.conindid AND i.indrelid=r.oid
					  AND i.indisvalid AND i.indisready AND i.indislive AND i.indisunique AND i.indimmediate
					  AND i.indpred IS NULL AND i.indexprs IS NULL
				  )) OR (c.contype='f'
					AND c.confrelid=pg_catalog.to_regclass(pg_catalog.format('%I.runtime_run_attempts',current_schema()))
					AND c.confkey=(
					  SELECT pg_catalog.array_agg(a.attnum ORDER BY n.pos)::smallint[]
					  FROM pg_catalog.unnest(pg_catalog.string_to_array($4,',')) WITH ORDINALITY n(name,pos)
					  JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attname=n.name AND NOT a.attisdropped
					)
					AND c.confupdtype='a' AND c.confdeltype='r' AND c.confmatchtype='s'
				  ))
			)
		`, relation, key.kind, key.local, key.remote).Scan(&valid)
		if err != nil || !valid {
			return fmt.Errorf("current Attempt catalog key drift: %s err=%v", key.kind, err)
		}
	}
	migration, err := migrationFiles.ReadFile("migrations/0008_runtime_temporal_execution_identity.up.sql")
	if err != nil {
		return err
	}
	parts := strings.Split(string(migration), "$runtime_execution_identity$")
	if len(parts) != 3 {
		return fmt.Errorf("current Attempt catalog: invalid v8 function source")
	}
	for _, spec := range []struct {
		name string
		mask int
	}{
		{"runtime_current_attempt_no_mutation", 27},
		{"runtime_current_attempt_no_truncate", 34},
	} {
		var valid bool
		err := db.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_trigger tg
				JOIN pg_catalog.pg_class r ON r.oid=tg.tgrelid
				JOIN pg_catalog.pg_namespace ns ON ns.oid=r.relnamespace
				JOIN pg_catalog.pg_proc fn ON fn.oid=tg.tgfoid
				JOIN pg_catalog.pg_language lang ON lang.oid=fn.prolang
				WHERE ns.nspname=current_schema() AND r.relname=$1
				  AND tg.tgname=$2 AND tg.tgtype=$3 AND tg.tgenabled='A'
				  AND NOT tg.tgisinternal AND tg.tgqual IS NULL AND tg.tgattr::text=''
				  AND tg.tgnargs=0 AND tg.tgconstraint=0
				  AND fn.pronamespace=r.relnamespace
				  AND fn.proname='reject_runtime_execution_identity_mutation'
				  AND fn.prosrc=$4 AND NOT fn.prosecdef AND fn.pronargs=0
				  AND fn.prokind='f' AND lang.lanname='plpgsql'
				  AND fn.prorettype='pg_catalog.trigger'::regtype AND fn.proconfig IS NULL
			)
		`, relation, spec.name, spec.mask, parts[1]).Scan(&valid)
		if err != nil || !valid {
			return fmt.Errorf("current Attempt catalog trigger drift: %s err=%v", spec.name, err)
		}
	}
	return nil
}
