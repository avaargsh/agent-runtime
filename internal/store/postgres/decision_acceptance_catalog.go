package postgres

import (
	"context"
	"fmt"
)

// This attestation runs after the v12 migration (including on already-applied
// databases). Immutable triggers alone do not prove that an owner has kept
// the receipt/authority equality and referential constraints intact.
func verifyDecisionAcceptanceStructure(ctx context.Context, db harnessCatalogReader) error {
	const relation = "runtime_decision_acceptances"
	var columnCount, checkCount, keyCount int
	if err := db.QueryRow(ctx, `SELECT
        (SELECT count(*) FROM pg_catalog.pg_attribute a
         WHERE a.attrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',current_schema(),$1::text))
           AND a.attnum>0 AND NOT a.attisdropped),
        (SELECT count(*) FROM pg_catalog.pg_constraint c
         WHERE c.conrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',current_schema(),$1::text))
           AND c.contype='c'),
        (SELECT count(*) FROM pg_catalog.pg_constraint c
         WHERE c.conrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',current_schema(),$1::text))
           AND c.contype IN ('p','u','f'))`, relation).Scan(&columnCount, &checkCount, &keyCount); err != nil {
		return fmt.Errorf("verify decision acceptance schema counts: %w", err)
	}
	if columnCount != 10 || checkCount != 12 || keyCount != 5 {
		return fmt.Errorf("decision acceptance schema drift: columns=%d checks=%d keys=%d", columnCount, checkCount, keyCount)
	}
	// Exact types and nullability prevent a reused name or weakened constraint
	// from masquerading as the versioned v12 receipt record.
	columns := []struct {
		name, typ string
		defaulted bool
	}{
		{"run_id", "uuid", false},
		{"tenant_id", "text", false},
		{"turn_id", "uuid", false},
		{"decision_id", "text", false},
		{"record_sha256", "text", false},
		{"plan_hash", "text", false},
		{"breaker_epoch", "bigint", false},
		{"breaker_version", "bigint", false},
		{"receipt", "jsonb", false},
		{"created_at", "timestamp with time zone", true},
	}
	for _, c := range columns {
		var valid bool
		err := db.QueryRow(ctx, `SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute a
            JOIN pg_catalog.pg_class r ON r.oid=a.attrelid
            JOIN pg_catalog.pg_namespace ns ON ns.oid=r.relnamespace
            LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=r.oid AND d.adnum=a.attnum
            WHERE ns.nspname=current_schema() AND r.relname=$1
              AND r.relkind='r' AND r.relpersistence='p'
              AND a.attname=$2 AND a.attnum>0 AND NOT a.attisdropped
              AND a.atttypid=pg_catalog.to_regtype($3) AND a.attnotnull
              AND a.attgenerated='' AND a.attidentity=''
              AND (CASE WHEN $4::boolean
                        THEN a.atthasdef AND pg_catalog.pg_get_expr(d.adbin,d.adrelid)='clock_timestamp()'
                        ELSE NOT a.atthasdef END)
        )`, relation, c.name, c.typ, c.defaulted).Scan(&valid)
		if err != nil {
			return fmt.Errorf("verify decision acceptance column %s: %w", c.name, err)
		}
		if !valid {
			return fmt.Errorf("decision acceptance column drift: %s", c.name)
		}
	}
	// Deparser-independent formatting: trim whitespace, surplus parentheses
	// and implicit ::text casts; compare entire CHECK predicates, not names.
	// Replacing any CHECK by CHECK(TRUE), even with the same name, must fail.
	expectedChecks := []string{
		"decision_id~'^dec_[0-9a-f]{64}$'",
		"record_sha256~'^[0-9a-f]{64}$'",
		"plan_hash~'^[0-9a-f]{64}$'",
		"receipt->>'schema_version'ISNOTDISTINCTFROM'decision.continuation.v1'",
		"receipt->'authority'->>'tenant_id'ISNOTDISTINCTFROMtenant_id",
		"receipt->'authority'->>'run_id'ISNOTDISTINCTFROMrun_id",
		"receipt->'authority'->>'turn_id'ISNOTDISTINCTFROMturn_id",
		"receipt->>'decision_id'ISNOTDISTINCTFROMdecision_id",
		"receipt->>'record_sha256'ISNOTDISTINCTFROMrecord_sha256",
		"receipt->>'plan_hash'ISNOTDISTINCTFROMplan_hash",
		"receipt->'authority'->>'breaker_epoch'ISNOTDISTINCTFROMbreaker_epoch",
		"receipt->'authority'->>'breaker_version'ISNOTDISTINCTFROMbreaker_version",
	}
	for _, expected := range expectedChecks {
		var matches int
		err := db.QueryRow(ctx, `SELECT count(*)
            FROM pg_catalog.pg_constraint c
            WHERE c.conrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',current_schema(),$1::text))
              AND c.contype='c' AND c.convalidated
              AND NOT c.condeferrable AND NOT c.condeferred AND c.conislocal
              AND pg_catalog.regexp_replace(
                 pg_catalog.replace(pg_catalog.pg_get_expr(c.conbin,c.conrelid),'::text',''),
                 '[[:space:]()]','','g')=$2`, relation, expected).Scan(&matches)
		if err != nil {
			return fmt.Errorf("verify decision acceptance CHECK: %w", err)
		}
		if matches != 1 {
			return fmt.Errorf("decision acceptance CHECK drift: %s (matches=%d)", expected, matches)
		}
	}
	keys := []struct{ name, kind, local, target, remote string }{
		{"runtime_decision_acceptances_pkey", "p", "run_id", "", ""},
		{"runtime_decision_acceptances_turn_id_key", "u", "turn_id", "", ""},
		{"runtime_decision_acceptances_run_id_fkey", "f", "run_id", "runtime_decision_checkpoints", "run_id"},
		{"runtime_decision_acceptances_turn_id_fkey", "f", "turn_id", "runtime_decision_turns", "turn_id"},
		{"runtime_decision_acceptances_tenant_id_run_id_fkey", "f", "tenant_id,run_id", "runs", "tenant_id,run_id"},
	}
	for _, k := range keys {
		var valid bool
		err := db.QueryRow(ctx, `SELECT EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint c
            JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
            JOIN pg_catalog.pg_namespace ns ON ns.oid=r.relnamespace
            WHERE ns.nspname=current_schema() AND r.relname=$1
              AND c.conname=$2 AND c.contype=$3
              AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred AND c.conislocal
              AND c.conkey=(
                SELECT pg_catalog.array_agg(a.attnum ORDER BY names.pos)::smallint[]
                FROM pg_catalog.unnest(pg_catalog.string_to_array($4,',')) WITH ORDINALITY names(name,pos)
                JOIN pg_catalog.pg_attribute a ON a.attrelid=r.oid AND a.attname=names.name AND NOT a.attisdropped
              )
              AND ((
                c.contype IN ('p','u') AND c.confrelid=0 AND EXISTS (
                  SELECT 1 FROM pg_catalog.pg_index i WHERE i.indexrelid=c.conindid
                  AND i.indrelid=r.oid AND i.indisvalid AND i.indisready
                  AND i.indislive AND i.indisunique AND i.indimmediate
                  AND i.indpred IS NULL AND i.indexprs IS NULL
                )
              ) OR (
                c.contype='f' AND c.confrelid=pg_catalog.to_regclass(
                   pg_catalog.format('%I.%I',current_schema(),$5::text))
                AND c.confkey=(
                  SELECT pg_catalog.array_agg(a.attnum ORDER BY names.pos)::smallint[]
                  FROM pg_catalog.unnest(pg_catalog.string_to_array($6,',')) WITH ORDINALITY names(name,pos)
                  JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attname=names.name AND NOT a.attisdropped
                )
                AND c.confupdtype='a' AND c.confdeltype='r' AND c.confmatchtype='s'
              ))
        )`, relation, k.name, k.kind, k.local, k.target, k.remote).Scan(&valid)
		if err != nil {
			return fmt.Errorf("verify decision acceptance key %s: %w", k.name, err)
		}
		if !valid {
			return fmt.Errorf("decision acceptance key drift: %s", k.name)
		}
	}
	return nil
}
