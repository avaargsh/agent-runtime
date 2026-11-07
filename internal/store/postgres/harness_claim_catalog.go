package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// harnessCatalogReader accepts the schema-migration transaction so attestation
// sees the same PostgreSQL snapshot as the v7 migration ledger.
type harnessCatalogReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type harnessGuardSpec struct {
	triggerName  string
	functionName string
	triggerType  int // PostgreSQL tgtype bitmask: ROW=1, BEFORE=2, DELETE=8, UPDATE=16, TRUNCATE=32
}

var harnessGuardSpecs = [...]harnessGuardSpec{
	{
		triggerName:  "runtime_harness_claim_immutable",
		functionName: "enforce_runtime_harness_claim_transition",
		triggerType:  1 | 2 | 8 | 16, // BEFORE UPDATE OR DELETE FOR EACH ROW
	},
	{
		triggerName:  "runtime_harness_claim_no_truncate",
		functionName: "reject_runtime_harness_claim_truncate",
		triggerType:  2 | 32, // BEFORE TRUNCATE FOR EACH STATEMENT
	},
}

// verifyHarnessClaimCatalog ensures an existing v7 schema is not accepted only
// because its migration ledger says "applied". The expected PL/pgSQL bodies
// come from the already-committed v7 migration rather than a second hand-
// maintained copy. A change to the migration itself is outside this check.
//
// This is a point-in-time startup/migration attestation, NOT protection against
// an owner changing the schema afterwards. Production still requires a
// separately verified least-privilege role and search_path/pg_temp controls.
func verifyHarnessClaimCatalog(ctx context.Context, db harnessCatalogReader) error {
	migration, err := migrationFiles.ReadFile("migrations/0007_runtime_harness_session_claims.up.sql")
	if err != nil {
		return fmt.Errorf("Harness claim catalog: read v7 migration: %w", err)
	}
	for _, spec := range harnessGuardSpecs {
		expectedSource, err := harnessMigrationFunctionSource(string(migration), spec.functionName)
		if err != nil {
			return fmt.Errorf("Harness claim catalog: expected function %s: %w", spec.functionName, err)
		}
		var (
			enabled      string
			triggerType  int
			noWhen       bool
			updateCols   string
			functionName string
			source       string
			securityDef  bool
			language     string
			sameSchema   bool
			argCount     int
			functionKind string
		)
		err = db.QueryRow(ctx, `
			SELECT tg.tgenabled::text, tg.tgtype::integer,
				tg.tgqual IS NULL, tg.tgattr::text,
				fn.proname, fn.prosrc, fn.prosecdef, lang.lanname,
				fn_ns.oid = rel_ns.oid, fn.pronargs, fn.prokind::text
			FROM pg_catalog.pg_trigger AS tg
			JOIN pg_catalog.pg_class AS rel ON rel.oid = tg.tgrelid
			JOIN pg_catalog.pg_namespace AS rel_ns ON rel_ns.oid = rel.relnamespace
			JOIN pg_catalog.pg_proc AS fn ON fn.oid = tg.tgfoid
			JOIN pg_catalog.pg_namespace AS fn_ns ON fn_ns.oid = fn.pronamespace
			JOIN pg_catalog.pg_language AS lang ON lang.oid = fn.prolang
			WHERE rel_ns.nspname = current_schema()
				AND rel.relname = 'runtime_harness_session_claims'
				AND rel.relkind = 'r' AND rel.relpersistence = 'p'
				AND tg.tgname = $1 AND NOT tg.tgisinternal
		`, spec.triggerName).Scan(
			&enabled, &triggerType, &noWhen, &updateCols,
			&functionName, &source, &securityDef, &language,
			&sameSchema, &argCount, &functionKind,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("Harness claim catalog: missing or invalid trigger %s", spec.triggerName)
		}
		if err != nil {
			return fmt.Errorf("Harness claim catalog: inspect trigger %s: %w", spec.triggerName, err)
		}
		if enabled != "O" || triggerType != spec.triggerType || !noWhen ||
			strings.TrimSpace(updateCols) != "" || functionName != spec.functionName ||
			source != expectedSource || securityDef || language != "plpgsql" ||
			!sameSchema || argCount != 0 || functionKind != "f" {
			return fmt.Errorf("Harness claim catalog: protection drift in trigger %s", spec.triggerName)
		}
	}
	return nil
}

// The migration's tagged function body is retained as source-of-truth. The
// complete body must match pg_proc.prosrc; merely checking function names,
// object types or marker substrings is insufficient.
func harnessMigrationFunctionSource(migration string, functionName string) (string, error) {
	startTag := "CREATE FUNCTION " + functionName + "() RETURNS trigger\nLANGUAGE plpgsql AS $body$"
	if strings.Count(migration, startTag) != 1 {
		return "", errors.New("expected exactly one versioned trigger definition")
	}
	offset := strings.Index(migration, startTag) + len(startTag)
	end := strings.Index(migration[offset:], "$body$;")
	if end < 0 {
		return "", errors.New("missing closing PL/pgSQL body marker")
	}
	return migration[offset : offset+end], nil
}
