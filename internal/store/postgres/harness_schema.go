package postgres

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/avaargsh/agent-runtime/internal/harness/acp"
	"github.com/jackc/pgx/v5"
)

// A runtime connection's mutable search_path (including the implicit pg_temp
// precedence) MUST NOT select the authoritative Harness claim or Run table.
// We pin identifiers to the pool's trusted startup configuration instead.
//
// Until a separately authenticated schema config is introduced, accept only
// one unquoted simple schema identifier. No multi-schema search_path, pg_temp,
// pg_catalog, quoted/schema-list expressions or user-supplied schema is valid.
// An absent explicit search_path means the conventional public schema;
// deployments using a different schema must set one pinned startup value.
var harnessSchemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func (s *Store) harnessRelations() (claimTable, runTable string, err error) {
	if s == nil || s.pool == nil {
		return "", "", fmt.Errorf("%w: PostgreSQL pool unavailable", acp.ErrBindingInvalid)
	}
	schema := s.pool.Config().ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		schema = "public"
	}
	if !harnessSchemaName.MatchString(schema) || strings.HasPrefix(schema, "pg_") ||
		schema == "information_schema" {
		return "", "", fmt.Errorf("%w: untrusted or ambiguous Harness schema configuration", acp.ErrBindingInvalid)
	}
	return pgx.Identifier{schema, "runtime_harness_session_claims"}.Sanitize(),
		pgx.Identifier{schema, "runs"}.Sanitize(), nil
}
