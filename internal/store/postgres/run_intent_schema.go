package postgres

import (
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/jackc/pgx/v5"
)

// runIntentRelations pins all ACP RunIntent reads and writes to the one
// trusted startup schema. Unqualified names are unsafe because PostgreSQL
// resolves same-named pg_temp relations before ordinary schemas.
func (s *Store) runIntentRelations() (runs, principals, outbox string, err error) {
	_, runs, principals, _, err = s.harnessRelations()
	if err != nil {
		return "", "", "", run.ErrRepositoryUnavailable
	}
	schema := s.pool.Config().ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		schema = "public"
	}
	outbox = pgx.Identifier{schema, "runtime_outbox"}.Sanitize()
	return runs, principals, outbox, nil
}
