package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/jackc/pgx/v5"
)

// AcceptDecisionContinuation is a local CAS, not a remote authority verifier.
// The trusted worker must obtain receipt over the authenticated fresh Decision
// endpoint immediately before this call. No caller-supplied receipt is an
// authorization. A later protected operation still requires Guard checks.
func (s *Store) AcceptDecisionContinuation(ctx context.Context, expected run.DecisionAuthority, receipt run.DecisionContinuationReceipt) (run.DecisionContinuationReceipt, error) {
	var empty run.DecisionContinuationReceipt
	if expected.Validate() != nil || receipt.Validate() != nil || receipt.Authority != expected {
		return empty, run.ErrDecisionPreparationDenied
	}
	rel, err := s.checkpointRelations()
	if err != nil {
		return empty, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	current, err := readDecisionAuthority(ctx, tx, rel, expected.TenantID, expected.RunID, expected.InvocationID, true)
	if err != nil {
		return empty, err
	}
	if current != expected {
		return empty, run.ErrDecisionPreparationDenied
	}
	schema := s.pool.Config().ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		schema = "public"
	}
	table := pgx.Identifier{schema, "runtime_decision_acceptances"}.Sanitize()
	raw, err := json.Marshal(receipt)
	if err != nil {
		return empty, run.ErrDecisionPreparationDenied
	}
	// One immutable accepted record per Run. Repeating an exact commit can
	// recover its ACK, but a different record cannot replace it.
	_, err = tx.Exec(ctx, fmt.Sprintf(`
		INSERT INTO %s (run_id,tenant_id,turn_id,decision_id,record_sha256,plan_hash,breaker_epoch,breaker_version,receipt)
		VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9::jsonb)
		ON CONFLICT (run_id) DO NOTHING
	`, table), current.RunID, current.TenantID, current.TurnID, receipt.DecisionID,
		receipt.RecordSHA256, receipt.PlanHash, current.BreakerEpoch, current.BreakerVersion, string(raw))
	if err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	var stored []byte
	err = tx.QueryRow(ctx, fmt.Sprintf(`SELECT receipt FROM %s WHERE tenant_id=$1 AND run_id=$2::uuid`, table),
		current.TenantID, current.RunID).Scan(&stored)
	if err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	var got run.DecisionContinuationReceipt
	if json.Unmarshal(stored, &got) != nil || got.Validate() != nil || got != receipt {
		return empty, run.ErrDecisionPreparationDenied
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, run.ErrRepositoryUnavailable
	}
	return got, nil
}
