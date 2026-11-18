-- v12: local immutable acceptance of an authenticated Decision proposal.
-- This is not a tool authorization, execution receipt, or terminal outcome.
CREATE TABLE runtime_decision_acceptances (
    run_id UUID PRIMARY KEY REFERENCES runtime_decision_checkpoints (run_id) ON DELETE RESTRICT,
    tenant_id TEXT NOT NULL,
    turn_id UUID NOT NULL UNIQUE REFERENCES runtime_decision_turns (turn_id) ON DELETE RESTRICT,
    decision_id TEXT NOT NULL CHECK (decision_id ~ '^dec_[0-9a-f]{64}$'),
    record_sha256 TEXT NOT NULL CHECK (record_sha256 ~ '^[0-9a-f]{64}$'),
    plan_hash TEXT NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
    breaker_epoch BIGINT NOT NULL CHECK (breaker_epoch > 0),
    breaker_version BIGINT NOT NULL CHECK (breaker_version > 0),
    receipt JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, run_id) REFERENCES runs (tenant_id, run_id) ON DELETE RESTRICT,
    CHECK (receipt->>'schema_version' = 'decision.continuation.v1'),
    CHECK (receipt->'authority'->>'tenant_id' = tenant_id),
    CHECK (receipt->'authority'->>'run_id' = run_id::text),
    CHECK (receipt->'authority'->>'turn_id' = turn_id::text),
    CHECK (receipt->>'decision_id' = decision_id),
    CHECK (receipt->>'record_sha256' = record_sha256),
    CHECK (receipt->>'plan_hash' = plan_hash),
    CHECK (receipt->'authority'->>'breaker_epoch' = breaker_epoch::text),
    CHECK (receipt->'authority'->>'breaker_version' = breaker_version::text)
);

CREATE TRIGGER runtime_decision_acceptance_no_mutation
BEFORE UPDATE OR DELETE ON runtime_decision_acceptances
FOR EACH ROW EXECUTE FUNCTION reject_runtime_decision_checkpoint_mutation();

CREATE TRIGGER runtime_decision_acceptance_no_truncate
BEFORE TRUNCATE ON runtime_decision_acceptances
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_decision_checkpoint_mutation();

ALTER TABLE runtime_decision_acceptances ENABLE ALWAYS TRIGGER runtime_decision_acceptance_no_mutation;
ALTER TABLE runtime_decision_acceptances ENABLE ALWAYS TRIGGER runtime_decision_acceptance_no_truncate;
