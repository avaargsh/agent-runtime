-- v11: durable first business-stage fact. No input values, secrets, permit,
-- decision result, or verifier verdict in this checkpoint.
CREATE TABLE runtime_decision_checkpoints (
    run_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    run_intent_id UUID NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    workflow_id TEXT NOT NULL CHECK (workflow_id = 'agent-run/v1/' || run_id::text),
    execution_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    turn_id UUID NOT NULL UNIQUE,
    input_digest TEXT NOT NULL CHECK (input_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_revision TEXT NOT NULL CHECK (length(policy_revision) BETWEEN 1 AND 255),
    config_digest TEXT NOT NULL CHECK (config_digest ~ '^sha256:[0-9a-f]{64}$'),
    phase TEXT NOT NULL CHECK (phase = 'WAITING_AUTHORITY'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, run_id) REFERENCES runs (tenant_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, run_id, attempt_id)
        REFERENCES runtime_run_attempts (tenant_id, run_id, run_attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (turn_id) REFERENCES runtime_decision_turns (turn_id) ON DELETE RESTRICT
);

CREATE FUNCTION reject_runtime_decision_checkpoint_mutation() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
    RAISE EXCEPTION 'immutable Runtime business checkpoint';
END
$body$;

CREATE TRIGGER runtime_decision_checkpoint_no_mutation
BEFORE UPDATE OR DELETE ON runtime_decision_checkpoints
FOR EACH ROW EXECUTE FUNCTION reject_runtime_decision_checkpoint_mutation();

CREATE TRIGGER runtime_decision_checkpoint_no_truncate
BEFORE TRUNCATE ON runtime_decision_checkpoints
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_decision_checkpoint_mutation();

ALTER TABLE runtime_decision_checkpoints ENABLE ALWAYS TRIGGER runtime_decision_checkpoint_no_mutation;
ALTER TABLE runtime_decision_checkpoints ENABLE ALWAYS TRIGGER runtime_decision_checkpoint_no_truncate;
