-- Runtime v8: immutable identity of one Temporal Server execution and its
-- Decision turns. Existing mutable runtime_turn_intents continue to own Tool
-- Proposal revision state; these execution identities are separate.
CREATE TABLE runtime_run_attempts (
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    run_id UUID NOT NULL,
    run_attempt_id UUID NOT NULL PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    temporal_execution_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, run_id, run_attempt_id),
    UNIQUE (run_id, temporal_execution_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES runs (tenant_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id) REFERENCES runtime_run_principal_snapshots (run_id) ON DELETE RESTRICT,
    CHECK (workflow_id = 'agent-run/v1/' || run_id::text)
);

CREATE TABLE runtime_decision_turns (
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    run_id UUID NOT NULL,
    run_attempt_id UUID NOT NULL,
    turn_id UUID NOT NULL PRIMARY KEY,
    invocation_id UUID NOT NULL,
    turn_index INTEGER NOT NULL CHECK (turn_index BETWEEN 1 AND 10000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, run_id, run_attempt_id, turn_index),
    FOREIGN KEY (tenant_id, run_id, run_attempt_id)
        REFERENCES runtime_run_attempts (tenant_id, run_id, run_attempt_id) ON DELETE RESTRICT,
    CHECK (invocation_id = turn_id)
);

CREATE FUNCTION reject_runtime_execution_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $runtime_execution_identity$
BEGIN
    RAISE EXCEPTION 'immutable Runtime Attempt/Turn execution identity';
END
$runtime_execution_identity$;

CREATE TRIGGER runtime_attempt_no_mutation
BEFORE UPDATE OR DELETE ON runtime_run_attempts
FOR EACH ROW EXECUTE FUNCTION reject_runtime_execution_identity_mutation();

CREATE TRIGGER runtime_attempt_no_truncate
BEFORE TRUNCATE ON runtime_run_attempts
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_execution_identity_mutation();

CREATE TRIGGER runtime_turn_no_mutation
BEFORE UPDATE OR DELETE ON runtime_decision_turns
FOR EACH ROW EXECUTE FUNCTION reject_runtime_execution_identity_mutation();

CREATE TRIGGER runtime_turn_no_truncate
BEFORE TRUNCATE ON runtime_decision_turns
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_execution_identity_mutation();
