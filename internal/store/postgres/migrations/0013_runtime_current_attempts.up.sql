-- v13: generation-one pointer for newly allocated Runtime Attempts.
-- Historical v12 Attempts are not backfilled. No transition or new execution
-- authority is enabled. A future migration must explicitly unlock transitions.
CREATE TABLE runtime_current_attempts (
    tenant_id TEXT NOT NULL,
    run_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation = 1),
    breaker_epoch BIGINT NOT NULL CHECK (breaker_epoch = 1),
    PRIMARY KEY (tenant_id, run_id),
    FOREIGN KEY (tenant_id, run_id, attempt_id)
        REFERENCES runtime_run_attempts (tenant_id, run_id, run_attempt_id) ON DELETE RESTRICT
);

CREATE TRIGGER runtime_current_attempt_no_mutation
BEFORE UPDATE OR DELETE ON runtime_current_attempts
FOR EACH ROW EXECUTE FUNCTION reject_runtime_execution_identity_mutation();

CREATE TRIGGER runtime_current_attempt_no_truncate
BEFORE TRUNCATE ON runtime_current_attempts
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_execution_identity_mutation();

ALTER TABLE runtime_current_attempts ENABLE ALWAYS TRIGGER runtime_current_attempt_no_mutation;
ALTER TABLE runtime_current_attempts ENABLE ALWAYS TRIGGER runtime_current_attempt_no_truncate;
