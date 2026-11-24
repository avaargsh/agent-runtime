-- v13: immutable Runtime-owned current-Attempt authority generations.
-- The highest committed generation for a tenant+Run is the current Attempt.
-- Old Attempts remain immutable history for reconciliation; this table never
-- grants protected-effect permission or makes remote revocation atomic.
ALTER TABLE runtime_run_attempts
    ADD CONSTRAINT runtime_run_attempt_authority_identity_unique
    UNIQUE (tenant_id, run_id, run_attempt_id, temporal_execution_id);

CREATE TABLE runtime_run_attempt_authorities (
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    run_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    run_attempt_id UUID NOT NULL,
    temporal_execution_id UUID NOT NULL,
    breaker_epoch BIGINT NOT NULL CHECK (breaker_epoch > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, run_id, generation),
    UNIQUE (tenant_id, run_id, run_attempt_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES runs (tenant_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, run_id, run_attempt_id, temporal_execution_id)
        REFERENCES runtime_run_attempts (tenant_id, run_id, run_attempt_id, temporal_execution_id)
        ON DELETE RESTRICT
);

-- Backfill only a provably unambiguous first Attempt on a live Run with the
-- untouched initial breaker. Never infer authority from timestamps or choose
-- among multiple Attempts. Revoked, terminal and missing-breaker Runs stay
-- historical and receive no current authority.
INSERT INTO runtime_run_attempt_authorities (
    tenant_id, run_id, generation, run_attempt_id, temporal_execution_id, breaker_epoch
)
SELECT a.tenant_id, a.run_id, 1, a.run_attempt_id, a.temporal_execution_id, b.epoch
FROM runtime_run_attempts a
JOIN runs r ON r.tenant_id = a.tenant_id AND r.run_id = a.run_id
JOIN runtime_circuit_breakers b
  ON b.scope_kind = 'RUN' AND b.scope_id = a.run_id::text
WHERE r.status IN ('QUEUED', 'RUNNING')
  AND b.state = 'CLOSED' AND b.epoch = 1 AND b.version = 1
  AND NOT EXISTS (
      SELECT 1
      FROM runtime_run_attempts other_attempt
      WHERE other_attempt.tenant_id = a.tenant_id
        AND other_attempt.run_id = a.run_id
        AND other_attempt.run_attempt_id <> a.run_attempt_id
  );

CREATE FUNCTION enforce_runtime_run_attempt_authority_insert() RETURNS trigger
LANGUAGE plpgsql AS $body$
DECLARE
    run_status TEXT;
    breaker_state TEXT;
    current_breaker_epoch BIGINT;
    current_breaker_version BIGINT;
    last_recovery_evidence_ref TEXT;
    current_generation BIGINT;
    previous_breaker_epoch BIGINT;
BEGIN
    SELECT r.status, b.state, b.epoch, b.version, b.last_recovery_evidence_ref
      INTO run_status, breaker_state, current_breaker_epoch, current_breaker_version, last_recovery_evidence_ref
    FROM runs r
    JOIN runtime_circuit_breakers b
      ON b.scope_kind = 'RUN' AND b.scope_id = r.run_id::text
    WHERE r.tenant_id = NEW.tenant_id AND r.run_id = NEW.run_id
    FOR UPDATE OF r FOR SHARE OF b;

    IF NOT FOUND OR run_status NOT IN ('QUEUED', 'RUNNING')
       OR breaker_state <> 'CLOSED'
       OR current_breaker_epoch <> NEW.breaker_epoch THEN
        RAISE EXCEPTION 'Runtime Attempt authority requires an active Run and matching CLOSED breaker epoch';
    END IF;

    SELECT COALESCE(MAX(generation), 0), COALESCE(MAX(breaker_epoch), 0)
      INTO current_generation, previous_breaker_epoch
    FROM runtime_run_attempt_authorities
    WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id;

    IF NEW.generation <> current_generation + 1 THEN
        RAISE EXCEPTION 'Runtime Attempt authority generation must be contiguous';
    END IF;
    IF current_generation = 0 AND (NEW.breaker_epoch <> 1 OR current_breaker_version <> 1) THEN
        RAISE EXCEPTION 'initial Runtime Attempt authority must use breaker epoch/version 1';
    END IF;
    IF current_generation > 0 AND (
        NEW.breaker_epoch < previous_breaker_epoch + 3
        OR last_recovery_evidence_ref IS NULL
        OR last_recovery_evidence_ref = ''
    ) THEN
        RAISE EXCEPTION 'Runtime Attempt authority generation requires a completed, evidenced breaker recovery';
    END IF;

    RETURN NEW;
END
$body$;

CREATE FUNCTION reject_runtime_run_attempt_authority_mutation() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
    RAISE EXCEPTION 'Runtime Attempt authority generations are append-only';
END
$body$;

CREATE TRIGGER runtime_run_attempt_authority_insert_guard
BEFORE INSERT ON runtime_run_attempt_authorities
FOR EACH ROW EXECUTE FUNCTION enforce_runtime_run_attempt_authority_insert();

CREATE TRIGGER runtime_run_attempt_authority_no_mutation
BEFORE UPDATE OR DELETE ON runtime_run_attempt_authorities
FOR EACH ROW EXECUTE FUNCTION reject_runtime_run_attempt_authority_mutation();

CREATE TRIGGER runtime_run_attempt_authority_no_truncate
BEFORE TRUNCATE ON runtime_run_attempt_authorities
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_run_attempt_authority_mutation();

ALTER TABLE runtime_run_attempt_authorities ENABLE ALWAYS TRIGGER runtime_run_attempt_authority_insert_guard;
ALTER TABLE runtime_run_attempt_authorities ENABLE ALWAYS TRIGGER runtime_run_attempt_authority_no_mutation;
ALTER TABLE runtime_run_attempt_authorities ENABLE ALWAYS TRIGGER runtime_run_attempt_authority_no_truncate;
