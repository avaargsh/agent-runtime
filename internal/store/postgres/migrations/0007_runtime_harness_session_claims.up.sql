-- V7: Runtime-owned ACP v1 Harness session creation fence.
-- A PREPARED claim may be granted for dispatch at most once. We persist
-- UNKNOWN BEFORE calling session/new, so a lost ACK can never blind-retry.
-- Preserve migration scripts 0001..0006 without changes.
CREATE TABLE runtime_harness_session_claims (
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    run_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    harness_instance_id TEXT NOT NULL CHECK (length(harness_instance_id) BETWEEN 1 AND 255),
    agent_release_id TEXT NOT NULL CHECK (length(agent_release_id) BETWEEN 1 AND 255),
    policy_revision TEXT NOT NULL CHECK (length(policy_revision) BETWEEN 1 AND 255),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    working_dir TEXT NOT NULL CHECK (length(working_dir) BETWEEN 1 AND 4096 AND left(working_dir, 1) = '/'),
    state TEXT NOT NULL CHECK (state IN ('PREPARED', 'UNKNOWN', 'CONFIRMED')),
    agent_session_id TEXT CHECK (agent_session_id IS NULL OR length(agent_session_id) BETWEEN 1 AND 255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT runtime_harness_session_claim_identity PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT runtime_harness_claim_run_fk FOREIGN KEY (tenant_id, run_id)
        REFERENCES runs (tenant_id, run_id) ON DELETE RESTRICT,
    CONSTRAINT runtime_harness_session_confirmation CHECK (
        (state = 'CONFIRMED') = (agent_session_id IS NOT NULL)
    )
);

-- A concrete Agent session must never be attached to two Runtime Runs
-- in the same pinned Harness instance.
CREATE UNIQUE INDEX runtime_harness_agent_session_unique
    ON runtime_harness_session_claims (harness_instance_id, agent_session_id)
    WHERE agent_session_id IS NOT NULL;

CREATE FUNCTION enforce_runtime_harness_claim_transition() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Runtime harness claim deletion forbidden';
    END IF;
    IF ROW(NEW.tenant_id, NEW.run_id, NEW.attempt_id, NEW.harness_instance_id,
        NEW.agent_release_id, NEW.policy_revision, NEW.request_digest,
        NEW.working_dir, NEW.created_at) IS DISTINCT FROM
       ROW(OLD.tenant_id, OLD.run_id, OLD.attempt_id, OLD.harness_instance_id,
        OLD.agent_release_id, OLD.policy_revision, OLD.request_digest,
        OLD.working_dir, OLD.created_at) THEN
        RAISE EXCEPTION 'Runtime harness claim identity immutable';
    END IF;
    IF OLD.state = 'PREPARED' AND NEW.state = 'UNKNOWN'
       AND OLD.agent_session_id IS NULL AND NEW.agent_session_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'UNKNOWN' AND NEW.state = 'CONFIRMED'
       AND OLD.agent_session_id IS NULL AND NEW.agent_session_id IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'Runtime harness claim transition forbidden';
END
$body$;

CREATE TRIGGER runtime_harness_claim_immutable
BEFORE UPDATE OR DELETE ON runtime_harness_session_claims
FOR EACH ROW EXECUTE FUNCTION enforce_runtime_harness_claim_transition();

CREATE FUNCTION reject_runtime_harness_claim_truncate() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
    RAISE EXCEPTION 'Runtime harness claim TRUNCATE forbidden';
END
$body$;

CREATE TRIGGER runtime_harness_claim_no_truncate
BEFORE TRUNCATE ON runtime_harness_session_claims
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_harness_claim_truncate();
