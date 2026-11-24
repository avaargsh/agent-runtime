-- v14 makes the durable breaker state machine a database-enforced invariant.
-- This is additive: v4 and all previously applied migrations remain unchanged.
-- The approval identifier is a pre-existing reference required by the Go
-- contract. This trigger does not mint or authenticate external approval.
CREATE FUNCTION enforce_runtime_circuit_breaker_transition() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'CLOSED' OR NEW.epoch <> 1 OR NEW.version <> 1
           OR NEW.last_recovery_evidence_ref <> '' THEN
            RAISE EXCEPTION 'Runtime circuit breaker must be created CLOSED at epoch/version one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.scope_id IS DISTINCT FROM OLD.scope_id THEN
        RAISE EXCEPTION 'Runtime circuit breaker scope is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.epoch <> OLD.epoch + 1 OR NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'Runtime circuit breaker transition must advance epoch and version exactly once'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.updated_at <= OLD.updated_at THEN
        RAISE EXCEPTION 'Runtime circuit breaker transition timestamp must advance'
            USING ERRCODE = '23514';
    END IF;

    IF NOT (
        (OLD.state = 'CLOSED' AND NEW.state = 'OPEN')
        OR (OLD.state = 'OPEN' AND NEW.state = 'HALF_OPEN')
        OR (OLD.state = 'HALF_OPEN' AND NEW.state IN ('OPEN', 'CLOSED'))
    ) THEN
        RAISE EXCEPTION 'Runtime circuit breaker state transition is not supported'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'CLOSED' AND NEW.state = 'OPEN' THEN
        IF NEW.opened_at IS NULL OR NEW.opened_at <= OLD.updated_at
           OR NEW.recovery_approval_id <> ''
           OR NEW.last_recovery_evidence_ref IS DISTINCT FROM OLD.last_recovery_evidence_ref THEN
            RAISE EXCEPTION 'Runtime circuit breaker OPEN transition metadata is invalid'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'OPEN' AND NEW.state = 'HALF_OPEN' THEN
        IF NEW.reason_code IS DISTINCT FROM OLD.reason_code
           OR NEW.trigger_event_id IS DISTINCT FROM OLD.trigger_event_id
           OR NEW.opened_at IS DISTINCT FROM OLD.opened_at
           OR NEW.recovery_approval_id = ''
           OR NEW.last_recovery_evidence_ref IS DISTINCT FROM OLD.last_recovery_evidence_ref THEN
            RAISE EXCEPTION 'Runtime circuit breaker HALF_OPEN transition metadata is invalid'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'HALF_OPEN' AND NEW.state = 'OPEN' THEN
        IF NEW.opened_at IS NULL OR NEW.opened_at <= OLD.updated_at
           OR NEW.recovery_approval_id <> ''
           OR NEW.last_recovery_evidence_ref IS DISTINCT FROM OLD.last_recovery_evidence_ref THEN
            RAISE EXCEPTION 'Runtime circuit breaker reopen metadata is invalid'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state = 'HALF_OPEN' AND NEW.state = 'CLOSED' THEN
        IF NEW.reason_code <> '' OR NEW.trigger_event_id <> ''
           OR NEW.opened_at IS NOT NULL OR NEW.recovery_approval_id <> ''
           OR NEW.last_recovery_evidence_ref = '' THEN
            RAISE EXCEPTION 'Runtime circuit breaker recovery completion metadata is invalid'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$body$;

CREATE FUNCTION reject_runtime_circuit_breaker_mutation() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
    RAISE EXCEPTION 'Runtime circuit breaker rows cannot be deleted or truncated'
        USING ERRCODE = '23514';
END;
$body$;

CREATE TRIGGER runtime_circuit_breaker_transition
BEFORE INSERT OR UPDATE ON runtime_circuit_breakers
FOR EACH ROW EXECUTE FUNCTION enforce_runtime_circuit_breaker_transition();

CREATE TRIGGER runtime_circuit_breaker_no_delete
BEFORE DELETE ON runtime_circuit_breakers
FOR EACH ROW EXECUTE FUNCTION reject_runtime_circuit_breaker_mutation();

CREATE TRIGGER runtime_circuit_breaker_no_truncate
BEFORE TRUNCATE ON runtime_circuit_breakers
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_circuit_breaker_mutation();

ALTER TABLE runtime_circuit_breakers
    ENABLE ALWAYS TRIGGER runtime_circuit_breaker_transition;
ALTER TABLE runtime_circuit_breakers
    ENABLE ALWAYS TRIGGER runtime_circuit_breaker_no_delete;
ALTER TABLE runtime_circuit_breakers
    ENABLE ALWAYS TRIGGER runtime_circuit_breaker_no_truncate;
