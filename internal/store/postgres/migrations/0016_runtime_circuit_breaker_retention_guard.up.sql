-- v16 prevents ordinary writers from resetting durable breaker identity.
-- The v14/v15 state-transition trigger and its function body remain unchanged.
CREATE FUNCTION reject_runtime_circuit_breaker_mutation() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
    RAISE EXCEPTION 'Runtime circuit breaker rows cannot be deleted or truncated'
        USING ERRCODE = '23514';
    RETURN NULL;
END;
$body$;

CREATE TRIGGER runtime_circuit_breaker_no_delete
BEFORE DELETE ON runtime_circuit_breakers
FOR EACH ROW EXECUTE FUNCTION reject_runtime_circuit_breaker_mutation();

CREATE TRIGGER runtime_circuit_breaker_no_truncate
BEFORE TRUNCATE ON runtime_circuit_breakers
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_circuit_breaker_mutation();

ALTER TABLE runtime_circuit_breakers
    ENABLE ALWAYS TRIGGER runtime_circuit_breaker_no_delete;
ALTER TABLE runtime_circuit_breakers
    ENABLE ALWAYS TRIGGER runtime_circuit_breaker_no_truncate;
