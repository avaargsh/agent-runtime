-- v10: freeze the accepted ACP execution binding without freezing lifecycle
-- status/updated_at. Existing legacy Runs cannot be converted by UPDATE.
CREATE FUNCTION enforce_immutable_acp_run_binding() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.run_intent_id IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'runs_acp_binding_immutable',
                MESSAGE = 'accepted ACP Run binding is immutable';
        END IF;
        RETURN OLD;
    END IF;
    IF (OLD.run_intent_id IS NOT NULL OR NEW.run_intent_id IS NOT NULL)
       AND ROW(NEW.run_id, NEW.tenant_id, NEW.agent_id, NEW.agent_release_id,
               NEW.session_id, NEW.idempotency_key, NEW.request_digest,
               NEW.workflow_id, NEW.input, NEW.created_at,
               NEW.run_intent_id, NEW.source_request_digest)
           IS DISTINCT FROM
           ROW(OLD.run_id, OLD.tenant_id, OLD.agent_id, OLD.agent_release_id,
               OLD.session_id, OLD.idempotency_key, OLD.request_digest,
               OLD.workflow_id, OLD.input, OLD.created_at,
               OLD.run_intent_id, OLD.source_request_digest)
    THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'runs_acp_binding_immutable',
            MESSAGE = 'accepted ACP Run binding is immutable';
    END IF;
    RETURN NEW;
END
$body$;

CREATE TRIGGER runs_acp_binding_immutable
BEFORE UPDATE OR DELETE ON runs
FOR EACH ROW EXECUTE FUNCTION enforce_immutable_acp_run_binding();

ALTER TABLE runs ENABLE ALWAYS TRIGGER runs_acp_binding_immutable;
