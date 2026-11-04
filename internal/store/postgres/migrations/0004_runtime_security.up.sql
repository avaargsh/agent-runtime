CREATE TABLE runtime_security_audit_events (
    tenant_id          TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    event_id           TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 512),
    run_id             TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 255),
    event_type         TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    occurred_at        TIMESTAMPTZ NOT NULL,
    source             TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 512),
    trace_id           TEXT NOT NULL DEFAULT '',
    proposal_id        TEXT NOT NULL DEFAULT '',
    tool_call_id       TEXT NOT NULL DEFAULT '',
    approval_id        TEXT NOT NULL DEFAULT '',
    permit_id          TEXT NOT NULL DEFAULT '',
    guard_operation_id TEXT NOT NULL DEFAULT '',
    payload_digest     TEXT NOT NULL DEFAULT '',
    payload            JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX runtime_security_audit_run_time_idx
    ON runtime_security_audit_events (tenant_id, run_id, occurred_at DESC);

CREATE INDEX runtime_security_audit_type_time_idx
    ON runtime_security_audit_events (tenant_id, event_type, occurred_at DESC);

CREATE INDEX runtime_security_audit_proposal_idx
    ON runtime_security_audit_events (tenant_id, proposal_id, occurred_at DESC)
    WHERE proposal_id <> '';

CREATE OR REPLACE FUNCTION reject_runtime_security_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $security_audit$
BEGIN
    RAISE EXCEPTION 'runtime security audit events are append-only';
END;
$security_audit$;

CREATE TRIGGER runtime_security_audit_no_update_delete
BEFORE UPDATE OR DELETE ON runtime_security_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_runtime_security_audit_mutation();

CREATE TABLE runtime_circuit_breakers (
    scope_kind                 TEXT NOT NULL CHECK (scope_kind IN ('RUN', 'AGENT_INSTANCE', 'TENANT')),
    scope_id                   TEXT NOT NULL CHECK (length(scope_id) BETWEEN 1 AND 512),
    state                      TEXT NOT NULL CHECK (state IN ('CLOSED', 'OPEN', 'HALF_OPEN')),
    epoch                      BIGINT NOT NULL CHECK (epoch > 0),
    version                    BIGINT NOT NULL CHECK (version > 0),
    reason_code                TEXT NOT NULL DEFAULT '',
    trigger_event_id           TEXT NOT NULL DEFAULT '',
    opened_at                  TIMESTAMPTZ,
    recovery_approval_id       TEXT NOT NULL DEFAULT '',
    last_recovery_evidence_ref TEXT NOT NULL DEFAULT '',
    updated_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope_kind, scope_id),
    CHECK (
        (state = 'CLOSED' AND reason_code = '' AND trigger_event_id = ''
            AND opened_at IS NULL AND recovery_approval_id = '')
        OR
        (state = 'OPEN' AND reason_code <> '' AND trigger_event_id <> ''
            AND opened_at IS NOT NULL AND recovery_approval_id = '')
        OR
        (state = 'HALF_OPEN' AND reason_code <> '' AND trigger_event_id <> ''
            AND opened_at IS NOT NULL AND recovery_approval_id <> '')
    )
);

CREATE INDEX runtime_circuit_breakers_state_idx
    ON runtime_circuit_breakers (state, updated_at DESC);
