CREATE TABLE runs (
    run_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    agent_id TEXT NOT NULL CHECK (length(agent_id) BETWEEN 1 AND 255),
    agent_release_id TEXT NOT NULL CHECK (length(agent_release_id) BETWEEN 1 AND 255),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 255),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 255),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    workflow_id TEXT NOT NULL UNIQUE CHECK (length(workflow_id) BETWEEN 1 AND 512),
    status TEXT NOT NULL CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    input JSONB NOT NULL CHECK (jsonb_typeof(input) = 'object'),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT runs_tenant_idempotency_key_unique UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX runs_tenant_created_at_idx
    ON runs (tenant_id, created_at DESC);

CREATE TABLE runtime_outbox (
    outbox_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    aggregate_id UUID NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    delivered_at TIMESTAMPTZ,
    last_error TEXT,
    CONSTRAINT runtime_outbox_aggregate_event_unique UNIQUE (tenant_id, aggregate_id, event_type)
);

CREATE INDEX runtime_outbox_pending_idx
    ON runtime_outbox (available_at, created_at)
    WHERE delivered_at IS NULL;
