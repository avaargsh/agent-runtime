CREATE TABLE execution_intents (
    tenant_id       TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    run_id          TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 255),
    turn_id         TEXT NOT NULL CHECK (length(turn_id) BETWEEN 1 AND 255),
    current_revision BIGINT NOT NULL CHECK (current_revision > 0),
    intent_digest   TEXT NOT NULL CHECK (intent_digest ~ '^sha256:[0-9a-f]{64}$'),
    complete        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, run_id, turn_id)
);

CREATE TABLE execution_proposals (
    tenant_id            TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    proposal_id          TEXT NOT NULL CHECK (length(proposal_id) BETWEEN 1 AND 255),
    run_id               TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 255),
    turn_id              TEXT NOT NULL CHECK (length(turn_id) BETWEEN 1 AND 255),
    intent_revision      BIGINT NOT NULL CHECK (intent_revision > 0),
    arguments_digest     TEXT NOT NULL CHECK (arguments_digest ~ '^sha256:[0-9a-f]{64}$'),
    action_request_digest TEXT NOT NULL CHECK (action_request_digest ~ '^sha256:[0-9a-f]{64}$'),
    tool_policy          JSONB NOT NULL CHECK (jsonb_typeof(tool_policy) = 'object'),
    state                TEXT NOT NULL CHECK (state IN (
        'PROPOSED','PREPARED','SUPERSEDED','CANCELLED',
        'COMMIT_AUTHORIZED','SUBMITTED_TO_GUARD'
    )),
    version              BIGINT NOT NULL CHECK (version > 0),
    guard_submission_key TEXT,
    guard_operation_id   TEXT,
    confirmation_actor_id TEXT,
    confirmation_ref     TEXT,
    created_at           TIMESTAMPTZ NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, proposal_id),
    UNIQUE (tenant_id, guard_submission_key),
    UNIQUE (tenant_id, guard_operation_id),
    FOREIGN KEY (tenant_id, run_id, turn_id)
        REFERENCES execution_intents (tenant_id, run_id, turn_id)
        ON DELETE RESTRICT
);

CREATE INDEX execution_proposals_pending_idx
    ON execution_proposals (tenant_id, run_id, turn_id, intent_revision)
    WHERE state IN ('PROPOSED','PREPARED');

CREATE TABLE execution_evidence (
    event_id          UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    proposal_id       TEXT NOT NULL,
    event_type        TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    proposal_version  BIGINT NOT NULL CHECK (proposal_version > 0),
    intent_revision   BIGINT NOT NULL CHECK (intent_revision > 0),
    payload           JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at        TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, proposal_id, event_type, proposal_version),
    FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES execution_proposals (tenant_id, proposal_id)
        ON DELETE RESTRICT
);

CREATE INDEX execution_evidence_proposal_idx
    ON execution_evidence (tenant_id, proposal_id, created_at, event_id);
