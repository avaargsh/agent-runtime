CREATE TABLE runtime_turn_intents (
    tenant_id       TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    run_id          UUID NOT NULL,
    turn_id         TEXT NOT NULL CHECK (length(turn_id) BETWEEN 1 AND 255),
    intent_revision BIGINT NOT NULL CHECK (intent_revision > 0),
    intent_complete BOOLEAN NOT NULL,
    version         BIGINT NOT NULL CHECK (version > 0),
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, run_id, turn_id),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES runs (tenant_id, run_id) ON DELETE RESTRICT
);

CREATE TABLE runtime_proposals (
    tenant_id             TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    proposal_id           TEXT NOT NULL CHECK (length(proposal_id) BETWEEN 1 AND 255),
    run_id                UUID NOT NULL,
    turn_id               TEXT NOT NULL,
    intent_revision       BIGINT NOT NULL CHECK (intent_revision > 0),
    arguments_digest      TEXT NOT NULL CHECK (arguments_digest ~ '^sha256:[0-9a-f]{64}$'),
    action_request_digest TEXT NOT NULL CHECK (action_request_digest ~ '^sha256:[0-9a-f]{64}$'),
    tool_policy           JSONB NOT NULL CHECK (jsonb_typeof(tool_policy) = 'object'),
    state                 TEXT NOT NULL CHECK (state IN (
        'PROPOSED', 'PREPARED', 'SUPERSEDED', 'CANCELLED',
        'COMMIT_AUTHORIZED', 'SUBMITTED_TO_GUARD'
    )),
    version               BIGINT NOT NULL CHECK (version > 0),
    guard_submission_key  TEXT NOT NULL DEFAULT '',
    guard_operation_id    TEXT NOT NULL DEFAULT '',
    confirmation_actor_id TEXT NOT NULL DEFAULT '',
    confirmation_ref      TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, proposal_id),
    FOREIGN KEY (tenant_id, run_id, turn_id)
        REFERENCES runtime_turn_intents (tenant_id, run_id, turn_id) ON DELETE RESTRICT,
    CHECK (
        (state IN ('COMMIT_AUTHORIZED', 'SUBMITTED_TO_GUARD') AND guard_submission_key <> '')
        OR (state NOT IN ('COMMIT_AUTHORIZED', 'SUBMITTED_TO_GUARD') AND guard_submission_key = '')
    ),
    CHECK (
        (state = 'SUBMITTED_TO_GUARD' AND guard_operation_id <> '')
        OR (state <> 'SUBMITTED_TO_GUARD' AND guard_operation_id = '')
    ),
    CHECK (
        (confirmation_actor_id = '' AND confirmation_ref = '')
        OR (confirmation_actor_id <> '' AND confirmation_ref <> '')
    )
);

CREATE UNIQUE INDEX runtime_proposals_guard_submission_key_idx
    ON runtime_proposals (tenant_id, guard_submission_key)
    WHERE guard_submission_key <> '';

CREATE UNIQUE INDEX runtime_proposals_guard_operation_idx
    ON runtime_proposals (tenant_id, guard_operation_id)
    WHERE guard_operation_id <> '';

CREATE INDEX runtime_proposals_turn_state_idx
    ON runtime_proposals (tenant_id, run_id, turn_id, state, intent_revision);

CREATE TABLE runtime_execution_outbox (
    event_id          UUID PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    run_id            UUID NOT NULL,
    turn_id           TEXT NOT NULL,
    aggregate_type    TEXT NOT NULL CHECK (aggregate_type IN ('TURN_INTENT', 'TOOL_PROPOSAL')),
    proposal_id       TEXT NOT NULL DEFAULT '',
    aggregate_version BIGINT NOT NULL CHECK (aggregate_version > 0),
    event_type        TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    payload           JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at        TIMESTAMPTZ NOT NULL,
    delivered_at      TIMESTAMPTZ,
    attempts          INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    CHECK (
        (aggregate_type = 'TURN_INTENT' AND proposal_id = '')
        OR (aggregate_type = 'TOOL_PROPOSAL' AND proposal_id <> '')
    ),
    FOREIGN KEY (tenant_id, run_id, turn_id)
        REFERENCES runtime_turn_intents (tenant_id, run_id, turn_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX runtime_execution_outbox_turn_version_idx
    ON runtime_execution_outbox (tenant_id, run_id, turn_id, aggregate_version)
    WHERE aggregate_type = 'TURN_INTENT';

CREATE UNIQUE INDEX runtime_execution_outbox_proposal_version_idx
    ON runtime_execution_outbox (tenant_id, proposal_id, aggregate_version)
    WHERE aggregate_type = 'TOOL_PROPOSAL';

CREATE INDEX runtime_execution_outbox_pending_idx
    ON runtime_execution_outbox (created_at)
    WHERE delivered_at IS NULL;
