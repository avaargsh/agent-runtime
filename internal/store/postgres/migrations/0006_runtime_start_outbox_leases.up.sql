-- v6 is additive: do not rewrite already-applied Runtime migrations.
-- An unacknowledged Temporal Start is UNKNOWN, not a failed Run.
-- Only ACP-linked RUN_START_REQUESTED rows are eligible for the new worker.
ALTER TABLE runtime_outbox
    ADD COLUMN lease_owner TEXT,
    ADD COLUMN lease_expires_at TIMESTAMPTZ;

ALTER TABLE runtime_outbox
    ADD CONSTRAINT runtime_start_lease_pair CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL)
        OR
        (lease_owner IS NOT NULL AND length(lease_owner) BETWEEN 1 AND 128
         AND lease_expires_at IS NOT NULL)
    );

CREATE INDEX runtime_outbox_start_claim_idx
    ON runtime_outbox (available_at, created_at, outbox_id)
    WHERE delivered_at IS NULL AND event_type = 'RUN_START_REQUESTED';
