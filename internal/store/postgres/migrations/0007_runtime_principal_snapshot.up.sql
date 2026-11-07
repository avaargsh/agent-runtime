-- Runtime v7: proposed ACP principal/policy acceptance snapshot. This table
-- is deliberately additive; legacy Runs remain without verified claims and
-- MUST NOT be eligible for an execution-start Outbox claim.
CREATE TABLE runtime_run_principal_snapshots (
    run_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    issuer_spiffe_id TEXT NOT NULL CHECK (issuer_spiffe_id LIKE 'spiffe://%'),
    snapshot_version TEXT NOT NULL CHECK (snapshot_version = 'acp-principal/v1'),
    project_id TEXT NOT NULL CHECK (length(project_id) BETWEEN 1 AND 255),
    subject_id TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 255),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 255),
    policy_revision TEXT NOT NULL CHECK (length(policy_revision) BETWEEN 1 AND 255),
    config_digest TEXT NOT NULL CHECK (config_digest ~ '^sha256:[0-9a-f]{64}$'),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT runtime_principal_run_fk FOREIGN KEY (tenant_id, run_id)
        REFERENCES runs (tenant_id, run_id) ON DELETE RESTRICT
);

CREATE FUNCTION reject_runtime_principal_mutation() RETURNS trigger
LANGUAGE plpgsql AS $principal$
BEGIN
    RAISE EXCEPTION 'immutable Runtime principal snapshot';
END
$principal$;

CREATE TRIGGER runtime_principal_no_row_mutation
BEFORE UPDATE OR DELETE ON runtime_run_principal_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_runtime_principal_mutation();

CREATE TRIGGER runtime_principal_no_truncate
BEFORE TRUNCATE ON runtime_run_principal_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_principal_mutation();
