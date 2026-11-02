-- Additive migration: existing local development Runs keep their unversioned
-- workflow IDs; ACP-sourced RunIntents require the v1 mapping.
ALTER TABLE runs ADD COLUMN run_intent_id UUID;
ALTER TABLE runs ADD COLUMN source_request_digest TEXT;
ALTER TABLE runs ADD CONSTRAINT runs_intent_unique UNIQUE (run_intent_id);
-- PostgreSQL may generate runs_workflow_id_check1 for an inline CHECK
-- on a UNIQUE column. Resolve the real constraint name, never guess.
DO $acp_migration$
DECLARE check_name text;
BEGIN
  SELECT c.conname INTO check_name
  FROM pg_constraint c
  WHERE c.conrelid = 'runs'::regclass AND c.contype = 'c'
    AND pg_get_constraintdef(c.oid) LIKE '%workflow_id%';
  IF check_name IS NULL THEN
    RAISE EXCEPTION 'legacy Workflow ID CHECK constraint missing';
  END IF;
  EXECUTE format('ALTER TABLE runs DROP CONSTRAINT %I', check_name);
END
$acp_migration$;
ALTER TABLE runs ADD CONSTRAINT runs_workflow_id_check CHECK (
    (run_intent_id IS NULL AND workflow_id = 'agent-run/' || run_id::text)
    OR (run_intent_id IS NOT NULL AND workflow_id = 'agent-run/v1/' || run_id::text)
);
ALTER TABLE runs ADD CONSTRAINT runs_intent_source_binding CHECK (
    (run_intent_id IS NULL AND source_request_digest IS NULL)
    OR (run_intent_id IS NOT NULL AND source_request_digest = 'sha256:' || request_digest)
);
