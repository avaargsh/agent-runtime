-- V5 is additive. Existing databases may already have applied the original
-- v4 security schema, so changing the v4 file cannot install this trigger.
-- Drop/recreate is transactionally safe and also handles ephemeral databases
-- initialized with a prior unmerged version of the v4 script.
DROP TRIGGER IF EXISTS runtime_security_audit_no_truncate
    ON runtime_security_audit_events;

CREATE TRIGGER runtime_security_audit_no_truncate
BEFORE TRUNCATE ON runtime_security_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_runtime_security_audit_mutation();
