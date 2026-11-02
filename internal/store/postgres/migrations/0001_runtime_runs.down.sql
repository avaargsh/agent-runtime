DROP TABLE IF EXISTS runtime_outbox;
DROP TABLE IF EXISTS runs;
DELETE FROM runtime_schema_migrations WHERE version = 1;
