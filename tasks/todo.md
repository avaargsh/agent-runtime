# Agent Runtime Tasks

## Verified baseline

- [x] Initial Go Temporal Decision Activity / Workflow / Worker / Starter spike passes GitHub Actions Run [41435829765](https://github.com/avaargsh/agent-runtime/actions/runs/41435829765) on commit `a9a6b50748948db407f3dcff4306ccd476eb9cd3`.
- [ ] Real Temporal Server execution, replay and Worker restart are still unverified.
- [ ] PostgreSQL, Run idempotency, Event Inbox/Outbox and Guard UNKNOWN recovery are not implemented in the inspected PR #2 tree.

## Gate A — Durable Run and events (P0)

- [ ] Add PostgreSQL-backed canonical Run / Task / Attempt metadata and idempotent StartRun.
- [ ] Enforce stable Workflow ID derived from canonical Run ID and reject idempotency-key/request-digest conflicts.
- [ ] Add transactional Event Inbox + Outbox; ACK only after commit.
- [ ] Enforce tenant/Run ownership, event ID deduplication and changed-payload conflict rejection.
- [ ] Make Temporal Signal delivery idempotent by event ID across dispatcher restart.
- [ ] Add PostgreSQL migration, concurrency and restart integration tests.

## Gate B — Durable Temporal execution (P0)

- [ ] Add real Temporal Server integration tests.
- [ ] Verify Worker stop/start and Workflow history replay.
- [ ] Verify Activity retry against stable invocation identity and bounded deadlines.
- [ ] Add cancellation propagation and terminal Run behavior.

## Gate C — Guarded side effects (P0)

- [ ] Add a versioned Runtime-to-EngageGuard client/Activity.
- [ ] Bind operation_id, action_hash, attempt_id and receipt_id to the originating Run/Task.
- [ ] Validate receipt identity, schema and status before updating Runtime projections.
- [ ] Treat UNKNOWN / RECONCILING / MANUAL_REVIEW as fail-closed; never create a new operation for blind retry.
- [ ] Add lost-ACK, process-crash and reconciliation integration tests.

## Gate D — Cross-plane Golden Path (P1)

- [ ] Add Runtime Adapter SPI and Worker registration/heartbeat/capability discovery.
- [ ] Add Session Runtime Binding that survives Worker restart and migration.
- [ ] Bind Compute Allocation by reference; do not own Provider/Allocation lifecycle.
- [ ] Persist execution result and Evidence references.
- [ ] Verify cancellation, resource release observation and recovery.

## Legacy migration track — separate repository

- [ ] Audit `musuntana/cloud-agent-runtime` SQLite decoupling and storage contract.
- [ ] Verify legacy ProviderOperationJournal adapter semantics before migration or reuse.
- [ ] Keep SQLite out of this Go repository; use PostgreSQL/pgx as the target persistence backend.
