# Agent Runtime Tasks

## Verified architecture foundation

- [x] Define Runtime ↔ Decision ↔ EngageGuard ownership and identifier semantics.
- [x] Pin the canonical Agent Decision v0.1 protocol revision.
- [x] Specify per-Activity retry and UNKNOWN handling rules.
- [x] Add fail-closed Guard status/retry decision unit tests (pure Go; no provider I/O).
- [x] Add PostgreSQL-backed RunStore and idempotent Runtime RunIntent acceptance (stacked implementation; real deployment acceptance remains separate).
- [x] Add internal mTLS-verified ACP RunIntent accept / inspect boundary (network deployment and authenticated ACP producer acceptance remain separate).

## Gate A — Durable Run and events (P0)

- [x] Add PostgreSQL-backed Run metadata, stable RunIntent mapping and idempotent StartRun.
- [x] Enforce stable Workflow ID derived from canonical Run ID and reject idempotency-key/request-digest conflicts.
- [ ] Complete durable Outbox delivery to Temporal and Event Inbox deduplication / ordering / gap recovery.
- [ ] Add real PostgreSQL + Temporal restart and lost-ACK integration tests on the complete end-to-end path.

## Gate B — Durable Temporal execution (P0)

- [ ] Verify real Temporal Server execution, Workflow replay and Worker stop/start recovery.
- [ ] Verify Activity retry against stable invocation identity and bounded deadlines.
- [ ] Add cancellation propagation and terminal Run behavior backed by owning-operation outcomes.

## Gate C — Guarded side effects (P0)

- [ ] Ratify the actual EngageGuard request / receipt / idempotency contract against the deployed service.
- [ ] Add a versioned Runtime-to-EngageGuard client / Activity.
- [ ] Bind Guard operation_id, action_hash, executor attempt_id and receipt_id to the originating Run / Task / Proposal.
- [ ] Validate receipt identity, schema and status before updating Runtime projections.
- [ ] Treat UNKNOWN / RECONCILING / MANUAL_REVIEW as fail-closed; never create a new operation for blind retry.
- [ ] Add lost-ACK, process-crash and authoritative reconciliation integration tests.

## Gate D — Agent Execution Safety Commit Protocol (P0)

- [x] Define Proposal / Prepare / Runtime Commit Boundary / Guard execution ownership in the Agent Execution Safety RFC.
- [x] Add a pure-Go Runtime Proposal state model with stale-revision, admission, confirmation and idempotency checks.
- [x] Add Alice admin-to-read-only correction Golden Path with a Guard test double and Evidence assertions.
- [ ] Persist Proposal state, immutable ActionRequest digest, stable Guard submission key and commit Evidence atomically in Runtime PostgreSQL.
- [ ] Wire Proposal / Prepare / Commit / recovery into deterministic Temporal Workflow + Activities.
- [ ] Run exact-head unit/race/vet CI and then real PostgreSQL / Temporal / EngageGuard fault-injection acceptance.

## Gate E — Cross-plane Golden Path (P1)

- [ ] Add Runtime Adapter SPI and Worker registration / heartbeat / capability discovery.
- [ ] Add Session Runtime Binding that survives Worker restart and migration.
- [ ] Bind Compute Allocation by reference; do not own Provider / Allocation lifecycle.
- [ ] Persist execution result and Evidence references; project versioned events to ACP.
- [ ] Verify cancellation, resource release observation and recovery.
- [ ] Add Voice Agent architecture map and production failure taxonomy as Runtime adapter / observability inputs.

## P2 — Ecosystem capability analysis

- [ ] Compare LiveKit / Telnyx / Cartesia / managed Temporal patterns against Runtime boundaries.
- [ ] Identify reusable components and gaps; do not introduce a second workflow engine, operation journal or provider scheduler.


## Gate F — Coding Agent Runtime Security Boundary (P0/P1, issue #10)

- [x] Define Runtime / ACP / EngageGuard security ownership and canonical identity correlation in the Security Boundary RFC.
- [ ] Propagate trusted SecurityContext through model, tool, subprocess and remote-egress boundaries; reject plugin-supplied identity.
- [ ] Define versioned Runtime SecurityEvent schema and append-only PostgreSQL audit persistence; keep Outbox as delivery only.
- [ ] Audit model request/response metadata, Proposal/tool lifecycle, policy decisions, file/shell/network observations, breaker and recovery events without storing plaintext secrets.
- [ ] Add Run-scoped circuit breaker with monotonic epoch fencing, Temporal cancellation, process/sandbox termination and Guard revocation integration.
- [ ] Add fail-closed enforcement when audit, policy, scanner, Vault or supervisor dependencies are unavailable.
- [ ] Define OutboundProtector / InboundRestorer contracts and encrypted Token Vault adapter.
- [ ] Implement scoped reversible PII tokenization; credentials/private keys/passwords use irreversible redaction or local Secret References.
- [ ] Implement audience/purpose-bound rehydration and reject forged, expired, cross-tenant and cross-Run tokens.
- [ ] Add streaming-boundary, retry, cancellation-race, audit/Vault outage and process-supervisor integration tests.
- [ ] Pass exact-head Go race/vet/format and PostgreSQL / Runtime integration CI before promotion.

## Legacy migration track — separate repository

- [ ] Audit `musuntana/cloud-agent-runtime` SQLite decoupling and storage contract.
- [ ] Verify legacy ProviderOperationJournal adapter semantics before migration or reuse.
- [ ] Keep SQLite out of this Go repository; use PostgreSQL / pgx as the target persistence backend.
