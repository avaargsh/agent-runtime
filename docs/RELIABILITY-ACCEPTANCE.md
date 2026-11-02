# Runtime Reliability Acceptance

- Status: Draft acceptance contract
- Scope: `avaargsh/agent-runtime`
- Updated: 2026-11-02
- Related: [Runtime baseline](architecture/BASELINE.md), [Agent plugin contract](architecture/AGENT-PLUGIN-CONTRACT.md), [Validation ledger](architecture/VALIDATION.md)

This document turns the reliability review into testable release gates. A row is not complete because an interface or design document exists: implementation, automated verification, and real-environment acceptance are recorded separately.

## 1. Ownership boundaries

The following boundaries are normative for this repository.

| Concern | Authority | Runtime requirement |
|---|---|---|
| Run, Task, Attempt and execution lifecycle | Agent Runtime | Persist canonical Runtime metadata and idempotency in PostgreSQL; expose query projections. |
| Durable workflow history, timers, replay and Activity retry orchestration | Temporal | Keep Workflow code deterministic; perform I/O only in Activities. |
| Agent reasoning and framework state | Managed Python/TypeScript plugin | Execute one bounded Decision Turn; return a versioned FinalResponse or ActionProposal; never execute privileged side effects. |
| Authorization, Permit, external side-effect Operation Journal and reconciliation | EngageGuard | Runtime calls Guard with stable identifiers and consumes its authoritative receipt/status. |
| Compute Provider, Workload and Allocation lifecycle | Compute Control Plane | Runtime stores resource references and observes results; it does not create a competing allocation state machine. |
| Legacy SQLite compatibility | `musuntana/cloud-agent-runtime` migration track | Audit and decouple the legacy storage adapter separately. Do not add SQLite as a second persistence backend to this Go repository. |

### 1.1 Operation Journal is not a Runtime-owned journal

EngageGuard is the authority for `Action`, `Permit`, `OperationJournal`, `ExecutionReceipt` and audit evidence. Runtime must not implement a second authoritative ProviderOperationJournal or independently decide whether an ambiguous external side effect can be retried.

Runtime and EngageGuard correlate records with:

- `operation_id`: stable for one logical protected action.
- `attempt_id`: unique for each concrete execution attempt.
- `action_hash`: binds the authorized action and its parameters.
- `receipt_id`: identifies the authoritative execution receipt.

Runtime may persist an operation reference and a read/query projection for Run recovery. It must not overwrite Guard-owned status or turn an ambiguous result into a confirmed failure.

### 1.2 UNKNOWN is an operation state, not a test result

`UNKNOWN` means the external side effect may have happened, but available evidence is insufficient to prove the outcome.

- Never translate a timeout, lost ACK, worker crash or missing response directly into `FAILED_CONFIRMED`.
- Never create a new `operation_id` to retry an ambiguous action.
- Do not automatically re-dispatch while Guard reports `UNKNOWN`, `RECONCILING` or `MANUAL_REVIEW`.
- Resume only from an authoritative Guard reconciliation result, or through a documented idempotent request using the same `operation_id`.
- If Guard cannot establish the outcome, preserve the unknown state and require later reconciliation or human review.

The Runtime may retry its own idempotent request to Guard only when the same `operation_id` is reused and Guard's deduplication contract makes that request safe. This is not permission to repeat the underlying provider side effect.

## 2. Event Inbox and Temporal delivery contract

Runtime-owned event intake must provide durable at-least-once delivery with consumer-side deduplication. It must not claim exactly-once delivery across PostgreSQL and Temporal.

### 2.1 Minimum event envelope

Every accepted event must be bound to trusted identity and include:

- `event_id`, `tenant_id`, `run_id`, `event_type`, `schema_version`.
- `source`, `occurred_at`, `received_at`, `correlation_id` and trace context.
- A canonical payload digest and either a bounded payload or a durable payload reference.

Tenant and Run ownership must be derived from authenticated context and the canonical Run record; caller-supplied body fields are not proof of ownership.

### 2.2 Required transaction and recovery semantics

1. Validate tenant, Run ownership, event schema and Run lifecycle.
2. In one database transaction, insert the Inbox record and the corresponding Outbox delivery record.
3. Enforce a unique key on the tenant-scoped event identity. The same event ID and same payload digest is an idempotent duplicate. The same event ID with a different digest is a conflict and must be rejected.
4. Return a successful ACK only after the transaction commits.
5. Dispatch the Outbox record to Temporal using the original `event_id`; retry delivery without changing the logical event identity.
6. If the process crashes after Temporal accepts a Signal but before the Outbox is marked delivered, a repeated Signal must be harmless. The Workflow must deduplicate by `event_id` before applying the event.
7. Retain the Inbox/Outbox evidence until the configured delivery and audit retention conditions are satisfied. A cleanup job must not erase unresolved or unacknowledged records.

### 2.3 Minimum failure cases

- Crash before DB commit: no success ACK; redelivery can insert the event.
- Crash after DB commit but before ACK: redelivery is deduplicated.
- Crash after Temporal Signal but before Outbox completion: duplicate Signal is deduplicated in Workflow state.
- Same event ID with changed payload: reject as conflict; do not silently overwrite.
- Cross-tenant or cross-Run event: reject and preserve an auditable denial.
- Event for a terminal Run: reject or route to an explicitly defined late-event policy; never silently reopen the Run.

## 3. Minimum reliability acceptance matrix

Paths marked **planned** are target test locations, not claims that files already exist.

| Gate | Acceptance target | Minimum regression test | Failure condition | Evidence required |
|---|---|---|---|---|
| P0 — Run identity | One logical Run has one stable Runtime ID and Temporal Workflow ID derived from it. | **Planned:** `internal/run/start_test.go`; duplicate StartRun with same tenant/idempotency key and request digest. | Duplicate Run/Workflow created, or same key with different request accepted. | API test, DB unique constraint, Temporal start result and Workflow ID. |
| P0 — Run persistence | Run/Task/Attempt metadata survives API and Worker restarts; Attempt IDs differ while Run ID remains stable. | **Planned:** `internal/store/postgres/run_repository_test.go`; restart and concurrent update tests. | Lost state, cross-Run update, or Attempt overwrites another Attempt. | PostgreSQL integration report, row snapshots, restart log. |
| P0 — Inbox commit/ACK | ACK is returned only after durable Inbox + Outbox commit. | **Planned:** `internal/events/inbox_test.go`; inject failure before and after commit. | ACK before commit or event loss after acknowledged commit. | Transaction test, DB rows and request/ACK trace. |
| P0 — Event deduplication | Same event ID and digest is idempotent; changed digest is a conflict. | **Planned:** `internal/events/inbox_test.go`; concurrent duplicate and payload-conflict tests. | Duplicate business application or silent payload replacement. | Unique-constraint test, conflict response and audit record. |
| P0 — Outbox recovery | Pending delivery survives restart; repeated Temporal Signal is safe. | **Planned:** `internal/events/outbox_test.go`, `internal/workflows/event_dedup_test.go`. | Lost event or duplicate state transition after crash between Signal and delivery mark. | Dispatcher retry log, Workflow history and dedup assertion. |
| P0 — Workflow determinism | Workflow contains no direct DB/network/LLM/filesystem I/O or nondeterministic Go calls. | Existing: `internal/workflows/run_test.go`; **planned:** replay tests with recorded histories. | Replay divergence or I/O from Workflow code. | Unit test, replay test and Temporal history. |
| P0 — Temporal restart | Worker can stop/restart and continue an open Run from Temporal history without changing Run identity. | **Planned:** `internal/integration/temporal/worker_restart_test.go`. | Workflow is lost, duplicated, or restarts from an unsafe initial state. | Real Temporal Server test logs and Workflow history. |
| P0 — Guard receipt contract | Runtime binds every protected action to stable operation/action/attempt identifiers and validates the receipt. | **Planned:** `internal/guard/client_test.go`; malformed, mismatched and stale receipt cases. | Receipt for another Run/action accepted or missing identity accepted. | Contract vectors, request/receipt pair and validation test. |
| P0 — UNKNOWN fail-closed | Lost ACK, timeout or Worker crash cannot trigger a new protected action while Guard is uncertain. | **Planned:** `internal/guard/unknown_recovery_test.go`; crash after dispatch and before receipt persistence. | UNKNOWN becomes ordinary failure or a new operation is dispatched. | Guard Journal record, Runtime projection, reconciliation trace. |
| P0 — PostgreSQL semantics | Unique keys, transactions, row locking and concurrent updates preserve the same contract under multiple Workers. | **Planned:** `internal/integration/postgres/*_test.go`. | Lost update, duplicate operation, partial Inbox/Outbox commit or lock race. | Real PostgreSQL test report and schema/migration evidence. |
| P1 — Plugin contract | Python and TypeScript plugins pass the same versioned schema vectors and remain bounded. | Existing: `internal/decision/client_test.go`; opt-in: `internal/decision/integration_test.go`; **planned:** cross-language contract vectors. | Unknown schema/capability accepted, oversized response accepted, or privileged execution delegated to plugin. | Contract test report and versioned JSON Schema. |
| P1 — Worker lifecycle | Registration, heartbeat, capability, timeout and cancellation are observable and recoverable. | **Planned:** `internal/worker/*_test.go` and Worker integration tests. | Stale Worker receives new work or cancellation is reported before execution stops. | Worker lifecycle trace and fault-injection report. |
| Legacy — SQLite decoupling | Legacy persistence interface can replace SQLite without changing Inbox/Journal semantics. | Separate source-repo contract tests; not part of this Go repository's build. | SQLite assumptions leak through the legacy repository interface or target backend semantics diverge. | Legacy repository commit, adapter contract tests and PostgreSQL evidence. |

## 4. Test and CI mapping

### 4.1 Existing tests and current CI

The current Go workflow is `.github/workflows/go-tests.yml`. Its `test` job runs:

- `go mod tidy` followed by a clean-diff check for `go.mod` and `go.sum`.
- `go test -race -count=1 ./...`.
- `go vet ./...`.
- `gofmt` verification for `cmd` and `internal`.

Existing test files:

- `internal/decision/client_test.go`: HTTP method/path, response validation, endpoint restrictions, redirect rejection and bounded response handling.
- `internal/workflows/run_test.go`: Temporal Workflow unit tests with a mocked Decision Activity.
- `internal/decision/integration_test.go`: opt-in Python plugin HTTP integration test; it is not exercised unless `DECISION_INTEGRATION_URL` is configured.

The current workflow does not provision PostgreSQL or a real Temporal Server. A passing `test` job therefore proves Go module/build/unit-test quality for that commit, not database, Temporal Server, restart or end-to-end recovery behavior.

### 4.2 CI jobs to add when implementation exists

| Planned CI job | Scope | Required exit condition |
|---|---|---|
| `postgres-integration` | Migrations, Run idempotency, Inbox/Outbox, concurrent claims and restart recovery against real PostgreSQL. | All contract and concurrency tests pass; no migration drift. |
| `temporal-integration` | Real Temporal Server, Workflow start conflict policy, Signal deduplication, Worker restart and history replay. | Same Run resumes with the same Workflow ID and no duplicate state transition. |
| `guard-contract` | Guard request/receipt schema, identifier binding, UNKNOWN and reconciliation behavior. | Unknown/mismatched receipt fails closed; no blind replay. |
| `fault-injection` | Crash at DB commit, Signal delivery, Guard dispatch, ACK receipt and projection write boundaries. | Recovery matches the state table in this document. |

Keep fast hermetic tests in the existing Go test job. Run service-backed tests in dedicated jobs, and keep destructive or long-running fault injection as a separately visible gate rather than silently skipping it.

## 5. Evidence levels and reporting rules

Report each capability with three independent evidence levels:

| Level | Meaning | Minimum proof |
|---|---|---|
| S1 — Implemented | Code and schema exist on the reviewed commit. | Commit SHA and code paths. |
| S2 — Automated | The relevant test suite passed on that exact commit. | CI run URL, job, test command and report. |
| S3 — Environment accepted | Real PostgreSQL/Temporal/Guard/Provider environment passed the relevant failure scenarios. | Environment identity, fault-injection trace, persisted records and reconciliation evidence. |

Do not infer S2 from S1 or S3 from S2. `UNKNOWN` is a runtime operation state and must be reported separately from S1/S2/S3.

For every acceptance row, record: commit SHA, PR, CI run, test command, environment, injected failure point, expected result, observed result and evidence references. If an artifact or environment is unavailable, record **UNKNOWN**; do not backfill it from an old PR description or historical test result.

## 6. Current evidence snapshot — 2026-11-02

| Item | Observed evidence | Conclusion |
|---|---|---|
| PR #1 architecture baseline | Draft PR #1 defines Runtime/Temporal authority and the bounded plugin contract; it adds documentation only. | Contract proposal exists; not merged. |
| PR #2 Go Temporal spike | Draft PR #2 adds Go Workflow, Decision Activity, Worker/Starter, tests, module files and CI workflow. | Initial implementation exists; not production Runtime. |
| Go CI | Workflow Run [41435829765](https://github.com/avaargsh/agent-runtime/actions/runs/41435829765) for commit `a9a6b50748948db407f3dcff4306ccd476eb9cd3` completed with `success`. | S2 verified for the current Go test workflow only. |
| PostgreSQL Run store | No PostgreSQL store or integration test is present in the inspected PR #2 tree. | UNKNOWN / not implemented in the inspected branch. |
| Event Inbox / Outbox | No Inbox/Outbox implementation or tests are present in the inspected PR #2 tree. | UNKNOWN / not implemented in the inspected branch. |
| EngageGuard adapter / Operation Journal | No Runtime Guard adapter or receipt/reconciliation integration is present in the inspected PR #2 tree. Journal authority remains EngageGuard-owned. | UNKNOWN / not implemented in the inspected branch. |
| Real Temporal Server, replay and Worker restart | Current tests use Temporal's Workflow test environment; no real-server run was found in the inspected PR #2 evidence. | UNKNOWN. |
| Legacy SQLite decoupling | Belongs to the separate `cloud-agent-runtime` migration track; current legacy repository state was not re-verified for this snapshot. | UNKNOWN. |

This snapshot is intentionally commit-scoped. Update it only when new evidence is read from the corresponding commit, CI run or environment.

## 7. Release gates

### Gate A — Durable Run and events (P0)

- [ ] PostgreSQL-backed Run metadata and idempotent StartRun.
- [ ] Stable `workflow_id` derived from canonical `run_id`.
- [ ] Transactional Inbox + Outbox with tenant/Run validation.
- [ ] Duplicate event and changed-payload conflict behavior.
- [ ] Temporal Signal deduplication after dispatcher crash.
- [ ] PostgreSQL integration and restart tests.

### Gate B — Durable Temporal execution (P0)

- [ ] Real Temporal Server integration.
- [ ] Worker restart and Workflow history replay.
- [ ] Activity retry policy tested against stable invocation identity.
- [ ] Cancellation and deadline propagation.
- [ ] No nondeterministic Workflow code or I/O.

### Gate C — Guarded side effects (P0)

- [ ] Runtime-to-EngageGuard versioned adapter.
- [ ] Stable operation/action/attempt identity binding.
- [ ] Receipt validation and persisted Runtime projection.
- [ ] Lost-ACK UNKNOWN recovery with no blind retry.
- [ ] Reconciliation and manual-review outcomes are visible to Run observers.

### Gate D — Cross-plane Golden Path (P1)

- [ ] Bind Agent/Release/Session context to a Run without taking over their global identity authority.
- [ ] Bind the Run to a Compute Allocation reference.
- [ ] Execute one bounded plugin turn and route protected actions through EngageGuard.
- [ ] Persist result and evidence references.
- [ ] Cancel/finish the Run and observe Compute resource release.
- [ ] Restart Runtime/Worker and recover the same Session/Run binding.

No production-readiness claim is allowed until the relevant P0 gates have S3 evidence. A green unit-test workflow alone is not a release gate for production reliability.
