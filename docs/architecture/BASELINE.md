# Agent Runtime Baseline

Status: Proposed v0.1

## Authority

Runtime owns Run, Task, Runtime Attempt, Decision Turn coordination, and execution lifecycle. Temporal owns durable Workflow history, replay, timers, Workflow Task dispatch, and Activity retry orchestration. Runtime PostgreSQL stores canonical Run metadata, the unique run_intent_id → run_id mapping, start idempotency, correlation records, and query projections; it does not duplicate Temporal history or EngageGuard's Action Operation Journal or Compute CP's provider journal.

## Temporal / Agent Framework split

Go Temporal Workflow coordinates deterministic lifecycle only. It performs no direct I/O, network calls, DB calls, LLM inference, or filesystem operations. Activities perform I/O and invoke managed plugins/services. Agent Decision executes one bounded Decision Turn and returns FinalResponse, ActionProposal list, or NeedsInput. Framework state must not become canonical platform Run state.

## Workflow

Start Run → Temporal Workflow → invoke Decision Activity → validate complete response → for each proposal submit an idempotent ActionRequest to EngageGuard → wait for approval / operation result → persist Runtime projection.

Runtime never invokes a protected executor directly. EngageGuard owns authorization, Permit claim, Action Operation Journal, action-level UNKNOWN and trusted-executor receipt. Compute CP owns compute provider dispatch, compute_operation_id and provider UNKNOWN reconciliation.

## Identity

Stable `workflow_id` is `agent-run/v1/<run_id>`; Runtime guarantees `run_id` is globally unique within the Temporal namespace and does not generate a random Workflow ID per retry. `invocation_id` identifies one logical Decision Turn and is stable across Activity retries. `run_attempt_id` identifies a Runtime-owned Task/Run execution attempt; Temporal Activity retry counters are not business IDs. Runtime persists one `guard_submission_key` (ActionRequest `Idempotency-Key`) per admitted proposal; EngageGuard creates the authoritative `operation_id`, owns the record and its `executor_attempt_id` (receipt wire field `attempt_id`). Run start idempotency is keyed by the upstream `run_intent_id` + canonical request digest and enforced by Runtime DB; Runtime derives the Workflow ID and applies an explicit Temporal conflict/reuse policy.

## Determinism

Workflow code uses only SDK deterministic APIs. No wall-clock reads, random generation, network, DB, filesystem, or direct goroutines/channels in Workflow code. All I/O and ID generation happen in Activities or before Workflow start and are supplied as durable inputs. Version Workflow changes with Temporal patching/worker deployment discipline. Inputs/results are versioned and serializable.

## Retry ownership

Temporal owns Workflow Task recovery and configured Activity retry policy. It does not own the safety decision for external side effects.

- Decision Activity retries reuse the same `invocation_id`, request digest, and absolute deadline.
- Guard submission retries reuse the same Runtime-persisted `guard_submission_key` (HTTP `Idempotency-Key`) and byte-equivalent logical ActionRequest. Guard returns the existing service-created `operation_id`/Operation record or a conflict.
- Operation status reads are safe to retry. Runtime does not call the executor or dispatch an operation directly. Runtime also does not dispatch Compute provider operations; it calls Compute CP with a stable per-capacity-request Idempotency-Key.
- EngageGuard owns ambiguity/reconciliation of protected Action Operations. Compute CP owns ambiguity/reconciliation of provider-side ComputeOperations. Runtime must not replay a protected action while Guard reports UNKNOWN/RECONCILING/MANUAL_REVIEW or a provider mutation outside Compute CP.
- A timeout after a request may have reached Guard is not proof that the request failed. Retry only the idempotent Guard submission with the same persisted key, then query the same returned operation_id.
- Cancellation of a Workflow or Activity does not roll back an already-dispatched external side effect.

Activities must have explicit maximum attempts, backoff, and schedule-to-close limits. No unbounded default retry policy is accepted for model/provider calls or Guard integration.

## Initial stack

Go Temporal SDK, PostgreSQL/pgx, OpenTelemetry. Agent plugins use the pinned versioned HTTP JSON protocol. Python-first, TypeScript supported through the same canonical schema and fixtures.


## RunIntent and Compute boundary

Agent Control Plane creates run_intent_id and its immutable request digest. Runtime creates run_id and workflow_id only after accepting that intent, and persists the unique mapping before starting Temporal. A lost StartRun ACK is resolved through Runtime's authoritative idempotency registry; a Temporal visibility miss is not proof of non-creation.

For ordinary Run capacity, Runtime requests ComputeWorkload and stores the returned workload_id/allocation_id. For sandboxed execution, Runtime calls SandboxProvider Claim and SandboxProvider requests the required Compute capacity exactly once. Runtime never calls Kubernetes, Kueue or a provider directly.

A protected Agent compute proposal follows EngageGuard authorization. Compute CP validates the delegated Permit at its API enforcement point and owns the provider mutation journal. The Guard Action Operation and ComputeOperation are linked but have distinct IDs and state machines.
