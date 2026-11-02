# Agent Runtime Baseline

Status: Proposed v0.1

## Authority

Runtime owns Run, Task, Runtime Attempt, Decision Turn coordination, and execution lifecycle. Temporal owns durable Workflow history, replay, timers, Workflow Task dispatch, and Activity retry orchestration. Runtime PostgreSQL stores canonical Run metadata, start idempotency, correlation records, and query projections; it does not duplicate Temporal history or EngageGuard's Operation Journal.

## Temporal / Agent Framework split

Go Temporal Workflow coordinates deterministic lifecycle only. It performs no direct I/O, network calls, DB calls, LLM inference, or filesystem operations. Activities perform I/O and invoke managed plugins/services. Agent Decision executes one bounded Decision Turn and returns FinalResponse, ActionProposal list, or NeedsInput. Framework state must not become canonical platform Run state.

## Workflow

Start Run → Temporal Workflow → invoke Decision Activity → validate complete response → for each proposal submit an idempotent ActionRequest to EngageGuard → wait for approval / operation result → persist Runtime projection.

Runtime never invokes a protected executor directly. EngageGuard owns authorization, Permit claim, Operation Journal, external dispatch coordination, UNKNOWN and reconciliation.

## Identity

Stable `workflow_id` is `agent-run:v1:<run_id>`; Runtime guarantees `run_id` is globally unique within the Temporal namespace and does not generate a random Workflow ID per retry. `invocation_id` identifies one logical Decision Turn and is stable across Activity retries. `runtime_attempt_id` identifies a Runtime-owned Task/Run execution attempt; Temporal Activity retry counters are not business IDs. EngageGuard creates `operation_id` and its own `attempt_id`; Runtime must not generate or reinterpret either. Run start idempotency is enforced by Runtime DB and an explicit Temporal Workflow ID conflict/reuse policy.

## Determinism

Workflow code uses only SDK deterministic APIs. No wall-clock reads, random generation, network, DB, filesystem, or direct goroutines/channels in Workflow code. All I/O and ID generation happen in Activities or before Workflow start and are supplied as durable inputs. Version Workflow changes with Temporal patching/worker deployment discipline. Inputs/results are versioned and serializable.

## Retry ownership

Temporal owns Workflow Task recovery and configured Activity retry policy. It does not own the safety decision for external side effects.

- Decision Activity retries reuse the same `invocation_id`, request digest, and absolute deadline.
- Guard submission retries reuse the same Runtime-persisted idempotency key and byte-equivalent logical ActionRequest. Guard returns the existing `operation_id` or a conflict.
- Operation status reads are safe to retry. Runtime does not call the executor or dispatch an operation directly.
- EngageGuard owns ambiguity/reconciliation of privileged external side effects. Runtime must not replay a side effect while EngageGuard reports UNKNOWN, RECONCILING, or MANUAL_REVIEW.
- A timeout after a request may have reached Guard is not proof that the request failed. Retry only the idempotent Guard submission with the same key, then query the same operation.
- Cancellation of a Workflow or Activity does not roll back an already-dispatched external side effect.

Activities must have explicit maximum attempts, backoff, and schedule-to-close limits. No unbounded default retry policy is accepted for model/provider calls or Guard integration.

## Initial stack

Go Temporal SDK, PostgreSQL/pgx, OpenTelemetry. Agent plugins use the pinned versioned HTTP JSON protocol. Python-first, TypeScript supported through the same canonical schema and fixtures.
