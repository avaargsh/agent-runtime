# Agent Runtime Baseline

Status: Proposed v0.1

## Authority
Runtime owns Run, Task, Attempt and execution lifecycle. Temporal owns durable Workflow history, replay, timers, workflow task dispatch and retry orchestration. Runtime PostgreSQL stores canonical Run metadata, idempotency and query projections; it does not duplicate workflow history.

## Temporal / Agent Framework split
Go Temporal Workflow coordinates deterministic lifecycle only. It performs no direct I/O, network calls, DB calls, LLM inference or filesystem operations. Activities perform I/O and invoke managed plugins/services. Agent Framework plugin executes a bounded decision turn and returns FinalResponse or ActionProposal. Framework state must not become canonical platform Run state.

## Workflow
Start Run → Temporal Workflow → invoke Decision plugin Activity → receive proposal → for each action call EngageGuard Activity → wait for approval via Signal/Update → continue after receipt → persist result projection.

## Identity
Stable workflow_id is derived from canonical run_id (not random per retry). attempt_id and operation_id are distinct. Run idempotency is enforced by Runtime DB and Temporal Workflow ID conflict policy.

## Determinism
Workflow code uses only SDK deterministic APIs. No time.Now, random, network, goroutines/channels or direct DB. All I/O in Activities. Version Workflow changes with Temporal patching/worker deployment discipline. Inputs/results are versioned and serializable.

## Retry ownership
Temporal owns Workflow and Activity retry policy. EngageGuard owns ambiguity/reconciliation of privileged external side effects. Runtime must not replay a side effect while EngageGuard reports UNKNOWN. Activities must be idempotent or carry stable operation_id.

## Initial stack
Go Temporal SDK, PostgreSQL/pgx, OpenTelemetry. Agent plugins communicate via versioned HTTP/gRPC contract. Python-first, TypeScript supported.
