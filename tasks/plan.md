# Agent Runtime Implementation Plan

1. Freeze Run/Runtime Attempt/Decision Invocation/Guard Operation identifiers and pin the Agent Decision v0.1 protocol.
2. Implement Go service bootstrap, PostgreSQL schema, Run start idempotency, invocation correlation, and query projection.
3. Implement Temporal Client and deterministic Run Workflow with explicit Workflow ID conflict/reuse policy.
4. Implement Decision Activity with strict schema/semantic validation and bounded retry policy.
5. Implement idempotent EnsureGuardOperation Activity; persist idempotency key before network call and persist returned operation_id.
6. Implement read-only operation status handling, approval wait via Signal/Update, and Guard-owned UNKNOWN reconciliation.
7. Add cancellation, deadline propagation, Activity timeout/retry configuration, and worker versioning policy.
8. Add Go/Python/TypeScript shared protocol fixture conformance and failure-injection tests.
9. Verify replay, duplicate start, lost Decision ACK, lost Guard ACK, lost Receipt ACK, restart, cancellation, and stale-worker behavior.

Exit gate: one logical Run has one stable Workflow ID; plugin cannot execute privileged effects; Temporal replay is deterministic; retries reuse stable intent IDs; UNKNOWN / RECONCILING / MANUAL_REVIEW block blind redispatch.
