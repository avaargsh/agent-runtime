# Agent Runtime Implementation Plan

1. Freeze Run/Attempt/Operation identifiers and Agent Plugin Contract.
2. Implement Go service bootstrap, DB schema, Run idempotency and projection.
3. Implement Go Temporal Client and deterministic Run Workflow.
4. Implement Activities for Decision invocation and EngageGuard action execution.
5. Implement approval wait using Temporal Signal/Update; no polling loop.
6. Add cancellation, timeout, retry and worker versioning policy.
7. Build Python plugin reference and cross-language contract tests.
8. Add replay, duplicate start, lost ACK, restart and cancellation tests.

Exit gate: same logical Run has one stable Workflow ID; plugin cannot execute privileged effects; Temporal replay is deterministic; UNKNOWN action blocks blind retry.
