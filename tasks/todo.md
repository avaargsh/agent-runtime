# Agent Runtime Tasks

- [x] Define Runtime ↔ Decision ↔ EngageGuard ownership and identifier semantics.
- [x] Pin the canonical Agent Decision v0.1 protocol revision.
- [x] Specify per-Activity retry and UNKNOWN handling rules.
- [x] Add fail-closed Guard status/retry decision unit tests (pure Go; no provider I/O).
- [ ] Confirm EngageGuard HTTP Idempotency-Key contract and implement lost-ACK integration test.
- [ ] Implement Run metadata and idempotent start API.
- [ ] Implement deterministic Go Temporal Workflow and Activities.
- [ ] Implement Decision Activity with strict schema and allow-list validation.
- [ ] Implement idempotent Guard operation submission and status projection.
- [ ] Implement approval wait, cancellation, deadlines, and bounded retry policies.
- [ ] Add Go/Python/TypeScript shared fixture conformance CI.
- [ ] Verify replay, duplicate start, lost ACK, restart, cancellation, and UNKNOWN recovery.
