# Decision v0.1 protocol lock

The canonical protocol lives at [avaargsh/agent-decision](https://github.com/avaargsh/agent-decision/tree/07a37e5e7b777cc1510e3bf408de081fea3de5c1/protocol/v0.1).

`decision-protocol.lock.json` pins the exact Agent Decision commit used by Runtime. It is intentionally not the moving `main` or PR branch head.

**Release gate:** verify the pinned schema, fixtures, and strict boundary tests with the version used by the Runtime integration. Updating this lock alone does **not** establish Go/TypeScript conformance or prove lost-ACK recovery, and no Runtime worker may automatically substitute a different protocol revision.

Runtime's `run_attempt_id` is distinct from the Guard-owned `executor_attempt_id`, the Temporal Activity retry counter, and the Decision `invocation_id`.
