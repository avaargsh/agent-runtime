# Go Temporal / Python Decision Spike

Go 1.26 and Temporal Go SDK v1.50.0 pinned in go.mod. This is a smoke-test only: no DB, production API, authenticated plugin transport, privileged tools, model, approval, or durable invocation ledger.

1. Run `temporal server start-dev`.
2. From agent-decision branch `feature/temporal-plugin-spike`, run `python -m decision_plugin.server`.
3. Run `go mod tidy && go test ./...` (needs network-accessible Go module cache and Go 1.26).
4. Run `DECISION_PLUGIN_URL=http://127.0.0.1:8081/api/v1/decision-turns go run ./cmd/worker`.
5. Run `go run ./cmd/starter`. Expected: `Accepted: hello`.

The canonical Workflow ID mapping is centralized in `internal/workflows/identity.go`:

```text
workflow_id = "agent-run/v1/" + run_id
```

Runtime creates `run_id` once per accepted `run_intent_id`; duplicate delivery/start must return the same Run and Workflow ID. The starter is a demonstration, not the idempotent production StartRun API.

This PR's minimal `Turn` / `Result` DTO is a **smoke-test subset**, not full Agent Decision Protocol v0.1 conformance. The canonical full request/response schemas live in [agent-control-panel contracts](https://github.com/avaargsh/agent-control-panel/tree/feature/platform-foundation/contracts/agent-decision/v0.1). Before production integration, replace this subset with generated/validated DTOs and shared conformance vectors.

Workflow contains only deterministic orchestration; all HTTP I/O occurs in an Activity. The Python endpoint is loopback-only and intentionally unauthenticated, and must not be exposed outside a developer machine.

**Verification limitation:** the current PR's green unit-test workflow does not prove real Temporal Server replay, Worker restart, PostgreSQL idempotency, authenticated transport or protected action recovery. Keep this PR Draft until those gates are independently verified.
