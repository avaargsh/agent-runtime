# Go Temporal / Python Decision Spike

Go 1.26 and Temporal Go SDK v1.50.0 pinned in go.mod. This is a smoke-test only: no DB, API, authenticated plugin transport, privileged tools, model, or approval.

1. Run `temporal server start-dev`.
2. From agent-decision branch `feature/temporal-plugin-spike`, run `python -m decision_plugin.server`.
3. Run `go mod tidy && go test ./...` (needs network-accessible Go module cache and Go 1.26).
4. Run `DECISION_PLUGIN_URL=http://127.0.0.1:8081/api/v1/decision-turns go run ./cmd/worker`.
5. Run `go run ./cmd/starter`. Expected: `Accepted: hello`.

The stable Workflow ID is `agent-run/<run_id>`; retries must not construct a new ID for the same logical Run. The starter is a demonstration, not the idempotent production StartRun API.

Workflow contains only deterministic orchestration; all HTTP I/O occurs in an Activity. The Python endpoint is loopback-only and intentionally unauthenticated, and must not be exposed outside a developer machine.

**Verification limitation:** code has not been compiled or tested against Temporal in the authoring environment. Production requires pinned Go dependencies, go.sum, CI, authenticated channel, durable idempotency, provider failure handling and replay tests.
