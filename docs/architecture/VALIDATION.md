# Runtime validation ledger

## Verified GitHub Actions

- Workflow: [Go Runtime tests](https://github.com/avaargsh/agent-runtime/actions/runs/41435829765)
- Commit: `a9a6b50748948db407f3dcff4306ccd476eb9cd3`
- Result: `success` (2026-11-02).
- Verified steps: `go mod tidy` lock consistency, `go test -race -count=1 ./...`, `go vet ./...` and `gofmt` check.

This is S2 evidence for the Go module and tests included in that commit. It is not evidence of real Temporal Server, PostgreSQL, Worker restart or protected side-effect recovery.

## Previously recorded local evidence

- Go 1.23.2 isolated `internal/decision` module: `go test -race -count=1` PASS.
- Python Decision Plugin running on localhost + Go Client opt-in integration: PASS.
- Go `go vet ./internal/decision` in isolated standard-library module: PASS.

These are historical local records. The opt-in Python integration test is not part of the standard CI run unless `DECISION_INTEGRATION_URL` is configured.

## Not yet tested

- Real Temporal Server execution, Workflow history replay compatibility and Worker restart.
- PostgreSQL Run idempotency, transactional Event Inbox/Outbox and concurrent recovery.
- Runtime-to-EngageGuard receipt validation, lost-ACK handling and UNKNOWN reconciliation.
- Authenticated/encrypted inter-service communication and tenant authorization.
- Compute Allocation binding, cancellation and observed resource release.

Do not merge or claim production reliability based only on passing HTTP client and Temporal Workflow unit tests.
