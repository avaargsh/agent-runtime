# Runtime validation ledger

## Independently executed, local

- Go 1.23.2 isolated `internal/decision` module: `go test -race -count=1` PASS.
- Python Decision Plugin running on localhost + Go Client opt-in integration: PASS.
- Go `go vet ./internal/decision` in isolated standard-library module: PASS.

## Pending authoritative CI evidence

Full Runtime module targets Go 1.26.0 and Temporal SDK v1.50.0. The authoring environment cannot fetch SDK dependencies and does not have that Go toolchain. GitHub Actions workflow runs `go mod tidy`, `go test -race -count=1 ./...`, `go vet ./...` and gofmt on a Go 1.26 runner. A passing workflow must be inspected before marking full Runtime tests green.

## Not yet tested

- Temporal real-server execution, workflow history replay compatibility, worker restart.
- PostgreSQL Run idempotency, outbox/inbox and UNKNOWN Action reconciliation.
- Authenticated and encrypted inter-service communication, tenant authorization.

Do not merge based only on passing HTTP client tests.
