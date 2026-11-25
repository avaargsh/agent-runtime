# Agent Runtime

Go-based durable Agent Runtime built on Temporal.

## Product boundary

Owns Run identity, durable execution coordination, Run/Task lifecycle projections, cancellation and recovery. Temporal owns workflow history and durable orchestration semantics. Agent Frameworks are managed Python/TypeScript plugins; they do not own the platform Run lifecycle.

## Initial architecture

- Go API, Temporal Client and Go Workflow Workers.
- Temporal Workflows coordinate durable Run lifecycle.
- Activities call managed Agent Framework plugins and EngageGuard.
- Python/TypeScript plugins perform model reasoning and produce tool-call proposals.
- All protected side effects pass through EngageGuard and a trusted executor.

The Runtime does not implement a workflow engine or a generic Agent Framework.

## Architecture and contracts

- [Runtime reliability acceptance](docs/RELIABILITY-ACCEPTANCE.md)
- [Decision ↔ Runtime ↔ EngageGuard integration contract](docs/architecture/DECISION-INTEGRATION-CONTRACT.md)
- [Agent Execution Safety RFC](docs/architecture/AGENT-EXECUTION-SAFETY-RFC.md)

## Go toolchain for local verification

[`go.mod`](go.mod) declares Go 1.26.0 as the module minimum. The
[Go test workflow](.github/workflows/go-tests.yml) pins and checks Go 1.26.11
for repository verification. For comparable local checks, select Go 1.26.11
and run from a clean checkout:

```sh
export GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.26.11"
go mod verify
go mod tidy
git diff --exit-code -- go.mod go.sum
go test -race -count=1 ./...
go vet ./...
test -z "$(gofmt -l cmd internal)"
```

A pass using another SDK is not a reproduction of the pinned CI toolchain.
Tests requiring external services still need the isolated setup in the
[reliability acceptance guide](docs/RELIABILITY-ACCEPTANCE.md). In particular,
local tests without `TEST_DATABASE_URL` do not replace the PostgreSQL 17
integration job.

## Worker runtime configuration

The Temporal Worker requires:

- `DECISION_PLUGIN_URL`: managed Decision plugin endpoint. Plain HTTP is restricted to loopback for development; remote endpoints must use HTTPS.
- `DATABASE_URL`: the Runtime PostgreSQL database used for durable Run breaker state and security audit. Worker startup verifies connectivity and applies the versioned Runtime migrations.
- `TEMPORAL_ADDRESS`: optional Temporal frontend address; defaults to `127.0.0.1:7233`.

Before each Decision HTTP call, the Activity reads the owning Tenant's Run breaker. While the request is in flight, it polls the same Run breaker epoch every 250 ms. Every preflight, polling and postflight database read has a 250 ms context deadline; a timed-out read is treated as breaker-store uncertainty. OPEN, stale epoch, missing state or PostgreSQL uncertainty cancels the request and returns a non-retryable Activity error. With the default 250 ms poll interval and 250 ms read deadline, an unresponsive store is detected within approximately one poll interval plus one read deadline (about 500 ms, excluding scheduler and transport cancellation latency).

The current Worker calls a remote Decision HTTP plugin and does not spawn a local Agent process or shell. This guard therefore cancels the in-flight HTTP request; process-group, cgroup or container termination belongs to a future local sandbox runtime.

