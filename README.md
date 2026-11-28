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
(
  set -e
  export GOTOOLCHAIN=local
  actual_go=$(go env GOVERSION)
  if [ "$actual_go" != "go1.26.11" ]; then
    printf 'Expected Go 1.26.11 for CI comparison; found %s.\n' "$actual_go" >&2
    exit 1
  fi
  go mod verify
  go mod tidy
  git diff --exit-code -- go.mod go.sum
  go test -race -count=1 ./...
  go vet ./...
  test -z "$(gofmt -l cmd internal)"
)
```

A pass using another SDK is not a reproduction of the pinned CI toolchain.
Tests requiring external services still need the isolated setup in the
[reliability acceptance guide](docs/RELIABILITY-ACCEPTANCE.md). In particular,
local tests without `TEST_DATABASE_URL` do not replace the PostgreSQL 17
integration job.

## Local checks

The root [`Makefile`](Makefile) wraps the checks above. `make` with no
target runs `make help`. Those targets set `GOTOOLCHAIN=local` and use only
the Go toolchain already on `PATH`. If `go` is missing, or older than the
Go 1.26.0 minimum in [`go.mod`](go.mod), the target stops and does not
download a toolchain. The
[Go test workflow](.github/workflows/go-tests.yml) pins Go 1.26.11. A local
Go 1.26.0 or newer satisfies the Makefile; Go 1.26.11 matches CI.

```sh
make help
make lint
make test
make build
make clean
```

`make lint` requires `gofmt -l cmd internal` to be empty, the same
directories CI checks, then runs `go vet ./...`, `go mod verify`, and
`go mod tidy -diff`. The `-diff` form reports module drift and does not
rewrite `go.mod` or `go.sum`. The plain `go mod tidy` command in the section
above can still rewrite those files. `make test` runs
`go test -race -count=1 ./...`. `make build` compiles every main package
under `./cmd` into `bin/`: `acp-api`, `decision-authority-api`,
`guard-authority-api`, `starter`, and `worker`. `make clean` deletes `bin/`
only and does not clear the Go build cache.

`make lint`, `make test`, and `make build` do not start Temporal or
PostgreSQL. A passing `make test` is not the PostgreSQL 17 integration job.

Tests skip only at the `t.Skip` calls below. `TestACPSubprocessHarnessFixture`
returns without skipping unless `ACP_HARNESS_PROCESS_FIXTURE=1`.
`TestHarnessCreationProcessFixture` returns without skipping unless
`RUNTIME_HARNESS_CREATION_PROCESS_FIXTURE` is set.

- `TEST_DATABASE_URL` unset: `newTestStore` in
  `internal/store/postgres/run_store_integration_test.go` skips with
  `TEST_DATABASE_URL is not set; PostgreSQL integration test skipped`.
  `runningPrincipalRun`, `harnessFixture`, and `newProposalStore` call
  `newTestStore`. Every test in package `postgres_test` that calls one of
  those four functions skips the same way, unless an earlier gate below
  already skipped it.
- `RUNTIME_TEMPORAL_INTEGRATION` is not `1`:
  `TestBusinessStartDispatcherUsesRealCheckpointAndRecoversLostACK`,
  `TestDevelopmentStartDispatcherRecoversCommittedWorkflowWithoutSecondStart`,
  `TestDevelopmentStartDispatcherDoesNotAcknowledgeUnrelatedWorkflow`,
  `TestTemporalStartLostACKAndServerWorkerRestartPreservesWorkflowIdentity`,
  `TestAcceptedDecisionCheckpointSurvivesWorkerSIGKILL`, and
  `TestBusinessWorkflowConsumesFencedDecision` skip before PostgreSQL. If
  `RUNTIME_TEMPORAL_INTEGRATION=1` and `TEST_DATABASE_URL` is unset, the
  first four and `TestBusinessWorkflowConsumesFencedDecision` then skip
  inside `newTestStore`. `TestAcceptedDecisionCheckpointSurvivesWorkerSIGKILL`
  fails instead, with `real Temporal test requires PostgreSQL`.
- `RUNTIME_EXTERNAL_ACP_TEST` is not `1`:
  `TestExternalACPAdmissionTemporalRecovery` skips. That test does not read
  `TEST_DATABASE_URL`.
- `DECISION_INTEGRATION_URL` empty: `TestPythonDecisionPlugin` in
  `internal/decision/integration_test.go` skips.
- `RUNTIME_CHECKPOINT_WORKER` is not `1`:
  `TestAcceptedDecisionCheckpointWorkerProcess` skips. When that variable is
  `1`, an empty `TEST_DATABASE_URL`, `RUNTIME_CHECKPOINT_SCHEMA`,
  `RUNTIME_CHECKPOINT_TEMPORAL`, or `RUNTIME_CHECKPOINT_MARKER` fails the
  test.
- `RUNTIME_CONTINUATION_WORKER` is not `1`:
  `TestVerifiedDecisionContinuationWorkerProcess` skips. When that variable
  is `1`, an empty `TEST_DATABASE_URL`, `RUNTIME_CONTINUATION_SCHEMA`,
  `RUNTIME_CONTINUATION_TEMPORAL`, `RUNTIME_CONTINUATION_DIR`,
  `RUNTIME_CONTINUATION_KEY`, or `RUNTIME_CONTINUATION_MARKER` fails the
  test.

None of the `./cmd` binaries can be started from the compiled file alone.
Each one needs Temporal, PostgreSQL, or both, and the worker also needs a
Decision plugin endpoint.

- `bin/worker` requires `DECISION_PLUGIN_URL` and `DATABASE_URL`, then pings
  PostgreSQL, applies migrations, and dials Temporal (`TEMPORAL_ADDRESS`,
  default `127.0.0.1:7233`).
- `bin/starter` dials that same Temporal address and starts a workflow.
- `bin/acp-api` requires `RUNTIME_DATABASE_URL`, a TLS certificate, a TLS
  key, a client CA, and `RUNTIME_ACP_SPIFFE_ID`, then pings PostgreSQL.
- `bin/decision-authority-api` requires `RUNTIME_DECISION_DATABASE_URL`, a
  TLS certificate, a TLS key, a client CA, `RUNTIME_DECISION_PEER_SPIFFE_ID`,
  and `RUNTIME_DECISION_TENANT`, then pings PostgreSQL.
- `bin/guard-authority-api` requires
  `RUNTIME_GUARD_AUTHORITY_DATABASE_URL`, a TLS certificate, a TLS key, a
  client CA, `RUNTIME_GUARD_AUTHORITY_PEER_SPIFFE_ID`, and
  `RUNTIME_GUARD_AUTHORITY_TENANT`, then pings PostgreSQL and checks a
  read-only role.

## Worker runtime configuration

The Temporal Worker requires:

- `DECISION_PLUGIN_URL`: managed Decision plugin endpoint. Plain HTTP is restricted to loopback for development; remote endpoints must use HTTPS.
- `DATABASE_URL`: the Runtime PostgreSQL database used for durable Run breaker state and security audit. Worker startup verifies connectivity and applies the versioned Runtime migrations.
- `TEMPORAL_ADDRESS`: optional Temporal frontend address; defaults to `127.0.0.1:7233`.

Before each Decision HTTP call, the Activity reads the owning Tenant's Run breaker. While the request is in flight, it polls the same Run breaker epoch every 250 ms. Every preflight, polling and postflight database read has a 250 ms context deadline; a timed-out read is treated as breaker-store uncertainty. OPEN, stale epoch, missing state or PostgreSQL uncertainty cancels the request and returns a non-retryable Activity error. With the default 250 ms poll interval and 250 ms read deadline, an unresponsive store is detected within approximately one poll interval plus one read deadline (about 500 ms, excluding scheduler and transport cancellation latency).

The current Worker calls a remote Decision HTTP plugin and does not spawn a local Agent process or shell. This guard therefore cancels the in-flight HTTP request; process-group, cgroup or container termination belongs to a future local sandbox runtime.

