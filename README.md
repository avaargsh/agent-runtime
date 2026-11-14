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

## Worker runtime configuration

The Temporal Worker requires:

- `DECISION_PLUGIN_URL`: managed Decision plugin endpoint. Plain HTTP is restricted to loopback for development; remote endpoints must use HTTPS.
- `DATABASE_URL`: the Runtime PostgreSQL database used for durable Run breaker state and security audit. Worker startup verifies connectivity and applies the versioned Runtime migrations.
- `TEMPORAL_ADDRESS`: optional Temporal frontend address; defaults to `127.0.0.1:7233`.

Before each Decision HTTP call, the Activity reads the owning Tenant's Run breaker. While the request is in flight, it polls the same Run breaker epoch every 250 ms. OPEN, stale epoch, missing state or PostgreSQL uncertainty cancels the request and returns a non-retryable Activity error.

The current Worker calls a remote Decision HTTP plugin and does not spawn a local Agent process or shell. This guard therefore cancels the in-flight HTTP request; process-group, cgroup or container termination belongs to a future local sandbox runtime.

