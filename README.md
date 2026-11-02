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
