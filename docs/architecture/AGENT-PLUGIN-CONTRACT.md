# Agent Framework Plugin Contract v0.1

Status: Proposed. The canonical language-neutral protocol is maintained by `avaargsh/agent-decision` under `protocol/v0.1/`. This repository pins the exact protocol commit in `protocol/decision-protocol.lock.json`; do not fork or hand-edit a second schema.

## Invocation

Runtime sends one bounded Decision Turn request over HTTP JSON. The plugin returns exactly one of:

- `final_response`: structured answer and evidence references.
- `action_proposals`: an ordered list of typed, untrusted ActionProposal records.
- `needs_input`: a prompt and required missing fields.

The plugin does not execute privileged tools, own Run/Task/Session lifecycle, authorize actions, or claim that a side effect has completed.

## Request

The normative request schema is pinned in the Agent Decision protocol repository. Its v0.1 fields are:

`protocol_version`, `invocation_id`, `agent_id`, `bundle_digest`, `release_id`, `session_id`, `run_id`, `turn_id`, `user_input_ref`, `context_projection_ref`, `allowed_capabilities`, `deadline`, and `trace_context`.

- Tenant and principal identity are derived from authenticated workload/request context, never trusted from plugin-controlled body fields.
- Input and context are immutable, content-addressed references with digest, media type, and schema version. Plugin reads them through an authenticated, tenant-scoped, read-only interface.
- Capability descriptors contain exact capability ID/version and argument-schema digest. They define the proposal allow-list, not an authorization grant.
- Deadline is an absolute UTC RFC 3339 timestamp and remains unchanged across retries.
- Trace context is diagnostic only.

## Response and validation

The response is a discriminated union with exactly one result kind. Runtime validates the complete response, including every proposal, against the pinned response schema and the request's capability allow-list before submitting any proposal to EngageGuard.

Proposals are then submitted sequentially. A Guard denial or UNKNOWN operation stops later proposals. Previously completed operations are not rolled back; v0.1 does not promise atomic multi-action execution.

Framework metadata is bounded, diagnostic, and non-authoritative. Unknown fields, protocol versions, capability versions, or argument schema versions fail closed.

## Security

Plugin identity is workload-authenticated. No provider secrets, Permit tokens, direct executor credentials, or privileged tool access are sent to the plugin. Tenant/principal are derived from trusted authentication context, not body fields.

ActionProposal is untrusted input. Runtime validates the protocol and maps it into an ActionRequest; EngageGuard performs authoritative action canonicalization, computes ActionHash, and applies fresh authorization. EngageGuard/Trusted Executor remain the only path for protected side effects.
