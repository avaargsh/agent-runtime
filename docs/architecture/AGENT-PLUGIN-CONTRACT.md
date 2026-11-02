# Agent Framework Plugin Contract v0.1

## Invocation
Runtime sends one bounded DecisionTurn request. The plugin returns either a FinalResponse or a list of typed ActionProposal objects. It does not execute privileged tools.

## Request fields
protocol_version, invocation_id, tenant_id, agent_id, bundle_digest, release_id, session_id, run_id, turn_id, user_input_ref, context_projection_ref, allowed_capabilities, deadline, trace_context.

## Response
- final: structured answer and evidence references; OR
- proposals: ordered ActionProposal records with proposal_id, capability_id, capability_version, typed arguments, target_resource_ref and rationale_ref.
- status: completed | needs_input | failed.
- framework metadata is diagnostic, bounded and non-authoritative.

## Security
Plugin identity is workload-authenticated. Tenant and principal are derived from trusted auth context, not trusted from body fields. No provider secrets, Permit tokens or direct executor credentials are sent to the plugin. Tool proposals are revalidated by EngageGuard at execution time.

## Limits
One call is bounded by deadline, token budget, max proposals, response size and framework-specific execution budget. Plugin retries are controlled by Temporal Activity policy with invocation_id idempotency. Streaming is optional and not required for v0.1.

## Compatibility
Protocol is versioned; unknown capability versions fail closed. Python and TypeScript implementations must pass the same JSON Schema/contract test vectors.
