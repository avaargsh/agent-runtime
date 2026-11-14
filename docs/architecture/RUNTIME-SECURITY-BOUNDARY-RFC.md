# Runtime Security Boundary RFC

- Status: **Proposed**
- Scope owner: `avaargsh/agent-runtime`
- Control-plane integration: `avaargsh/agent-control-panel`
- Protected-action enforcement: `avaargsh/EngageGuard`
- Date: 2026-11-04
- Tracking: [agent-runtime issue #10](https://github.com/avaargsh/agent-runtime/issues/10)

## 1. Goal

Provide a single enforceable security boundary around Coding Agent model interactions and tool execution. The boundary correlates trusted identity, records behavior, blocks risky execution, and protects sensitive data before it leaves the trusted runtime.

The first release covers four capabilities:

1. Identity correlation across User / Agent / Session / Run / Turn / Proposal / Tool Call.
2. Append-only Runtime behavior audit, with Guard-owned protected-action evidence referenced rather than copied.
3. Risk-triggered Run / Agent / Tenant circuit breaking and cancellation.
4. Outbound tokenization and response rehydration for explicitly reversible data classes.

This RFC defines ownership and contracts. It does not claim production readiness or authorize protected effects by itself.

## 2. Authority boundaries

| Concern | Authority | Rule |
|---|---|---|
| Tenant, Project, Agent, AgentRelease, canonical Session identity and security-policy bindings | Agent Control Panel | Runtime consumes authenticated identity and immutable policy references; it does not redefine ACP identities. |
| Authenticated human / workload principal | Identity provider and verified service boundary | Never accept identity assertions from Agent Framework payloads or arbitrary headers. |
| Run, RunAttempt, Turn, Proposal, Tool Call and Runtime security event | Agent Runtime | Runtime creates and persists execution-scoped identities and correlates every model/tool boundary. |
| Run-scoped data-protection context and Token Vault access orchestration | Agent Runtime | Raw mappings remain inside trusted storage and never enter Framework plugins. |
| Action authorization, risk evaluation for protected actions, approval, Permit, operation ID, operation journal, trusted executor, receipt and action-level UNKNOWN | EngageGuard | Runtime submits untrusted intent and consumes Guard evidence. It must not create a second authorization or operation journal. |
| Durable workflow history and retry orchestration | Temporal | Runtime cancellation and retries remain deterministic; Temporal is not the authorization authority. |
| External effect and actual resource state | Target provider / owning service | A local timeout is not proof that an external effect failed. |

The Runtime Proposal Outbox is a delivery mechanism. It is not a substitute for an append-only audit archive.

## 3. Canonical identity correlation

Runtime creates only the identifiers it owns. The authenticated execution context is assembled by trusted adapters and is immutable for one operation.

| Identifier | Authority | Meaning |
|---|---|---|
| `tenant_id` | ACP / authenticated tenant authority | Tenant security boundary |
| `subject_id` / `actor_id` | Verified identity provider / principal resolver | Human or service subject and acting principal |
| `agent_id` / `agent_release_id` | ACP | Agent definition and immutable release |
| `session_id` | ACP | Canonical interaction session |
| `run_id` / `run_attempt_id` | Runtime | Logical execution and one execution attempt |
| `turn_id` / `intent_revision` | Runtime | Interaction turn and current intent revision |
| `proposal_id` | Runtime | One untrusted tool proposal |
| `tool_call_id` | Runtime | One concrete tool invocation |
| `guard_submission_key` | Runtime | Stable idempotency key persisted before Guard submission |
| `operation_id` / `permit_id` / `executor_attempt_id` | EngageGuard | Authoritative protected-action identities |
| `trace_id` | Observability adapter | Distributed correlation only; never an authorization credential |

Rules:

- Framework/plugin output may reference a Proposal or capability, but cannot choose or override tenant, subject, actor, Agent, Session, Run, Attempt, policy binding or Guard identity.
- Every boundary derives identity from a trusted `SecurityContext`; missing or stale required fields fail closed.
- Delegated/sub-agent work receives a narrowed child context and capability set. It does not inherit all parent permissions.
- Logs and API responses must not expose bearer tokens, private keys or raw Token Vault mappings.

## 4. Runtime behavior audit

### 4.1 Coverage

Runtime audit records at least:

- Run / Attempt / Turn / Proposal creation, state transition, correction, cancellation and recovery.
- Model request preparation, outbound dispatch, provider/model identity, response receipt, timeout and retry.
- Tool proposal, validation, policy result, approval wait, tool call, execution result and cancellation.
- File, shell, Git and network operations as observed by the trusted tool adapter / sandbox boundary.
- Data classification, tokenization, rehydration decision, rejected token, Vault failure and policy revision.
- Breaker trip, scope, trigger, affected work, revocation request and recovery approval.
- Guard operation/approval/Permit/receipt/UNKNOWN references and evidence digests.

Runtime must not claim visibility into an OS or network action unless an enforcement adapter actually observes that boundary. A plugin-reported event alone is untrusted evidence.

### 4.2 Event contract

A Runtime audit event includes:

- `event_id`, `occurred_at`, `event_type`, `schema_version`
- trusted identity references: tenant, subject, actor, agent, release, session, run, attempt, turn, proposal and tool call
- `trace_id` / `parent_event_id` where available
- action / resource classification, outcome, policy reference and breaker epoch
- request/response digest, redacted evidence reference and source adapter
- Guard operation / receipt references where applicable

Append-only audit facts are persisted transactionally with Runtime state transitions where both belong to one PostgreSQL transaction. The delivery outbox is written in the same transaction, but consumers cannot mutate or erase the audit fact. Raw secrets and original PII are excluded from event payloads by construction.

Guard remains authoritative for the protected-action journal. Runtime stores correlation IDs, digest and verified evidence references, not a second copy of Guard's mutable operation state.

### 4.3 Failure policy

- If audit persistence fails, protected tool execution and external data egress stop. The Runtime must not silently continue without an audit trail.
- If an audit event is delayed for a non-effectful local computation, the Run may pause; it must not cross the next enforcement boundary until the event is durable.
- Hash chaining / immutable archival is a later integrity hardening step. Hashes alone do not establish trusted event origin.

## 5. Risk and circuit breaker

### 5.1 Responsibility split

- EngageGuard decides whether a protected action is allowed, requires approval, is denied or trips its action-level protection.
- Runtime owns the Run / Agent execution kill switch and responds to Guard security signals.
- ACP owns policy bindings and administrative desired state; it may request a broader suspension but does not terminate Runtime processes directly.

### 5.2 Scope and state

Initial scopes:

- `RUN`: stop one execution and its delegated work.
- `AGENT_INSTANCE`: stop an Agent instance and its active Runs.
- `TENANT`: emergency tenant-wide suspension, restricted to an operator-authorized path.

States:

- `CLOSED`: normal admission; each boundary still performs policy checks.
- `OPEN`: deny new work, cancel in-flight Runtime work, invalidate Run-scoped capabilities and request Guard-side revocation/cancellation where supported.
- `HALF_OPEN`: controlled recovery probe with read-only capabilities only; never automatically re-enable a previously denied irreversible action.

A breaker record includes scope, monotonically increasing `breaker_epoch`, trigger event, reason code, policy revision, actor/system identity, opened time and recovery evidence. Each worker/tool adapter checks the current epoch before beginning work so stale workers cannot continue under an old lease.

### 5.3 Trigger and recovery

Candidate critical triggers include confirmed credential exfiltration, protected-path access, unauthorized external egress, audit tampering/disablement, repeated policy-bypass attempts, or a Guard-issued critical denial signal.

On trip:

1. Persist the breaker transition and security event.
2. Reject new Tool Proposals, model egress and tool calls in the affected scope.
3. Cancel Temporal work and propagate cancellation to process/container supervisors.
4. Revoke Runtime capabilities and request Guard revocation for outstanding eligible Permits/operations.
5. Preserve workspace snapshot and evidence references.
6. Keep uncertain external effects in the owning Guard/provider UNKNOWN reconciliation path.
7. Require explicit, scope-appropriate recovery authorization; do not clear a critical breaker based only on a timer.

Temporal cancellation alone is insufficient: the sandbox/process supervisor and trusted executor must enforce termination and stale-work fencing.

## 6. Sensitive data protection

### 6.1 Placement

Data protection runs inside the trusted Runtime boundary:

- before every external model request;
- before every remote MCP/tool/network request;
- after every external response and before user display or local downstream use.

Framework plugins receive only the protected representation. They cannot access the Token Vault or call rehydration directly.

### 6.2 Data classes

| Class | Examples | Default handling |
|---|---|---|
| Reversible PII | Name, email, phone, customer identifier | Run-scoped random token backed by encrypted Vault mapping, subject to policy |
| Credentials / authentication secrets | Password, API key, bearer token, private key, session cookie | Irreversible redaction or narrow local Secret Reference; never a reversible model-visible token |
| Restricted business data | Contract text, internal records, source-code secrets | Policy-specific redaction, local-only processing or explicit egress denial |
| Public data | Public documentation, public code | Pass through after normal scanning |

Tokenization is not a substitute for authorization. A data class may be prohibited from external processing even when a reversible token could be generated.

### 6.3 Outbound transformation

1. Resolve the trusted tenant / Run scope and immutable data-protection policy revision.
2. Scan structured fields and unstructured text; classify each detected span.
3. Reject ambiguous overlaps or malformed inputs instead of guessing offsets.
4. Replace allowed reversible values with cryptographically random opaque placeholders.
5. Store the original value only through an encrypted Vault interface; persist scope, type, token digest, key version and expiry.
6. Replace credentials with irreversible redaction or a non-authorizing local Secret Reference.
7. Emit an audit event containing classifications, counts and payload digest, never original values.
8. Send only the protected payload to the external destination.

Example:

```text
Original: Contact 张三 at zhangsan@example.com, phone 13812341234.
Outbound: Contact [[PII:PERSON:<opaque>]] at
          [[PII:EMAIL:<opaque>]], phone [[PII:PHONE:<opaque>]].
```

### 6.4 Inbound validation and rehydration

- Parse only placeholders registered by this Vault and matching the exact tenant / Run scope.
- Require an explicit audience and purpose authorization for every restoration.
- Restore reversible PII only into approved local destinations, such as the user-facing response renderer or a local workspace operation.
- Never restore credentials to model text. A local executor may resolve a Secret Reference only under a separately authorized operation.
- Unknown, forged, expired or cross-Run placeholders are never resolved.
- Responses are untrusted: restored values are treated as data, never as instructions or authorization.
- For streaming responses, buffer across chunk boundaries until a complete placeholder can be validated; enforce bounded buffering and fail closed on overflow.
- Before any subsequent model call, run outbound inspection again. A value restored for user display must not silently flow back to the model.

### 6.5 Vault contract and security

The Token Vault is a storage interface backed by authenticated encryption and a managed key provider. The Runtime package must not invent its own key management or store plaintext mappings in the Agent Memory, ordinary Session Store, logs, traces or metrics.

Vault records are scoped by tenant and Run, expire, and are not portable between Runs. Tokens use high-entropy randomness; lookups require exact scope and a registered token record. Repeated values may preserve equality within one Run, but cross-Run correlation is prohibited.

Vault outage, key unavailability, scanner failure or policy lookup failure blocks external egress when protected data may be present. The implementation must never fall back to sending the original payload.

## 7. Stable Go boundaries

The first implementation should keep interfaces small and injected at Runtime boundaries:

```go
type SecurityContext struct {
    TenantID, SubjectID, ActorID string
    AgentID, AgentReleaseID      string
    SessionID, RunID             string
    RunAttemptID, TurnID         string
    PolicyRevision               string
}

type OutboundProtector interface {
    Protect(ctx context.Context, scope SecurityScope, audience string,
        payload Payload) (ProtectedPayload, error)
}

type InboundRestorer interface {
    Restore(ctx context.Context, scope SecurityScope, audience, purpose string,
        payload Payload) (Payload, error)
}

type AuditRecorder interface {
    Append(ctx context.Context, event SecurityEvent) error
}

type Breaker interface {
    Check(ctx context.Context, scope BreakerScope) (BreakerSnapshot, error)
    Trip(ctx context.Context, scope BreakerScope, reason SecurityReason) error
    Recover(ctx context.Context, scope BreakerScope, approval RecoveryApproval) error
}
```

The concrete schemas, persistence adapter and encrypted Vault provider must be versioned separately. No implementation may accept identity or scope by copying untrusted plugin fields.

## 8. Implementation sequence

### P0 — enforceable Runtime boundary

- Canonical SecurityContext propagation and stale-context rejection.
- Audit event schema and append-only PostgreSQL persistence for model/tool/security boundaries.
- Run-scoped breaker state, epoch fencing, Temporal cancellation and sandbox supervisor integration.
- Guard signal / evidence correlation without duplicating Guard's operation journal.
- Fail-closed behavior for audit, policy and enforcement dependencies.

### P1 — privacy-preserving data path

- Detector interface and structured/text scanner.
- Encrypted Token Vault interface and key-provider adapter.
- Reversible PII tokenization and audience-bound rehydration.
- Irreversible credential redaction / Secret Reference support.
- Streaming and adversarial-token tests.

### P2 — enterprise governance

- Agent-instance and tenant-wide breaker controls.
- Policy administration and evidence viewer in ACP.
- Hash-chained / immutable audit archival, retention and legal-hold controls.
- Data-classification policy packs and operational dashboards.

## 9. Acceptance scenarios

- Plugin-supplied tenant, actor, Run or policy identity is ignored/rejected.
- A model request, model response, Proposal, tool call, result, denial, cancellation and recovery each produce correlated audit evidence.
- Audit or Vault outage blocks the relevant external boundary without fallback to raw data.
- A critical breaker trip prevents stale workers, child processes and retries from continuing.
- Guard's action journal remains the only authority for protected action execution and UNKNOWN reconciliation.
- Outbound PII is tokenized; passwords, bearer tokens and private keys are never reversibly exposed to a model.
- Only exact registered tokens from the matching tenant/Run can be restored for an allowed audience and purpose.
- Forged, expired, modified, malformed, cross-tenant and cross-Run tokens cannot recover original values.
- Repeated values preserve equality within a Run where policy requires it, without cross-Run correlation.
- Streaming responses split at every possible placeholder boundary are safely buffered and restored.
- Logs, traces, errors and metrics contain neither plaintext protected values nor Vault mappings.
- Exact-head Go race/vet/format and relevant PostgreSQL / process-supervisor integration tests pass.

## 10. Explicit non-goals

- No second authorization engine or Permit / Action Operation Journal in Runtime.
- No direct provider-side effect execution from Agent Framework plugins.
- No general distributed transaction or exactly-once side-effect guarantee.
- No reversible credential tokenization.
- No claim that application middleware alone can stop arbitrary child processes or direct network traffic.
- No production-readiness claim until the concrete Vault, trusted executor, supervisor, policy and recovery integrations are independently tested.
