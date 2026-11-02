# Decision ↔ Runtime ↔ EngageGuard Integration Contract v0.1

Status: Proposed P0 integration contract.

## 1. Authorities

| Concern | Authority | Non-owner |
|---|---|---|
| Run / Task / Runtime Attempt | Agent Runtime | Agent Decision, EngageGuard |
| Workflow history / replay / timers / Activity retry | Temporal | Agent Decision |
| One bounded model Decision Turn | Agent Decision | Temporal |
| Action authorization / risk / approval / Permit | EngageGuard | Runtime, Agent Decision |
| Operation ID / Operation Journal / Guard dispatch attempt / UNKNOWN / reconciliation | EngageGuard | Runtime, Agent Decision |
| Actual protected side effect and trusted receipt | Trusted Executor / Provider | Agent Decision |

No service may infer another service's authoritative state from a timeout, missing ACK, or local projection.

## 2. Identifier ownership and lifetime

| Identifier | Creator / authority | Lifetime and retry rule |
|---|---|---|
| `run_id` | Runtime | One logical Run; stable across all retries |
| `workflow_id` | Runtime mapping to Temporal | Deterministic from run_id; never random per retry |
| `turn_id` | Runtime | One logical Decision Turn |
| `invocation_id` | Runtime | One logical plugin invocation; stable across Activity retries |
| `runtime_attempt_id` | Runtime | One Runtime-owned Task/Run execution attempt; does not change for Temporal Activity retries |
| Temporal Activity attempt counter | Temporal | SDK metadata only; never used as a business identifier |
| `proposal_id` | Agent Decision | Stable within the stored response for one invocation; unique within that invocation |
| `idempotency_key` | Runtime | Generated once and persisted for one proposal/operation intent; reused for every Guard submission retry |
| `operation_id` | EngageGuard | Server-created logical external operation; Runtime stores and reuses the returned value |
| `attempt_id` | EngageGuard | One Guard-owned external dispatch attempt; do not alias to runtime_attempt_id |
| `receipt_id` | Trusted Executor | One immutable execution receipt |

The EngageGuard `attempt_id` meaning is fixed by OperationRecord/ExecutionReceipt. Runtime uses the distinct name `runtime_attempt_id`. Temporal's numeric Activity attempt is not persisted as either identifier.

## 3. Request and response protocol

The canonical Agent Decision protocol is HTTP JSON, JSON Schema Draft 2020-12, protocol version `0.1`, maintained at `avaargsh/agent-decision/protocol/v0.1/`. The exact immutable source revision is pinned in `protocol/decision-protocol.lock.json`.

Request includes protocol/invocation identity, Agent/Bundle/Release/Session/Run/Turn references, immutable user-input and context-projection refs, exact allowed capability descriptors, absolute UTC deadline, and W3C trace context. Tenant/principal are derived from authenticated workload context, not trusted body fields.

Response is exactly one of `final_response`, `action_proposals`, or `needs_input`. There is no parallel `status` field and no `retryable` boolean. Errors use the separate versioned error envelope. Runtime owns retry policy.

Before any Guard submission, Runtime validates the whole response, unique proposal IDs, every capability ID/version against the request allow-list, and every arguments object against the exact argument-schema digest. If any proposal is invalid, reject the entire response and submit none.

After validation, proposals are processed in order, each as a separate Guard operation. A Guard denial, timeout with unresolved operation, or UNKNOWN stops subsequent proposals. Earlier completed operations are not rolled back; multi-proposal responses are not atomic transactions.

## 4. Idempotency rules

### Decision invocation

- Runtime persists `invocation_id`, request digest, and absolute deadline before invoking the plugin.
- Request digest is SHA-256 over RFC 8785 JCS canonical JSON excluding only `trace_context`; all other fields participate.
- Same authenticated tenant + invocation_id + digest: replay completed response or return bounded in-progress response.
- Same invocation_id with a different digest: terminal `INVOCATION_ID_REUSED`.
- A plugin worker crash before durable completion may cause inference to be recomputed after lease expiry. This can duplicate model-provider cost, but the plugin has no protected side effects.

### Guard operation

- Runtime creates and persists one opaque idempotency key for each admitted proposal before calling Guard.
- The key is stable across HTTP/Activity retries and is not derived from attempt_id.
- Guard scopes the key by tenant and compares request_hash. Same key + same request returns the same operation_id; same key + different request returns `409 IDEMPOTENCY_KEY_REUSED`.
- Runtime stores operation_id as soon as received. If the response is lost, Runtime repeats the same idempotent submission and then queries that operation.
- `action_hash` is an authorization binding, not an idempotency key. Distinct user intents may have identical action hashes.

## 5. Temporal Activity retry policy

Every Activity must declare StartToClose, ScheduleToClose, maximum attempts, backoff, and non-retryable error types. The retry deadline cannot exceed the immutable Decision Turn deadline or the Run's remaining budget.

| Activity | Safe retry condition | Stable identity |
|---|---|---|
| `InvokeDecision` | Only transient transport/dependency errors, RATE_LIMITED, or INVOCATION_IN_PROGRESS; stop at deadline | Same invocation_id + request digest |
| `EnsureGuardOperation` | Network ambiguity / transient 5xx only; same request and key | Same idempotency_key; same returned operation_id |
| `GetOperationStatus` | Read-only query; bounded retry | Same operation_id |
| `WaitForApproval` | Wait on Temporal Signal/Update; no model retry loop | Same approval/operation reference |
| `PersistRunProjection` | Idempotent projection upsert | Same source event / operation version |

Do not retry malformed request/response, unknown protocol/capability/schema version, authentication/authorization failures, invocation ID conflicts, idempotency-key payload conflicts, expired deadline, or policy denial.

The Runtime must not define a generic `DispatchProviderOperation` Activity that independently calls the provider. Guard submission creates/ensures an Operation; the Trusted Executor dispatches under Guard's Permit/Operation Journal protocol.

## 6. EngageGuard Operation state and UNKNOWN

EngageGuard is authoritative for Operation states. Runtime stores a read/query projection only.

| Guard state / result | Runtime behavior |
|---|---|
| REQUESTED / WAITING_APPROVAL / AUTHORIZED | Wait for Guard's next authoritative event or query |
| CLAIMED / DISPATCHING | Wait; do not submit another operation |
| SUCCEEDED | Accept only a trusted Receipt reference/hash; continue Workflow |
| FAILED_CONFIRMED | Treat current Operation as terminal. A new intent requires fresh Guard authorization, unless Guard explicitly exposes a Guard-owned controlled recovery path |
| UNKNOWN | Block all blind redispatch; query/reconcile the same operation_id |
| RECONCILING | Wait for Guard reconciliation; no new dispatch |
| MANUAL_REVIEW | Pause for authorized human resolution; no automatic retry |
| DENIED / REJECTED / EXPIRED / CANCELLED | Stop the proposal path; do not bypass Guard |

A timeout or lost ACK after the request may have reached Guard is an ambiguous transport outcome, not a failed operation. Runtime repeats only the idempotent EnsureGuardOperation request with the same key, then queries the same operation_id. It never creates a new key or operation to escape UNKNOWN.

Only EngageGuard/Reconciler may determine whether an external side effect is safe to recover. If a provider supports neither idempotency nor status query, UNKNOWN must remain unresolved or move to MANUAL_REVIEW; no automatic retry.

## 7. Cancellation

Temporal cancellation stops or requests cancellation of Workflow/Activity work. It does not prove that a Guard Operation or provider side effect was cancelled. If a Guard Operation may already be CLAIMED/DISPATCHING, Runtime keeps the operation correlation and obtains the authoritative Guard outcome. Guard/Executor own cancellation and reconciliation of the external operation. A completed external side effect is not rolled back by Workflow cancellation.

## 8. Error namespaces

Do not reuse one service's error envelope as another service's domain model.

- Decision Plugin errors: `protocol/v0.1/schemas/decision-turn-error.schema.json`.
- Runtime errors: Run/Task/Workflow lifecycle errors owned by Runtime.
- EngageGuard errors: Action, authorization, approval, Permit, idempotency, and Operation errors owned by Guard.
- Temporal failures: SDK/application Activity failures mapped by Runtime into its own typed failure categories.

Error code is machine-readable and stable. Human-readable message is diagnostic and not a retry instruction. Runtime retry decisions are based on the typed error category, Activity policy, remaining deadline, and authoritative operation state.

## 9. P0 conformance / fault-injection matrix

| ID | Scenario | Required result |
|---|---|---|
| P01 | Go, Python, TypeScript validate same valid request/response fixtures | Same accept result |
| P02 | Unknown protocol/capability/schema version | Fail closed; no Guard call |
| P03 | Extra field or mixed response union | Reject whole response; no Guard call |
| P04 | One proposal in a multi-proposal response is invalid | Reject whole response before any submission |
| P05 | Same invocation_id, same digest, completed | Replay stored response |
| P06 | Same invocation_id, different digest | INVOCATION_ID_REUSED; no model execution |
| P07 | Decision Activity retry after lost ACK | Same invocation_id/deadline/digest |
| P08 | Guard accepted ActionRequest but HTTP ACK lost | Same idempotency key returns same operation_id |
| P09 | Same Guard key, changed payload | 409; never create second operation |
| P10 | Guard Operation is UNKNOWN / RECONCILING | No redispatch; query/reconcile same operation_id |
| P11 | Provider success but receipt ACK lost | UNKNOWN until Guard verifies receipt/provider evidence |
| P12 | Runtime Activity retries | No new runtime_attempt_id or Guard attempt_id inferred from Temporal counter |
| P13 | Workflow cancelled while provider operation is dispatching | Keep correlation; do not claim rollback/cancel success |
| P14 | Old Executor/Worker reports with stale fencing token | Guard rejects stale state mutation |
| P15 | Guard returns MANUAL_REVIEW | Workflow pauses; no automatic retry |

## 10. Exit gate

- Canonical schema and golden fixtures are pinned to an immutable Agent Decision commit.
- Go Runtime, Python host, and TypeScript adapter pass the same fixture suite.
- Identifier ownership is explicit and persisted before network calls.
- Decision Activity and Guard submission retries reuse stable idempotency identities.
- Runtime cannot call protected providers directly.
- UNKNOWN, RECONCILING, and MANUAL_REVIEW block blind redispatch.
- Lost ACK, restart, cancellation, duplicate start, and stale-worker fault injection pass.
