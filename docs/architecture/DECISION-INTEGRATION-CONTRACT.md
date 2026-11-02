# Decision ↔ Runtime ↔ EngageGuard Integration Contract v0.1

Status: Proposed P0 integration contract.

## 1. Authorities

| Concern | Authority | Non-owner |
|---|---|---|
| Run / Task / Runtime Attempt | Agent Runtime | Agent Decision, EngageGuard |
| Workflow history / replay / timers / Activity retry | Temporal | Agent Decision |
| One bounded model Decision Turn | Agent Decision | Temporal |
| Action authorization / risk / approval / Permit | EngageGuard | Runtime, Agent Decision |
| Protected Action authorization, Permit, Action Operation Journal and action-level UNKNOWN/reconciliation | EngageGuard | Runtime, Agent Decision |
| ComputeWorkload, Allocation, ComputeOperation and provider-side UNKNOWN/reconciliation | Compute Control Plane | Runtime, EngageGuard |
| Actual protected side effect and trusted receipt | Capability-specific trusted enforcement point (Compute CP for compute mutations) / Provider | Agent Decision, Runtime |

No service may infer another service's authoritative state from a timeout, missing ACK, or local projection.

## 2. Identifier ownership and lifetime

| Identifier | Creator / authority | Lifetime and retry rule |
|---|---|---|
| `run_intent_id` | Agent Control Plane | One accepted business request; Runtime consumes it as the Run-start idempotency identity |
| `run_id` | Runtime | One logical Run per accepted run_intent_id; stable across all retries |
| `workflow_id` | Runtime mapping to Temporal | `agent-run/v1/<run_id>`; run_id must be globally unique in the Temporal namespace; never random per retry |
| `turn_id` | Runtime | One logical Decision Turn |
| `invocation_id` | Runtime | One logical plugin invocation; stable across Activity retries |
| `run_attempt_id` | Runtime | One Runtime-owned Task/Run execution attempt; does not change for Temporal Activity retries |
| Temporal Activity attempt counter | Temporal | SDK metadata only; never used as a business identifier |
| `proposal_id` | Agent Decision | Stable within the stored response for one invocation; unique within that invocation |
| `guard_submission_key` (ActionRequest `Idempotency-Key`) | Runtime | Persisted once per admitted proposal; reused for each Guard submission retry; distinct from action_hash and operation_id |
| `operation_id` | EngageGuard | Created by Guard on first accepted submission; same tenant + key + request digest resolves the same Operation |
| `executor_attempt_id` (receipt wire field: `attempt_id`) | EngageGuard / Trusted Executor | One concrete protected-action execution attempt; never alias to run_attempt_id or Temporal Activity attempt |
| `receipt_id` | Trusted Executor | One immutable execution receipt |
| `compute_operation_id` | Compute Control Plane | One immutable provider-side compute mutation; distinct from Action operation_id |

The EngageGuard receipt `attempt_id` is the Guard-owned executor attempt (canonical name executor_attempt_id). Runtime's run_attempt_id is a different business attempt, and Temporal's numeric Activity attempt is SDK metadata only. Runtime guarantees run_id uniqueness within the Temporal namespace and derives workflow_id exactly as agent-run/v1/<run_id>.

## 2.1 RunIntent start handshake

- Agent Control Plane owns run_intent_id, the tenant/principal-scoped idempotency key and canonical request digest.
- Runtime accepts run_intent_id and the exact request digest. In one Runtime PostgreSQL transaction it creates run_id and the unique run_intent_id → run_id mapping before starting the Temporal Workflow.
- Same run_intent_id + same digest returns the same run_id and workflow_id. Same run_intent_id + different digest returns 409; Runtime must not create a second Run.
- Runtime derives workflow_id as agent-run/v1/<run_id>. Agent Control Plane never sends or generates workflow_id.
- Runtime exposes an authoritative lookup by run_intent_id + digest. A workflow-listing miss is not proof of absence. Only a final not-found from the durable Runtime idempotency registry permits ACP to re-dispatch the same RunIntent identity and digest.

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

- Runtime creates and durably persists one guard_submission_key per admitted proposal before calling Guard. The Guard ActionRequest includes this opaque key in the `Idempotency-Key` header; the plugin must not set it.
- The same guard_submission_key and byte-equivalent logical ActionRequest are reused across HTTP/Temporal Activity retries. The key is not derived from run_attempt_id or a Temporal Activity counter.
- Guard enforces tenant + guard_submission_key uniqueness and compares canonical ActionRequest digest. Same key + same request returns the original Guard-generated operation_id; same key + different request/binding returns 409 IDEMPOTENCY_KEY_REUSED.
- Guard creates operation_id and executor_attempt_id, owns the OperationJournal record and trusted Receipt. Runtime persists the returned operation_id for query/reconciliation; it must not invent one after an ACK loss.
- action_hash is an authorization binding, not an idempotency key. Distinct user intents may have identical action hashes.

## 5. Temporal Activity retry policy

Every Activity must declare StartToClose, ScheduleToClose, maximum attempts, backoff, and non-retryable error types. The retry deadline cannot exceed the immutable Decision Turn deadline or the Run's remaining budget.

| Activity | Safe retry condition | Stable identity |
|---|---|---|
| `InvokeDecision` | Only transient transport/dependency errors, RATE_LIMITED, or INVOCATION_IN_PROGRESS; stop at deadline | Same invocation_id + request digest |
| `EnsureGuardOperation` | Network ambiguity / transient 5xx only; same request and persisted key | Same guard_submission_key; Guard returns operation_id |
| `GetOperationStatus` | Read-only query; bounded retry | Same operation_id |
| `WaitForApproval` | Wait on Temporal Signal/Update; no model retry loop | Same approval/operation reference |
| `PersistRunProjection` | Idempotent projection upsert | Same source event / operation version |

Do not retry malformed request/response, unknown protocol/capability/schema version, authentication/authorization failures, invocation ID conflicts, Guard Idempotency-Key payload conflicts, expired deadline, or policy denial.

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

A timeout or lost ACK after the request may have reached Guard is an ambiguous transport outcome, not a failed operation. Runtime repeats only the idempotent EnsureGuardOperation request with the same guard_submission_key, recovers the original operation_id, then queries that operation_id. It never creates a new key or action operation to escape UNKNOWN.

Only the service that owns the side effect may determine whether it is safe to recover. EngageGuard reconciles the protected Action Operation; Compute CP reconciles a provider-side ComputeOperation. If a provider supports neither idempotency nor status query, the ComputeOperation remains UNKNOWN or moves to MANUAL_REVIEW; no automatic retry.

## 7. Compute and Sandbox capacity integration

- For non-sandbox compute required to execute a Run, Runtime calls Compute CP with owner_ref = agent-runtime/run/<run_id> and a stable Idempotency-Key generated once per logical capacity request. Compute CP returns workload_id and allocation_id references; Runtime never creates provider resources directly.
- For sandboxed execution, Runtime calls SandboxProvider Claim. SandboxProvider is the sole Compute CP caller for that claim and uses owner_ref = sandbox-provider/sandbox-claim/<claim_id>. Runtime must not issue a parallel Compute request for the same sandbox claim.
- For an Agent-proposed protected compute action, Runtime submits ActionRequest to EngageGuard. The Permit audience is compute-control-panel; Compute CP validates the delegated Permit/action binding at its enforcement point, then owns compute_operation_id and provider reconciliation.
- Guard operation_id and Compute compute_operation_id are separate. Guard owns authorization, Action Operation and executor receipt; Compute CP owns Workload, Allocation and provider-side ComputeOperation. The Guard operation may link to compute_operation_id, but neither service overwrites the other's state.
- A ComputeWorkload 202 means the request is durably accepted, not that an Allocation is BOUND. Runtime may treat compute as ready only after an authoritative Compute CP Allocation reference/status says BOUND.

## 8. Cancellation

Temporal cancellation stops or requests cancellation of Workflow/Activity work. It does not prove that a Guard Operation or provider side effect was cancelled. If a Guard Operation may already be CLAIMED/DISPATCHING, Runtime keeps the operation correlation and obtains the authoritative Guard outcome. Guard/Executor own cancellation and reconciliation of the external operation. A completed external side effect is not rolled back by Workflow cancellation.

## 9. Error namespaces

Do not reuse one service's error envelope as another service's domain model.

- Decision Plugin errors: `protocol/v0.1/schemas/decision-turn-error.schema.json`.
- Runtime errors: Run/Task/Workflow lifecycle errors owned by Runtime.
- EngageGuard errors: Action, authorization, approval, Permit, idempotency, and Operation errors owned by Guard.
- Temporal failures: SDK/application Activity failures mapped by Runtime into its own typed failure categories.

Error code is machine-readable and stable. Human-readable message is diagnostic and not a retry instruction. Runtime retry decisions are based on the typed error category, Activity policy, remaining deadline, and authoritative operation state.

## 10. P0 conformance / fault-injection matrix

| ID | Scenario | Required result |
|---|---|---|
| P01 | Go, Python, TypeScript validate same valid request/response fixtures | Same accept result |
| P02 | Unknown protocol/capability/schema version | Fail closed; no Guard call |
| P03 | Extra field or mixed response union | Reject whole response; no Guard call |
| P04 | One proposal in a multi-proposal response is invalid | Reject whole response before any submission |
| P05 | Same invocation_id, same digest, completed | Replay stored response |
| P06 | Same invocation_id, different digest | INVOCATION_ID_REUSED; no model execution |
| P07 | Decision Activity retry after lost ACK | Same invocation_id/deadline/digest |
| P08 | Guard accepted ActionRequest but HTTP ACK lost | Same persisted guard_submission_key returns the same Guard-generated operation_id/record |
| P09 | Same Guard submission key, changed payload | 409; never create second operation |
| P10 | Guard Operation is UNKNOWN / RECONCILING | No redispatch; query/reconcile same operation_id |
| P11 | Provider success but receipt ACK lost | UNKNOWN until the owning enforcement point verifies receipt/provider evidence |
| P12 | Runtime Activity retries | No new run_attempt_id or executor_attempt_id is inferred from Temporal counter |
| P13 | Workflow cancelled while provider operation is dispatching | Keep correlation; do not claim rollback/cancel success |
| P14 | Old Executor/Worker reports with stale fencing token | Guard rejects stale state mutation |
| P15 | Guard returns MANUAL_REVIEW | Workflow pauses; no automatic retry |
| P16 | Duplicate StartRun for same run_intent_id/digest | Same run_id and workflow_id; no second Run |
| P17 | Lost StartRun ACK | Runtime registry lookup resolves found / final not-found / indeterminate; only final not-found permits same-key retry |
| P18 | Compute create ACK lost | Same Compute Idempotency-Key returns same workload_id; Compute CP reconciles compute_operation_id |
| P19 | Sandbox and Runtime both request capacity for one claim | Test rejects the duplicate path; SandboxProvider is the sole Compute requester |

## 11. Exit gate

- Canonical schema and golden fixtures are pinned to an immutable Agent Decision commit.
- Go Runtime, Python host, and TypeScript adapter pass the same fixture suite.
- Identifier ownership is explicit and persisted before network calls.
- Decision Activity and Guard submission retries reuse stable idempotency identities.
- Runtime cannot call protected providers directly.
- UNKNOWN, RECONCILING, and MANUAL_REVIEW block blind redispatch.
- Lost ACK, restart, cancellation, duplicate start, and stale-worker fault injection pass.


## 12. Cross-repository compatibility gate (2026-11-02 independent review)

The previous Runtime draft assumed the caller could allocate `action_operation_id` as the Guard wire `operation_id`. This conflicts with the existing EngageGuard v2.1 RFC, which defines a Guard-generated `operation_id` and a client-generated `Idempotency-Key`. This draft now follows the latter behavior as the integration baseline; **do not ship the Guard adapter until the actual EngageGuard HTTP contract and idempotency-lookup behavior are confirmed**. A timeout must not cause a new key to be generated. Test the lost-ACK scenario against a real Guard implementation before marking this PR Ready for Review.

The pure-Go `internal/recovery` package is limited to safe consumer decisions and has no authority to dispatch an external side effect. Its green tests do not constitute a Temporal replay or provider-side recovery test.
