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
- Runtime exposes an authoritative lookup by run_intent_id + digest. A workflow-listing miss is not proof of absence. `ABSENT_UNCERTAIN` is not permission to re-dispatch. Until an authoritative final-absence barrier is implemented and agreed with ACP (#22), continue read-only reconciliation or escalate; do not infer `NOT_FOUND_FINAL` from a registry miss. A future final-absence barrier must durably fence earlier in-flight acceptance before same-identity retry.

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
| P17 | Lost StartRun ACK | Runtime registry lookup resolves FOUND or ABSENT_UNCERTAIN today; same-key retry after absence requires a future authoritative final-absence barrier (#22) |
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

## 13. Current Attempt transition design (Issue #73)

Status: **proposed contract only**. Baseline `59debed3a0bb310f141a3bfbad4059da9ef2e8c2` uses migration v13, one immutable generation-1 row in `runtime_current_attempts` per tenant/Run, and rejects a different Temporal execution or breaker epoch. This section does not enable transitions, rewrite v13, or change any wire schema.

### 13.1 Authority and identity

Runtime remains the sole writer of the current pointer. Keep immutable historical Attempt, Turn, Checkpoint, Harness binding and receipt identities. The canonical authority tuple is (tenant, Run, Attempt, Temporal execution ID, generation, RUN breaker epoch). An Activity retry or a Worker restart within the same Temporal execution does not advance generation. A new server execution, including reset or Continue-As-New, does not acquire authority automatically.

Prefer one current pointer plus immutable transition receipts over a second competing current-authority ledger. A single-Attempt uniqueness constraint cannot support explicit continuation; choosing the latest historical row by timestamp cannot establish authorization. Transition receipts are audit/idempotency records, never a second current pointer.

Proposed internal command, not a public endpoint: request transition with expected full authority tuple, stable transition ID, target Temporal execution identity from authenticated server metadata, immutable release/principal/policy reference, recovery approval reference and authoritative reconciliation references. Runtime generates the new Attempt ID. Bind the complete immutable command to a canonical digest (algorithm and encoding require review before implementation). The response is a persisted transition receipt with previous and new tuples; a receipt is historical evidence, not reusable live authority.

### 13.2 Transition protocol and failure behavior

1. Authenticate the initiating workload and delegated principal; derive tenant and Run from canonical records. ACP policy/approval must authorize this recovery. A Runtime recovery approval is not a Guard Permit. Do not accept Agent-supplied authority or a caller-provided execution UUID as authentication.
2. Close admission for the previous generation using a durable recovery barrier coordinated with all dispatch paths. Cancel or quiesce previous execution; cancellation alone is not proof that effects stopped. Prevent new admissions and establish authoritative outcomes for every prior admitted invocation, Guard submission, Harness prompt and relevant sandbox/provider action. Missing inventory, pending admissions, UNKNOWN, RECONCILING, MANUAL_REVIEW, or untrusted evidence blocks advancement. Guard/provider owners reconcile their own effects. Never manufacture a receipt or use new idempotency keys to escape ambiguity.
3. Obtain downstream revocation/fencing acknowledgements or verified quiescence under an agreed protocol. A PostgreSQL CAS cannot revoke an already-issued remote request. Until Decision, Guard and trusted enforcement points support the required fence or provable drain, advancement stays disabled. Do not hold a database lock across remote I/O.
4. Under the canonical Run lock and documented Run/breaker lock order, revalidate the full expected tuple, lifecycle, authorized recovery epoch, approval/digest, durable admission closure and still-valid reconciliation/fence evidence. Terminal Runs never reopen. In one transaction insert the new immutable Attempt, advance the sole pointer by exactly one with CAS, append immutable transition receipt and any delivery outbox record. Roll back all writes on conflict or failure. Activation of new work must also depend on the committed pointer and the agreed downstream fence. No new dispatch during an incomplete cutover.
5. Repeating the same transition ID and digest returns its immutable historical receipt, even if the pointer later advances; it does not authorize work. Changed digest, stale tuple, missing pointer, overflow, tenant mismatch or a competing transition rejects without new writes. After commit ACK loss, query that transition ID and digest; never infer failure from a timeout or allocate another transition. Preserve unresolved state if the registry cannot be read.
6. All new dispatch, Decision acceptance and Harness recovery must validate the current tuple and the recovery admission state; old receipts remain readable for audit/reconciliation, and exact historical cancellation is allowed only under its existing bounded contract. Prevent stale remote effects through target-side enforcement; a stale response must not mutate current Run state. Checkpoint/context transfer requires its own pinned, validated compatibility contract and cannot copy old execution authority.

### 13.3 Delivery sequence and acceptance

- B3a: review this design with ACP, Decision, EngageGuard and executor owners; agree authorization, prior-effect inventory/barrier, remote fencing and versioned receipt contracts. No schema or API change.
- B3b: test-first local persistence implementation using a new additive migration after v13; no automatic historical backfill. Preserve startup catalog attestation, composite tenant/Run foreign keys, immutable history and atomic rollback. Do not enable dispatch from generation >1 while consumers remain uncoordinated.
- B3c: coordinated consumers and authenticated recovery command; pin actual contract revisions and test remote admission/revocation races. Only after complete evidence may a development integration enable the transition; production G01–G05 remain separate.

| Case | Required evidence |
|---|---|
| Same Temporal execution replay / Activity retry | Original Attempt and generation retained |
| Concurrent transitions against same expected tuple | One committed winner, no orphan Attempt/receipt; loser conflicts |
| Commit ACK lost / restart | Same transition ID/digest returns original historical receipt; no second advance |
| Same transition ID with changed digest | Conflict; no state change |
| Missing pointer / legacy Attempt / stale generation / wrong tenant | Fail closed, no promotion or dispatch |
| Breaker changes during recovery / Run terminal | CAS denies; no new authority |
| Prior admission races with barrier / remote ACK lost | Advancement blocked until authoritative inventory and outcomes are complete |
| Previous Guard or provider effect UNKNOWN | No advancement or new operation; owner reconciliation only |
| Stale Decision/Harness/Guard request after cutover | Current consumers and actual remote enforcement reject new work; history retained |
| Migration rollback / catalog drift / generation overflow | No partial activation; startup or transition rejects |

Require actual RED before behavioral fixes, exact-head Go race/vet/gofmt and PostgreSQL 17 integration, real Temporal restart/replay and relevant cross-service fault-injection evidence before enabling transitions. A design-only merge or local CAS test does not establish production authorization or external fencing.
