# Runtime Guard Execution Authority API

## Purpose and trust boundary

The Guard execution-authority API exposes a minimal, point-in-time projection of the Runtime-owned Run, current Attempt and current Turn. It is a read-only identity observation, not Approval, Risk, Permit, an authorization decision, or permission to execute an external effect.

The service is isolated from ACP RunIntent writes and Decision's business-authority listener. It accepts exactly one provisioned Guard SPIFFE identity for exactly one configured tenant. Tenant scope is configuration, never a request header or query parameter.

## Endpoint

`GET /internal/v1/guard-execution-authority/{run_id}/{turn_id}`

Both path identifiers must be canonical lower-case hyphenated UUIDs. Query parameters and request bodies are rejected.

Success returns `runtime.guard-execution-authority.v1` with the canonical Run, Temporal execution, Runtime Attempt and current Turn identities plus generation and breaker fences. Only the latest persisted Turn for the one current generation-one Attempt can be returned. A later Turn supersedes the prior Turn. The endpoint never returns approval, permit, risk, capability or provider credentials.

Verified missing, stale, foreign, ambiguous, superseded, terminal or breaker-denied identities return 403 without cross-tenant existence leakage. Invalid request syntax returns 400, an unauthenticated peer returns 401, unsupported methods return 405, and actual database/authority failures return 503. Responses use `Cache-Control: no-store`.

## Deployment configuration

The dedicated process reads:

- `RUNTIME_GUARD_AUTHORITY_DATABASE_URL`: a dedicated database credential with SELECT-only access to the schema and the six authority relations: `runs`, `runtime_run_principal_snapshots`, `runtime_run_attempts`, `runtime_current_attempts`, `runtime_decision_turns`, and `runtime_circuit_breakers`.
- `RUNTIME_GUARD_AUTHORITY_TLS_CERT`, `RUNTIME_GUARD_AUTHORITY_TLS_KEY`, `RUNTIME_GUARD_AUTHORITY_CLIENT_CA`: TLS 1.3 server certificate and client trust roots.
- `RUNTIME_GUARD_AUTHORITY_PEER_SPIFFE_ID`: one exact Guard workload SPIFFE URI.
- `RUNTIME_GUARD_AUTHORITY_TENANT`: one explicitly provisioned tenant.
- `RUNTIME_GUARD_AUTHORITY_LISTEN_ADDR`: optional listener address; defaults to `:8446` (all pod interfaces).

The process sets `default_transaction_read_only=on` and does not run migrations. This is defense in depth, not a substitute for a database role that lacks INSERT/UPDATE/DELETE/TRUNCATE/DDL privileges. Do not reuse the ACP or Decision database credentials.

## Consumer obligations

The result is a point-in-time observation. It can become stale immediately after the read. EngageGuard must independently recheck ACP, Decision, Approval, Risk, revocation and policy at Permit issuance/claim, and an independently deployed Executor PEP must verify the exact action and current fences at effect time. Provider ACK loss remains UNKNOWN until authoritative receipt reconciliation. Runtime's local observation is never a remote target-side fence.

Generation greater than one, historical Attempt backfill, Permit issuance, positive protected-write authorization and Provider dispatch are explicitly unsupported.
