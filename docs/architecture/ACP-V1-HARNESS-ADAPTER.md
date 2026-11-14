# Harness Adapter: Agent Client Protocol v1 (first slice)

Status: **experimental, Draft; not deployed and not production accepted**.

This document concerns **Agent Client Protocol (ACP)**, not the existing
`internal/acphttp` API, where ACP means **agent-control-panel**.
Protocol v1 reference:
- https://agentclientprotocol.com/protocol/v1/initialization
- https://agentclientprotocol.com/protocol/v1/session-setup
- https://agentclientprotocol.com/protocol/v1/cancellation
- https://agentclientprotocol.com/protocol/v1/security

## Responsibility boundaries

- Agent Control Panel: Tenant/Project, AgentRelease, SessionIdentity and RunIntent authority.
- Runtime + Temporal: canonical Run/Attempt, durable workflow lifecycle, Inbox, recovery and evidence correlations.
- `internal/harness/acp`: v1 version/capability negotiation and guarded existing-session recovery/cancel commands only.
- EngageGuard: any protected-action admission, Permit/Approval, Operation Journal and external side effects.
- Agent Client Protocol `session/request_permission`: a protocol-level UI request, **not** an EngageGuard Permit. This slice never implements auto-grant.
- No UHP/HarnessRouter dependency or competing Run authority.

## Implemented in this bounded slice

1. `initialize` requests v1 and no privileged client filesystem/terminal capabilities. A v2 (Draft) reply is rejected.
2. Omitted `agentCapabilities.loadSession` is treated as unsupported.
3. `Recover` uses only an authoritative, committed, tenant/Run-bound `BindingStore` record to call `session/load`. A successful load reports `SESSION_LOADED_OUTCOME_UNCERTAIN`, **never** an automatically retriable prompt or a completed Run.
4. `Cancel` sends the ACP v1 one-way `session/cancel` notification only after lookup. Reporting `CANCEL_SENT_UNCONFIRMED` does not claim process termination, Guard revocation or side-effect rollback.
5. Database outage, missing/unconfirmed or mismatched binding, failed load, lost transport reply, unsupported load capability and invalid tenant/Run identity remain `UNKNOWN_RECONCILE`.
6. No `session/new` or `session/prompt` is wired: a persistent pre-dispatch claim does not itself authorize an external call.
7. The Draft PostgreSQL v7/v8/v9 migration chain stores immutable Principal, Temporal Attempt and one Harness Claim with PREPARED→UNKNOWN→CONFIRMED semantics. `postgres.Store.LookupBinding` implements a **read-only** `BindingStore` that exposes only a confirmed tenant/Run/Attempt/Policy-bound Agent Session. UNKNOWN and missing bindings never authorize `session/load` or another `session/new`.
8. `NewStreamRPC` accepts an **already supplied** `io.ReadWriteCloser` (it does not spawn or authenticate a process). It uses newline-delimited JSON-RPC 2.0 and a 1 MiB maximum frame; it processes incoming messages while `Call` awaits a response, tracks request IDs and fails all outstanding calls on malformed, oversized or closed streams. Only one request/reply call may remain outstanding per connection; a concurrent Call fails immediately without killing the first call or preventing a one-way cancel notification. A cancelled Call/Notify also closes the entire stream, including a blocked write: partial delivery is ambiguous, so the connection must not be reused for another command. Untrusted `session/update` notifications enter a **bounded, non-durable** channel; overflow terminates the stream, rather than losing events silently.
9. Outbound methods are restricted to `initialize`, `session/load` and one-way `session/cancel`. Agent `session/request_permission` receives the v1 `cancelled` outcome with **no option selected**. Client filesystem and terminal requests are answered with JSON-RPC method-not-found. Unknown Agent notifications never grant authority. This is not an EngageGuard approval mechanism.
10. An integration test exercises the actual PostgreSQL claim + ACP v1 Client + bidirectional JSON-RPC bytes over `net.Pipe`: it denies unconfirmed sessions and an Agent's allow-once permission request during `session/load`, then delivers a best-effort cancellation on the confirmed session. It does not run a real Agent executable.

## Required next P0 slices (not implemented)

**P0-A: persistent binding and creation journal — Draft database slice implemented, external execution still gated**
- The Runtime-owned PostgreSQL v9 claim binds persisted Run/Attempt/Release/Policy and is unique per tenant+Run; a confirmed AgentSessionID is readable by the ACP Client only after a persisted UNKNOWN→CONFIRMED transition.
- `PREPARED`→`UNKNOWN` is committed **before** any hypothetical `session/new`; a lost dispatch ACK is never permission to retry blindly. The actual server-authenticated Temporal caller, pre-execution fencing, durable inbox/reconciliation and Agent capability attestation remain outside this PR.
- Cross-service ACK loss, concurrent Runtime replicas, long-running Agent process ownership and real worker/process restart still need independent evidence. Never infer Agent identity from a process or an opaque session string.

**P0-B: secure bidirectional transport — protocol framing slice implemented, process boundary NOT implemented**
- The transport reads bounded newline-delimited frames and responds to Agent permission requests with `cancelled`. It never starts a subprocess, grants capabilities, or automatically approves an Agent operation.
- Untrusted JSON-RPC `error.message` is decoded for protocol-type validation but never copied into a Runtime error, log or audit record by this adapter; numeric JSON-RPC error codes remain available for diagnosis. The enclosing error/result remains an uncertain recovery outcome, not a final Run failure.
- Still required: independently authenticated, pinned/sandboxed Codex or Claude-compatible executable, explicit working-directory allowlist, bounded stderr, subprocess kill/reap, OS-level read/write deadlines, and capability/credential isolation. The supplied `io.ReadWriteCloser` must already meet those operational requirements before production use.
- `session/update` is **not** an audit event or durable evidence merely because it was buffered. An independent Event Inbox consumer must validate, authorize, persist and correlate all event identities. The bounded queue closes on overflow. SecurityContext and all protected effects remain under authenticated ACP (control-plane) + Runtime + EngageGuard authority.

**P0-C: replay/UNKNOWN and Temporal integration**
- Wire into a dedicated Temporal activity with a durable Run/Attempt identity, event inbox and operation journal references. Classify missing ACK as UNKNOWN and reconcile before reissue; never convert timeout to FAILED automatically.
- Validate cancel-vs-completion, worker restart, mTLS authority, cross-tenant denial and delayed completion; test that `session/load` does not authorize any protected operation.
- Add real Codex and Claude Code contract tests; neither is claimed compatible by the current fake RPC tests.

**P1:** explicit Session Event semantics, controlled reconnection and approval UI.
**P2:** UHP parity experiment behind a replaceable Adapter, not an internal domain model.

## Evidence levels

- Implemented in Draft PR: ACP v1 fake/store seam, bounded default-deny JSON-RPC stream, PostgreSQL v9 confirmed-binding read, and their isolated integration tests.
- Repository evidence: Go 1.26 race/vet/gofmt and PostgreSQL 17 integration are run in GitHub Actions. Verify the **latest exact PR synthetic merge tree** before considering a change accepted; no parent CI or historical GREEN may be inherited.
- Not yet accepted: actual external Codex/Claude process; sandbox, independent authentication or process lifecycle; protected actions; a real Harness `session/new`; Temporal worker/Agent crash + ambiguous session ACK; approval/UI; or staging receipt. PostgreSQL tests do not confer production credentials or attest isolated roles.

Keep this work **Draft** until the outstanding P0 requirements have independent evidence. The slice makes no claim of full ACP implementation, secure sandboxing, production permissions, restart recovery, or any exactly-once external effect.
