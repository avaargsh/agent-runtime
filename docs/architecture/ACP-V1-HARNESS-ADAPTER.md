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
6. No `session/new` or `session/prompt` is wired: duplicate Session/Run creation and lost prompt ACK are out of scope until durable preparation and fencing exist.

## Required next P0 slices (not implemented)

**P0-A: persistent binding and creation journal**
- Add a Runtime-owned PostgreSQL 17 migration and tenant-scoped repository for Run/Attempt ↔ ACP AgentSessionID, harness kind, working directory and capability snapshot.
- Persist a UNIQUE, immutable logical session creation identity *before* invoking `session/new` and a confirmed result afterward. Persist UNKNOWN after ambiguous transport outcome. An unconfirmed creation MUST NOT be retried as another `session/new` without reconciliation/fencing.
- Under concurrent acceptance, restarts and lost ACK, assert one canonical Run and no competing bindings. Preserve original principal/release/tenant identity. Do not infer ACP agent identity from the process or session string.

**P0-B: secure bidirectional transport**
- A sandboxed, pinned executable / provider adapter for Codex and Claude Code, with bounded stderr/stdout, line framing, size limits, timeouts, version pinning and independent authentication.
- The RPC transport must process inbound `session/update` and `session/request_permission` while calls are pending. No auto-approval, arbitrary path access, terminal use or model-origin credentials.
- SecurityContext and policy decisions originate from authenticated ACP (control-plane) + Runtime + EngageGuard, not Agent messages.

**P0-C: replay/UNKNOWN and Temporal integration**
- Wire into a dedicated Temporal activity with a durable Run/Attempt identity, event inbox and operation journal references. Classify missing ACK as UNKNOWN and reconcile before reissue; never convert timeout to FAILED automatically.
- Validate cancel-vs-completion, worker restart, mTLS authority, cross-tenant denial and delayed completion; test that `session/load` does not authorize any protected operation.
- Add real Codex and Claude Code contract tests; neither is claimed compatible by the current fake RPC tests.

**P1:** explicit Session Event semantics, controlled reconnection and approval UI.
**P2:** UHP parity experiment behind a replaceable Adapter, not an internal domain model.

## Evidence levels

- Implemented: the pure Go seam in `internal/harness/acp` and deterministic fake-RPC/store tests.
- Locally verified: isolated Go standard-library `go test -race -count=1 ./...`, `go vet ./...`, `gofmt`. This is **not** the Go 1.26 full Runtime build.
- Repository exact-head CI: must be checked on this PR head; do not inherit a parent PR's prior green checks.
- Real environment: no PostgreSQL BindingStore, no real Agent executable, no Temporal workflow, no EngageGuard interaction, no real multi-device approval or staging receipt.

Keep this work **Draft** until the outstanding P0 requirements have independent evidence. The slice makes no claim of full ACP implementation, secure sandboxing, production permissions, restart recovery, or any exactly-once external effect.
