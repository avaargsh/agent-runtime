# ACP v1 Harness session claim: PostgreSQL v9

Status: **Draft; repository integration slice only. No real Harness dispatch**.

This document uses ACP = **Agent Client Protocol**. The existing
`internal/acphttp` package means **agent-control-panel** instead.

## Ownership

Runtime is the authority for canonical Run, Attempt and the pre-dispatch
session creation claim; Temporal drives workflow retries, not arbitrary
re-execution of external Agent effects. ACP (control-plane) owns RunIntent,
SessionIdentity, AgentRelease and authenticated initiating principal/policy
claims. EngageGuard remains the only protected-action Permit/Approval and
external side-effect authority.

The v9 database migration is additive, preserving migrations 0001-0008.
Its table `runtime_harness_session_claims` has a tenant+Run primary key and
tenant+Run foreign key, plus a unique confirmed Agent session per pinned
Harness instance. Identity columns are immutable; row deletion, TRUNCATE
and forbidden lifecycle changes fail closed in PostgreSQL trigger checks.

## Durable state machine

`PREPARED` (persisted, no network call) -> `UNKNOWN` (one successful
`BeginHarnessSessionDispatch` CAS grant persisted **before** network I/O)
-> `CONFIRMED` (trusted reply from that one grant).

This is a deliberately conservative model. A crash after the CAS but
before the actual Agent call can leave a never-dispatched UNKNOWN record.
That record requires reconciliation/operator review, NOT blind retry.
A transaction timeout or lost ACK does not prove the operation failed.

### API obligations

- `ClaimHarnessSession`: require tenant-bound persisted RUNNING Run, matching
  AgentRelease and canonical RunIntent SHA-256 digest, **and an immutable
  `acp-principal/v1` Runtime snapshot for the exact tenant/Run with matching
  PolicyRevision**. The schema-qualified snapshot relation uses the same
  trusted startup schema as the Run and Claim. The v8 Runtime/Temporal
  Attempt must match tenant, Run, AttemptID and workflow; caller-supplied
  AttemptID alone cannot authorize creation. A legacy Run lacking that
  snapshot cannot create a Harness session claim. Same entire claim replay
  returns the existing state; changing Attempt, Harness instance, release,
  policy revision, digest, or CWD conflicts.
- `BeginHarnessSessionDispatch`: the only creation grant, atomic
  PREPARED->UNKNOWN and permitted once. It rechecks the same persisted
  tenant/Run Principal/Policy snapshot and Temporal Attempt at dispatch time. Missing or changed
  claim, missing or mismatched principal/policy, cancelled Run, stale digest
  or wrong tenant cannot gain dispatch authority. A second call after the
  first grant returns false even if the first caller lost its ACK.
- `ConfirmHarnessSession`: UNKNOWN->CONFIRMED with returned Agent Session ID.
  Same response replay is idempotent; a different ID conflicts.
- `ReadHarnessSessionClaim`: tenant-scoped read; a database miss is **not**
  authoritative final absence. Does not infer Agent state from in-memory
  sessions or Temporal workflow listing.

## Evidence and limitations

- Repository tests verify concurrent claim/dispatch, exact identity replay,
  cross-tenant mismatch, status and digest validation, persisted principal/policy
  rejection and `pg_temp` authority spoofing, simulated lost ACK,
  store recreation, confirmation conflicts, and migration immutability.
- These tests use PostgreSQL and no external Harness executable. They do
  not prove a real session/new, Codex or Claude Code compatibility, true
  process recovery, temporal worker crash, remote isolation, or permissions.
- Claim and dispatch now require a persisted v8 Runtime/Temporal Attempt.
  This does not authenticate the external Temporal Server execution
  provenance or resolve post-commit cancellation. Do not wire the
  `acp.BindingStore` adapter to production on this DB check alone.
- PolicyRevision is now **compared against the persisted v7 immutable
  PrincipalSnapshot** for both creation and dispatch. This proves only that
  those database records agree; it does **not** authenticate the original ACP
  workload issuer or initiating actor, prove current Attempt validity, or
  issue an EngageGuard Permit. Real mTLS-backed principal provisioning,
  revocation and independent least-privilege database roles remain gated.
- This schema uses the existing Runtime PostgreSQL role/search_path setup.
  An independent low-privilege DB role, trigger/catalog drift attestation,
  pg_temp/search_path shadowing and restore tests remain separate security
  gates; database owner rights are not a tamper-proof ledger.
- A successful DB CAS can still race with Run cancellation *after* commit.
  Real dispatch needs a separate current authorization/fencing strategy
  immediately before external execution, and protected effects always
  require EngageGuard.
- No automatic CLAIMED/UNKNOWN timeout downgrade to FAILED or PREPARED.

## Remaining gates before merge

1. Exact-head Go 1.26 tests, PostgreSQL 17 integration, race, vet, formatting.
2. Independent code/security review; migration v4->v5->v6->v9 upgrade receipts.
3. Server-authenticated Temporal execution provenance, current Attempt
   fencing, and least-privilege catalog/trigger/search_path attestations.
4. Safe bidirectional ACP JSON-RPC transport, process isolation, session
   events, permission requests denied by default, and real Codex/Claude
   Code compatibility tests.
5. Temporal server worker-restart/ACK-loss test and EngageGuard G03/G05
   protected-action tests, with separate staging evidence.

Do not label this slice production ready or merge stacked parents until
their own review/acceptance gates close.
