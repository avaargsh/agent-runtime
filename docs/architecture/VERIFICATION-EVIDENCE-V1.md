# Verification Manifest & Evidence Assessment v1 — proposed, repository-local

- Status: **Draft / unratified** (Runtime [issue #27](https://github.com/avaargsh/agent-runtime/issues/27))
- Implementation: `internal/verification`, pure Go, no I/O, no added production route
- Base: Runtime Draft security parent [PR #21](https://github.com/avaargsh/agent-runtime/pull/21)
- Inspiration: Agent-friendly verification themes from ViteConf 2026; this is **our platform contract**, not an official Vite/Vitest protocol.

## Ownership and trust

1. Agent Control Panel (ACP Control Panel, **not** Agent Client Protocol) is the candidate authority for the approved required-check policy and release/manifest revision. This package receives a `Manifest` but **does not authenticate the caller or the manifest origin**.
2. Agent Runtime owns canonical Tenant/Run/Attempt identity and execution correlation. It may assess a Report against a separately trusted Manifest, but **does not manufacture verifier attestations**.
3. Dedicated verifier adapters run tests, lint, build, data validation or platform checks and generate digest-bound EvidenceRefs. The referenced bytes and provenance must be independently verified in a trusted artifact store before an assessment becomes admissible evidence. A URI and hash field alone do **not** prove immutability, signature, execution, or provenance.
4. EngageGuard retains sole protected-action Permit/Approval and action-level UNKNOWN reconciliation authority. Compute Control Panel retains Provider/Workload/Allocation and provider-side ComputeOperation authority.
5. **PASSED is not a merge, deploy, release, security or protected execution permission.** Cross-service final gating remains blocked.

## v1 immutable manifest identity

The verifier receives an externally pinned `Manifest` and a `Report`. Both carry:

- `schema_version = verification/v1`
- `tenant_id`, `run_id` (canonical Runtime Run), `attempt_id` (Runtime Attempt, **not** Guard executor_attempt_id)
- `source_revision`, `environment_digest` (lowercase SHA-256 hex)
- `manifest_digest` (lowercase SHA-256 hex, assumed authenticated/pinned by the caller)

The manifest also requires a nonempty, unique, ordered `required_check_ids` list. `Assess` rejects any report whose identity differs, any unsupported schema, unknown or duplicated checks, duplicated evidence IDs, invalid evidence digests, dangling references or unproven PASS/FAIL status.

A report consists of `checks` and `evidence`. Evidence refs are `id`, `uri`, and lowercase `sha256`. PASS and FAIL need at least one valid referenced EvidenceRef; non-PASS requires a reason. Results do not contain caller-supplied `overall_status`.

## Deterministic verdicts

| Observation | Pure contract verdict |
|---|---|
| All required checks present and PASSED with evidence refs | `PASSED` |
| Any explicit FAILED check with referenced evidence | `FAILED` (missing checks also returned separately) |
| Required check missing, NOT_RUN, SKIPPED or INCONCLUSIVE | `INCOMPLETE`, unless a proven failure exists |
| Invalid identity/version/digest/status/evidence reference | Error / fail closed; no verdict |
| Tool reports flaky test | Map to `INCONCLUSIVE`; do not count retry as proof of pass |
| Protected effect timed out / ACK lost | **Not a verification verdict**; query the appropriate Guard/Compute journal and retain UNKNOWN |

Important: this API evaluates **declared** required checks. It cannot know whether the authority omitted a mandatory check. An authenticated, immutable and approved Manifest is therefore a prerequisite to using a PASS downstream.

## Concrete next gates

- **V0 (this PR):** pure Go checks, negative fixtures, CI test run (including Go 1.26 race/vet/gofmt); no external service or storage proof.
- **V1:** authenticated manifest service, immutable revision and signed verifier receipts; strict JSON boundary decoder and size limits; redact secrets and validate artifact bytes/digest; policy-scoped query/inspection.
- **V2:** Runtime Run/Attempt persistence, durable event/outbox projection, retries and reboot testing with a real Temporal Server; no inferred final absence.
- **V3:** versioned ACP EvidenceRef interface, EngageGuard approval, Compute Workload/Allocation cost correlation, staging fault injection, real Coding Agent toolchain benchmark.

## Benchmark experiment (not yet run)

On a fixed corpus of real code-fix tasks, compare legacy CLI text-only feedback with a structured Verification Report adapter. Hold source, environment and test plan fixed; record task completion time, verification loop latency, number of tool invocations, cost/successful change, flaky false-fix rate, required-check coverage and evidence provenance. Do not extrapolate build speed to end-to-end Agent ROI without measuring this loop.
