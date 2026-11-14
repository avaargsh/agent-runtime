# Summary

What user-visible or architectural behavior changes, and why?

## Repository-specific authority / safety

- Runtime owns Run/Task/Attempt, durable execution receipts and Event Inbox; Temporal owns Workflow history/retries.
- Lost ACK, cancellation, deadline, restart and UNKNOWN recovery must not duplicate external effects; Guard alone authorizes protected effects.
- Real Agent subprocess/ACP v1 and staging G01/G05 claims require real-process evidence, not isolated adapter tests.

## Governance metadata

For a ready-to-merge PR targeting `main`, write the current 40-character base and head SHAs in the first field as `main base=<SHA> head=<SHA>`. Update after source/target changes. Draft PRs may remain incomplete until ready.

- Target branch (`main` or internal feature parent); exact base/head commit SHAs:
- Change class (docs-only / contract / migration / runtime / protected effect / provider):

- Affected domain / sole authoritative writer:
- Public API/Schema source repository + pinned source commit:
- Governance gate(s): G01 / G02 / G03 / G04 / G05 / none (explain)
- Linked blocking Issue and prerequisite PRs:
- Base branch and PR stack dependency:
- Migration or compatibility version; client impact:

## Evidence (link real CI runs)

- Test/CI evidence at exact HEAD (run URL or explicit no-workflow reason):
- Authorization/recovery negative-case evidence or explained N/A:

- [ ] Unit tests and negative-path assertions, with source SHA
- [ ] Contract/schema fixtures shared with actual consumers
- [ ] Integration tests (DB, Temporal, Guard, provider) where changed
- [ ] Lost ACK / UNKNOWN / restart / fencing / cancellation cases as applicable
- [ ] Tenant authorization and revocation checks where changed
- [ ] No evidence extrapolated from tests that were not executed
- [ ] Evidence grade recorded: designed / implemented / exact-head repository CI / real-service E2E / deployment acceptance

## Execution and side-effect safety

- [ ] No duplicate authority writer or cross-service DB mutation
- [ ] Idempotency identity and request digest persist before network effect
- [ ] Unknown external result never causes blind dispatch
- [ ] New ActionHash version / canonicalization changes have golden vectors
- [ ] Protected actions use Guard Permit and trusted enforcement point
- [ ] Not applicable (explain)

## Delivery / rollback

- Remaining blockers and explicit non-goals:
- Backward compatibility and rollback:
- Main promotion vs internal-only merge decision, with rationale:
- Draft until owner/consumer cross-repo gates are met:
- Required GitHub branch rules/required status checks verified independently (or current status UNKNOWN):

> This template is a review checklist, not an enforced required status check or approval of any G01–G05 gate.
