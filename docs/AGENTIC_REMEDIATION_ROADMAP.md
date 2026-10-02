# Quanta — Agentic Remediation: Design Principles and Roadmap

What the remediation engine has adopted from reference agentic-operations architectures,
what is shipped, and what is planned. Written from first principles of the product; no
third-party material is reproduced.

## Principles

1. **Signal to action to proof.** Every remediation moves through observe, prioritize,
   remediate, enforce, verify. Stopping at "a ticket exists" is not closure.
2. **Humans govern, agents propose.** Agents draft artifacts and verdicts; people approve,
   supervise exceptions, and own outcomes (human-on-the-loop). No agent holds execution tools.
3. **Narrow agents behind an orchestrator.** One orchestrator classifies intent and plans;
   specialised workers (normalise, enrich, plan, domain fixers, verifier) each do one job
   with the minimum tools.
4. **Deterministic gates around probabilistic output.** A model drafts; plain code checks.
   Anything that can be checked mechanically is checked mechanically, every time.
5. **Staged blast radius.** Change reaches a small ring first, soaks, then widens.
6. **Evidence by default.** Every action leaves an audit-ready record without extra effort.

## Shipped

| Capability | Where |
|---|---|
| Deterministic playbook safety lint (12 rules); approval refused while it fails | `remediation/validation/playbook_lint.py`, approve route |
| Closed-loop verification of triggered fixes from the next scan (verified / still-present / awaiting-rescan) | `remediation/verification/closed_loop.py`, `/api/remediation-verification` |
| Evidence pack per remediation (finding, approval trail, reviewed artifact, lint, outcome) | `/api/remediation-approvals/{id}/evidence` |
| Staged rollout rings (canary, pilot, broad, emergency) resolved per finding; fixers take a `rollout_ring` variable | `remediation/config/remediation_policy.yaml`, policy engine |
| Safety and outcome column on the Approvals page | `pages/remediationApprovals.js` |
| Container image, compose file, PostgreSQL via `QUANTA_DATABASE_URL` | `Dockerfile`, `docker-compose.yml`, `docs/DEPLOYMENT_ARCHITECTURE.md` |

## Planned, in priority order

1. **Remediation health tiers.** Classify each domain/playbook family by outcome history:
   high-fidelity (fixes hold), healthy, flaky (reappears), low-value. Feed tier into
   risk tier so a fix that keeps failing stops being auto-approvable.
2. **Verdict taxonomy on findings.** Per-finding states beyond severity: confirmed
   exploitable, possible, likely false positive; overall confidence for correlated chains.
3. **Scheduled triggers.** Cron-style re-verification and re-scan requests after a
   maintenance window closes, so verification does not depend on someone remembering.
4. **Rollback validator.** Pre-approval check that the documented rollback is executable
   (referenced snapshot/package exists), not just present.
5. **Execution verifier hooks.** Optional read-only post-change probes (service state,
   package version) that a customer's own automation reports back, closing the loop
   faster than waiting for the next scan.
6. **Orchestrator as a first-class component.** Intent classification and plan synthesis
   across fixers, with a policy knowledge base, replacing the fixed command sequence.
7. **Queue and worker pool** so scans, exports and pipeline runs stop blocking requests
   (prerequisite for multiple replicas).
8. **Policy-as-code with exception workflow**: controls expressed as reviewable rules, with
   time-boxed exceptions and break-glass that is always audited.

## What stays true

Fixers remain `Read, Write` only. Quanta never executes a fix, so "verified" always means
"the next scan no longer reports it", labelled as evidence rather than proof.

## Proving value: baseline first

A pilot is only convincing if it is measured against the customer's own starting point,
captured before the first agent runs. `/api/remediation-metrics` reports, from real
approval history only: requests, approvals, triggers, average days request-to-approval and
request-to-trigger, how many triggered fixes have been re-scanned, and the fix-hold rate.
Any figure with no data behind it is `null`, never a modelled estimate. Capture the
baseline at kick-off, then compare at mid-point and close.

## Model deployment options

Agents can run against frontier models by API, open-weight models hosted in the customer's
environment, or a hybrid that routes by task: complex reasoning (planning, root cause) to a
frontier model, simple mechanical work (normalisation, formatting) to a smaller local model.
Selection criteria are data residency, quality bar per task, latency, and cost. Whatever
the choice, the per-call and per-day spend caps and the Read/Write-only tool scoping apply
unchanged, and prompts carry the finding data inside an explicit untrusted-data boundary.
