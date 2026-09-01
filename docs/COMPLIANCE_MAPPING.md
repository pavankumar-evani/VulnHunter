# VulnHunter — Compliance Mapping

> **DISCLAIMER — READ BEFORE USING THIS DOCUMENT FOR ANYTHING**
>
> **This document is an informational reference only.** It maps existing technical
> capabilities in this repository to common compliance-framework control *categories*,
> for internal planning purposes. **It is NOT a certification, attestation, audit
> result, or compliance claim of any kind — for any framework.** Achieving actual
> SOC 2, NIST CSF, PCI DSS, or any other formal compliance status requires a licensed
> audit or formal third-party assessment process that this document cannot substitute
> for, regardless of how complete the mapping below looks. Do not present this document,
> or any summary of it, to a customer, auditor, or regulator as evidence of compliance.

**How to use this doc:** read this if you need a quick internal reference for "which
existing VulnHunter capability relates to which compliance control category" — and
just as importantly, what's missing before any real compliance claim could be made. For
the authoritative statement on why compliance certification isn't a coding deliverable,
see [KNOWLEDGE_TRANSFER.md §9, Tier 3](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade).
Also see [FAQ.md](FAQ.md) (the "Is this SOC2/NIST/PCI compliant?" entry links here),
[USER_GUIDE.md](USER_GUIDE.md), [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md), or
the [docs/README.md](README.md) index.

---

## NIST Cybersecurity Framework (CSF) — conceptual mapping

| CSF Function | Existing capability it conceptually relates to | Where it lives |
|---|---|---|
| **Identify** | Normalized asset/finding schema — every ingested finding carries an `asset.type` classification (`windows-server`, `unix-server`, `network-routing-switching`, `network-security-device`, `iot-ot-device`, `application`, `certificate`) | `remediation/schema/normalized-finding-schema.md`, `vuln-ingest-normalizer.md` |
| **Protect** | The tool-scoping safety model — each subagent has only the tools its job requires (e.g. `remediation-fixer-windows`/`-unix` have `Read`/`Write` only, no execution or network capability at all), which is a least-privilege concept applied architecturally rather than by policy | `.claude/agents/*.md` frontmatter; see [KNOWLEDGE_TRANSFER.md §4.3](../KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision) |
| **Detect** | Code vulnerability scanning (`vuln-scanner`) plus real-world exploitation-likelihood enrichment (CISA KEV + FIRST.org EPSS), and MITRE ATT&CK keyword tagging as a rough detection-technique grouping | `.claude/agents/vuln-scanner.md`, `remediation/enrichment/kev_epss.py`, `remediation/enrichment/attack_mapping.py` |
| **Respond** | Risk-tiered, prioritized remediation planning (`remediation-planner`) plus optional ServiceNow Incident creation for tracking response work in an org's own ITSM tool | `remediation-planner.md`, `remediation/connectors/servicenow_connector.py` |
| **Recover** | Every generated playbook carries a real, human-written `# Rollback: ...` header comment, now surfaced directly on the Remediation Approvals page (not just inside the playbook file), so a reviewer isn't starting from zero if a change needs to be undone | Playbook header comments in `remediation/output/*.yml`; `dashboard/data.py`'s `_parse_rollback_plan()`; `/remediation-approvals`'s "Rollback Plan" column |

## SOC 2 Trust Services Criteria — conceptual mapping

| TSC Category | Existing capability it conceptually relates to | Where it lives |
|---|---|---|
| **Security (Common Criteria)** | Least-privilege tool scoping (see Protect, above) as an access-control concept; a timestamped audit record of every real (non-dry-run) pipeline invocation, including the exact command and full stdout/stderr | `.claude/agents/*.md`; `cli/vulnhunter.py`'s `.vulnhunter/logs/<timestamp>-<pipeline>.json` audit records |
| **Confidentiality** | Live connector credentials are read from environment variables only, never passed as CLI arguments (so they don't leak into shell history/process listings); real vulnerability data pulled from live tenants (`remediation/live-data/`) and CLI audit logs (`.vulnhunter/logs/`) are gitignored, never committed | `remediation/connectors/README.md`'s setup instructions; `.gitignore` |

**None of the above is a control that has been tested, audited, or attested to by any
third party.** It is a map of "this exists and points in that direction," not evidence
that any control operates effectively over time — which is what SOC 2 and NIST CSF
assessments actually require.

## Patch Management Standards (NIST SP 800-40r4 / CIS Controls v8 §7 / ISO 27002:2022 §8.8, §8.32) — conceptual mapping

| Control | Existing capability it conceptually relates to | Where it lives |
|---|---|---|
| **NIST SP 800-40r4 — risk-based prioritization** | Configurable, weighted priority scoring (severity + asset criticality + asset type), with real CISA KEV/FIRST.org EPSS overrides so a confirmed-exploited or high-likelihood finding is never silently deprioritized | `remediation/config/priority_engine.py`, `remediation/config/priority_rules.yaml` |
| **CIS Controls v8 §7.1/7.4 — establish and maintain a remediation process** | Real per-finding remediation plans (action type, automation mechanism, risk tier) and generated, reviewable Ansible playbooks/PowerShell DSC — always an artifact for a human/change-management process to run, never auto-applied | `remediation-planner.md`, `remediation-fixer-windows.md`/`-unix.md`, `remediation/output/*.yml` |
| **CIS Controls v8 §7.2 — asset-criticality-tiered remediation timelines** | SLA windows are no longer keyed on finding severity alone — a real, disclosed asset `risk_tier` (Impact × Likelihood, see `remediation/enrichment/risk_scoring.py`) multiplies the base SLA window, tightening it for a Critical-risk asset and loosening it for a Low-risk one | `remediation/config/priority_engine.py`'s `compute_sla()`; `sla_risk_tier_multiplier` in `priority_rules.yaml` |
| **ISO/IEC 27002:2022 §8.32 — change management (test before applying)** | A real, recorded staging-validation attestation (who tested the change in a staging/test environment, and when) as an explicit step alongside the existing change-approval workflow | `remediation/remediation_approvals/store.py`'s `mark_staging_validated()`; `/remediation-approvals`'s "Staging Validation" column |
| **ISO/IEC 27002:2022 §8.32 — rollback/recovery procedure** | Every generated playbook's real `# Rollback: ...` header comment, now surfaced directly where the approval decision happens, not only inside the playbook file | `remediation/output/*.yml`; `/remediation-approvals`'s "Rollback Plan" column |
| **CIS Controls v8 §7.5/7.6 — automated vulnerability scanning** | **Not covered.** This app ingests already-scanned findings (Tenable/Armis exports or APIs, or its own code scanner) — it does not itself run a scheduled, automated infrastructure scan against live hosts. | — |
| **CIS Controls v8 §7.3 — automated patch deployment** | **Not covered by design.** Every generated remediation is a reviewable artifact for a human/change-management process to run — this app deliberately never executes a patch against real infrastructure (see the safety model). A real automated-deployment pipeline (e.g. Ansible Tower/AWX, SCCM/Intune) would sit downstream of this app's output, not inside it. | — |
| **Vendor-release / advisory monitoring, configuration-drift detection** | **Not covered.** No polling of vendor patch-release feeds or scheduled config-drift scanning exists; both would need real infrastructure access this demo doesn't have. | — |

## Quantum-Readiness Standards (NIST FIPS 203/204/205 / NIST IR 8547) — conceptual mapping

| Standard | Existing capability it conceptually relates to | Where it lives |
|---|---|---|
| **NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)** — finalized August 2024, the real post-quantum replacements for RSA/Diffie-Hellman key exchange and RSA/ECDSA digital signatures | A real classification of already-normalized findings whose title names classical asymmetric crypto (RSA/ECDSA/Diffie-Hellman), pointing each toward the correct FIPS replacement | `remediation/enrichment/quantum_readiness.py`; `/quantum-readiness` |
| **NIST IR 8547 migration timeline** (Initial Public Draft, November 2024 — not yet finalized) — RSA/ECDSA/Diffie-Hellman at the weaker, 112-bit-strength parameter tier (e.g. RSA-2048) deprecated after 2030, disallowed after 2035; stronger parameters skip the 2030 step | The real cited deadlines shown alongside every classified finding, and factored into the finding's own remediation policy domain (security-architecture review, not a routine patch) | `remediation/config/remediation_policy.yaml`'s `quantum-crypto` domain; `quantum_readiness.py`'s `NIST_IR_8547_DEPRECATED_BY`/`NIST_IR_8547_DISALLOWED_BY` |

**Not the same as NSA's CNSA 2.0** (PP-22-1338) — a separate, National-Security-Systems-
specific framework with its own different category-by-category schedule (2025-2033,
converging with IR 8547 only at a shared 2035 backstop). This app cites IR 8547 only,
to avoid conflating two real but distinct standards with different numbers.

This is a disclosed keyword classification against each finding's own real title (this
app's normalized finding schema carries no separate CWE field to join against) - not a
"quantum vulnerability scanner" (no such product category exists to honestly claim,
since a quantum computer capable of breaking real-world RSA/ECDSA doesn't exist yet) and
not a certification against any of the standards named above. See
`remediation/enrichment/quantum_readiness.py`'s module docstring for the full
disclosure.

Like the CSF/SOC 2 tables above, this is a conceptual mapping for internal planning, not
a certification, audit result, or attestation that any of these controls has been tested
or operates effectively over time — and the three "Not covered" rows are named
explicitly rather than silently omitted, since a real patch-management program needs
them regardless of what this app does or doesn't do.

---

## What's explicitly missing for a real compliance program

Pulled directly from the gaps already named in
[KNOWLEDGE_TRANSFER.md §9, Tier 3 — "Not started, needs a business/architecture decision
first"](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade), not invented for
this document:

- **Authentication, RBAC, SSO, multi-tenancy** — the dashboard currently has **zero
  authentication**; every request re-reads local files with no access control at all.
  A real compliance program (and honestly, any production deployment) needs this before
  anything else in this list matters. See
  [dashboard/README.md](../dashboard/README.md)'s "What this is NOT (yet)" section.
- **Third-party audit / formal assessment** — SOC 2 specifically requires an audit by a
  licensed CPA firm over months of operational evidence; NIST CSF alignment requires a
  self-attestation or third-party assessment. No amount of internal documentation
  (including this one) substitutes for that process.
- **A real deployment and data-handling architecture** — because the current MVP has no
  database and no persistence (findings are re-read from disk on every request), there is
  currently no encryption-at-rest posture, no data retention policy, and no formal
  incident-response process to document for this product's own operation — those all
  presuppose a persistence/deployment layer that doesn't exist yet
  ([KNOWLEDGE_TRANSFER.md §9, item 6](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade)
  names "Persistence + audit log" as the relevant unbuilt foundation). Until that
  architecture decision is made, any encryption/retention/incident-response policy
  written for this product would be describing infrastructure that isn't there.
- **Deployment + pricing model** — SaaS vs. self-hosted, and what this costs per customer
  at scale given real Claude API usage, is a business decision this document (and the
  codebase) cannot make unilaterally.

Compliance certification itself (SOC 2, NIST, PCI, or "any relevant compliance") is
listed in the same KNOWLEDGE_TRANSFER.md section as **not a coding task** — this repo can
build toward the underlying controls, but "compliant" is a claim only a licensed audit or
formal assessment can make, and asserting it prematurely (especially when pitching to
regulated customers like banks) is a legal/regulatory risk, not a feature gap.

---

## See also

- [FAQ.md](FAQ.md) — the plain-language "is this compliant" answer this doc backs up.
- [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) — where the audit-trail and
  rollback mechanics referenced above actually run.
- [USER_GUIDE.md](USER_GUIDE.md) — the safety model in practical, day-to-day terms.
- [KNOWLEDGE_TRANSFER.md §9](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade)
  and [README.md](../README.md) — the canonical roadmap this mapping is derived from.
