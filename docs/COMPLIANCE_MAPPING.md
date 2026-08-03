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
| **Recover** | Every remediation plan entry and generated playbook carries an explicit `rollback_plan` / rollback comment, so a reviewer isn't starting from zero if a change needs to be undone | `remediation-planner.md`'s `rollback_plan` field; playbook header comments in `remediation/output/*.yml` |

## SOC 2 Trust Services Criteria — conceptual mapping

| TSC Category | Existing capability it conceptually relates to | Where it lives |
|---|---|---|
| **Security (Common Criteria)** | Least-privilege tool scoping (see Protect, above) as an access-control concept; a timestamped audit record of every real (non-dry-run) pipeline invocation, including the exact command and full stdout/stderr | `.claude/agents/*.md`; `cli/vulnhunter.py`'s `.vulnhunter/logs/<timestamp>-<pipeline>.json` audit records |
| **Confidentiality** | Live connector credentials are read from environment variables only, never passed as CLI arguments (so they don't leak into shell history/process listings); real vulnerability data pulled from live tenants (`remediation/live-data/`) and CLI audit logs (`.vulnhunter/logs/`) are gitignored, never committed | `remediation/connectors/README.md`'s setup instructions; `.gitignore` |

**None of the above is a control that has been tested, audited, or attested to by any
third party.** It is a map of "this exists and points in that direction," not evidence
that any control operates effectively over time — which is what SOC 2 and NIST CSF
assessments actually require.

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
