# VulnHunter — `docs/` Index

**How to use this doc:** start here if you landed in `docs/` directly and need to find
the right file. Everything below is task-oriented reference material that sits
underneath the two canonical repo-root docs — [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md)
(the full architecture, design rationale, roadmap, and troubleshooting log) and
[README.md](../README.md) (the pitch-oriented overview and demo script). If you haven't
read those yet, read `KNOWLEDGE_TRANSFER.md` first — everything in this folder assumes
that context.

## Contents

| Doc | Read this for |
|---|---|
| [USER_GUIDE.md](USER_GUIDE.md) | Practical, day-to-day usage — running `/vulnhunt` and `/remediate` interactively and headlessly, using every dashboard page, interpreting severity/priority/risk-tier/SLA fields, reviewing a generated playbook before running it, the safety model in practice, and agent-based vs. agentless scanning. |
| [FAQ.md](FAQ.md) | Direct answers to the questions people actually ask — does this scan real infrastructure, does anything auto-apply, what languages does the scanner cover, is this compliant, does it support multi-tenancy, where does data live, what does a real scan cost. |
| [AI_COMMANDS.md](AI_COMMANDS.md) | Reference for every AI-facing entry point: `/vulnhunt` and `/remediate` slash-command syntax, every subagent's exact tool-scope (from its `.claude/agents/*.md` frontmatter), the headless CLI, and the dashboard's in-progress AI-assist feature. |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Every external system this connects to — Tenable, Armis, ServiceNow, Jira, Splunk, CrowdStrike Falcon, CISA KEV, FIRST.org EPSS — and precisely what's live-verified versus built-against-docs-but-unverified for each. Plus what's deliberately not built yet (Sentinel, QRadar, Defender, Qualys). |
| [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) | The full `/remediate` lifecycle end to end: ingest → normalize → enrich → risk-tier/priority/SLA scoring (and why there are two separate scoring mechanisms) → playbook generation → human review → manual apply. Includes MITRE ATT&CK tagging, ServiceNow ticketing, and which asset classes have no fixer yet. |
| [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) | An informational (**not certifying**) map of existing capabilities to NIST CSF / SOC 2 control categories, plus an explicit list of what's missing before any real compliance claim could be made. |
| [SUPPORT.md](SUPPORT.md) | How to get help, report a bug, or report a security issue — and where to look first. |

## Also see

- [../README.md](../README.md) — pitch-oriented overview, architecture diagrams, demo
  script.
- [../KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) — the canonical deep-dive: problem
  statement, design rationale, step-by-step run instructions, test evidence, roadmap, and
  troubleshooting log.
- [../SECURITY.md](../SECURITY.md) — how to report a security issue in VulnHunter itself.
- [../TEST_CASES.md](../TEST_CASES.md) — the full test case log (456 cases, steps,
  expected vs. actual).
- [../CHANGELOG.md](../CHANGELOG.md) — what's changed, in order.
