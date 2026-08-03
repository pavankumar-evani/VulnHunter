# VulnHunter — Support

**How to use this doc:** short reference for how to get help, report a bug, or file a
security issue against this project. If your question is "does VulnHunter do X," check
[FAQ.md](FAQ.md) first — it's faster than filing anything. See also
[USER_GUIDE.md](USER_GUIDE.md), [AI_COMMANDS.md](AI_COMMANDS.md), or the
[docs/README.md](README.md) index.

---

## Check these first

Most questions and "is this broken" moments are already answered:

1. **[FAQ.md](FAQ.md)** — specific, product-level questions (scope, safety, cost,
   compliance, multi-tenancy).
2. **[KNOWLEDGE_TRANSFER.md §12, Troubleshooting](../KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up)**
   — a running, honest log of environment issues that have already come up and how they
   were resolved: `winget`/`gh` CLI unavailability on locked-down machines, Docker Desktop
   being unreliable or absent, GitHub's secret-scanning blocking a push on
   realistic-looking fake demo credentials, subagents being project-scoped (they only
   load when Claude Code starts with this repo as the working directory), and the lack of
   LibreOffice/Node.js affecting only the `deliverables/` build tooling. If what you hit
   matches one of these, the fix is already documented there.
3. **[cli/README.md](../cli/README.md)** and **[dashboard/README.md](../dashboard/README.md)**
   — component-specific "what this is not (yet)" sections, for gaps that are known
   limitations rather than bugs.

## Reporting a bug

Open a GitHub issue on this repository using the **Bug report** template
(`.github/ISSUE_TEMPLATE/bug_report.md`). Include:

- **Which pipeline** — `/vulnhunt`, `/remediate`, or both.
- **Which component** — e.g. `vuln-scanner`, `remediation-planner`,
  `remediation-fixer-windows`, the dashboard, the headless CLI, a specific connector, or
  a generated artifact.
- **The exact command you ran** — the slash command with arguments, the
  `cli/vulnhunter.py` invocation, or the dashboard action, including any flags
  (`--fix`, `--generate`, `--dry-run`, etc.).
- **Full error output or unexpected result** — paste the relevant section of
  `SECURITY_REPORT.md`, `REMEDIATION_PLAN.md`, a generated playbook, dashboard response,
  or CLI/test output. **Redact anything sensitive first** — especially if you were
  running against real Tenable/Armis/ServiceNow data rather than the bundled samples.
- **Repo state** — which branch, and whether you're on a commit with local changes.
- **Whether the test suite catches it** — run
  `python -m unittest discover -s tests -p "test_*.py" -v`; if a bug should have been
  caught but wasn't, that's worth a new test case alongside the report (see
  [TEST_CASES.md](../TEST_CASES.md) for the existing pattern).

For a new asset class, data source, or capability request, use the **Feature request**
template (`.github/ISSUE_TEMPLATE/feature_request.md`) instead — it walks through the
safety-model checklist (e.g. any new `remediation-fixer-*` subagent must stay
`Read`/`Write`-only, per
[KNOWLEDGE_TRANSFER.md §4.3](../KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision))
before a change is scoped.

## Reporting a security issue

Do **not** open a public issue for a security vulnerability in VulnHunter itself. Follow
[SECURITY.md](../SECURITY.md): report privately to the contact listed there, with a
description of the issue, impact, reproduction steps, and which component is affected.
Acknowledgment target is 5 business days. Note the scope carveouts in that same file:
findings against `vulnerable-demo-app/` (intentionally vulnerable, expected) and
generated `remediation/output/` artifacts (unreviewed drafts by design) are not security
reports against VulnHunter itself.

## See also

- [FAQ.md](FAQ.md) — answers to the most common questions before you file anything.
- [USER_GUIDE.md](USER_GUIDE.md) — how the product is meant to be used day-to-day.
- [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) and [README.md](../README.md) — full
  architecture and troubleshooting log.
