# Quanta — Support

**How to use this doc:** short reference for how to get help, report a bug, or file a
security issue against this project. If your question is "does Quanta do X," check
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

Open a ticket from the in-app **Support** page (`/support`, sign-in required), type
*Something isn't working*. Tickets are stored in your deployment's own database, visible
only to you and your administrators, and never sent to a public tracker. Include:

- **Which pipeline** — `/vulnhunt`, `/remediate`, or both.
- **Which component** — e.g. `vuln-scanner`, `remediation-planner`,
  `remediation-fixer-windows`, the dashboard, the headless CLI, a specific connector, or
  a generated artifact.
- **The exact command you ran** — the slash command with arguments, the
  `cli/quanta.py` invocation, or the dashboard action, including any flags
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

For a new asset class, data source, or capability request, open a ticket of type
*A feature request* instead. Scoping applies the safety-model checklist (e.g. any new
`remediation-fixer-*` subagent must stay `Read`/`Write`-only, per
[KNOWLEDGE_TRANSFER.md §4.3](../KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision))
before a change is scoped.

## Reporting a security issue

Do **not** open a public issue for a security vulnerability in Quanta itself. Follow
[SECURITY.md](../SECURITY.md): report privately to the contact listed there, with a
description of the issue, impact, reproduction steps, and which component is affected.
Acknowledgment target is 5 business days. Note the scope carveouts in that same file:
findings against `vulnerable-demo-app/` (intentionally vulnerable, expected) and
generated `remediation/output/` artifacts (unreviewed drafts by design) are not security
reports against Quanta itself.

## See also

- [FAQ.md](FAQ.md) — answers to the most common questions before you file anything.
- [USER_GUIDE.md](USER_GUIDE.md) — how the product is meant to be used day-to-day.
- [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) and [README.md](../README.md) — full
  architecture and troubleshooting log.

## How tickets work

- **Open:** any signed-in user, from `/support`. Fields: type (bug, question, feature,
  access, other), severity (low to urgent), subject, description.
- **Visibility:** a requester sees only their own tickets and the replies addressed to
  them. Administrators see the whole queue, can assign a ticket, change status and
  severity, record a resolution, and add internal notes the requester never sees.
- **Status:** open, in progress, waiting on requester, resolved, closed. A requester's
  reply on a ticket waiting on them puts it back in progress.
- **Escalation to the vendor (optional):** set `QUANTA_SUPPORT_EMAIL` and the SMTP
  variables, and an admin can send a ticket (public content only, never internal notes)
  to the vendor's support desk by email. It previews first and sends only on explicit
  confirmation. Without these settings nothing ever leaves the deployment.
- **Audit:** every create, reply and triage change is written to the activity log.
