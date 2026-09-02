# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## This file is stale on one major point — read this first

The section below ("What this repository is") describes VulnHunter's original
hackathon-era shape: two slash commands and seven subagents, no runnable application.
That description is no longer complete. **A real, deployable dashboard now exists**
(`dashboard/app.py`, a FastAPI backend + hand-rolled JS SPA, with auth/RBAC, 8+ live
vendor connectors including a real OpenVAS/GVM scan engine, a Python `unittest` suite
of 1,300+ tests, and its own `dashboard/README.md`) — none of that is documented in the
architecture sections below yet. Rewriting this file to cover the dashboard properly is
a real, scoped follow-up task in its own right, not done here. Until then: for anything
touching `dashboard/`, `remediation/connectors/`, or the RBAC/auth model, trust
`dashboard/README.md`, `docs/enterprise-suite/architecture.html`, and the other
documents indexed in `docs/enterprise-suite/MANIFEST.md` over this file's own
architecture description.

## What this repository is (original scope — the two Claude Code pipelines)

VulnHunter started as a Claude Code **extension**: two slash
commands plus seven scoped subagents forming two pipelines:

- `/vulnhunt` — scans source code, reports findings, auto-fixes the safe ones (3 subagents).
- `/remediate` — ingests Tenable/Armis/threat-intel vulnerability data, normalizes it,
  plans remediation by risk tier, and generates reviewable fix automation for supported
  asset classes (4 subagents).

There is no build system, package manifest, or test suite for VulnHunter itself; the
"code" is markdown prompt/config files under `.claude/`. The only runnable code is the
intentionally-vulnerable demo Flask app in `vulnerable-demo-app/`, which exists purely as a
`/vulnhunt` scan target. `/remediate` has no runnable target app — it consumes the sample
data files in `remediation/sample-data/`.

## Running the pipelines

```bash
claude
/vulnhunt <path-to-target-repo> [--fix]
/vulnhunt vulnerable-demo-app        # scan+report only
/vulnhunt vulnerable-demo-app --fix  # scan+report, then auto-fix and push a branch

/remediate                           # ingests remediation/sample-data/* by default
/remediate --generate                # also generates Ansible playbooks for auto-remediable findings
```

There is no other tooling to build, lint, or test — modifying this project means editing
the command/agent markdown files directly and re-running the relevant slash command
against `vulnerable-demo-app/` (for `/vulnhunt`) or `remediation/sample-data/` (for
`/remediate`) to see the effect.

To run the demo app standalone (for manual verification, never deployed anywhere reachable):

```bash
cd vulnerable-demo-app
pip install -r requirements.txt
python init_db.py   # creates vulnshop.db with seed users
python app.py        # listens on 0.0.0.0:5000, debug=True
```

## Architecture: the 3-stage subagent pipeline

`/vulnhunt` (`.claude/commands/vulnhunt.md`) is the orchestrator. It parses `$ARGUMENTS`
for a target path (default: cwd) and an optional `--fix` flag, then sequences three
subagents strictly in order, each with **deliberately scoped tool access** — this scoping
is the core design idea of the project, not an incidental detail:

1. **`vuln-scanner`** (tools: `Read, Grep, Glob, Bash` — no write access, by design) scans
   the target for injection flaws, hardcoded secrets, auth/crypto weaknesses, insecure
   config, risky pinned dependencies, and Docker issues. It returns *only* a raw JSON
   array of findings (id, file, line, title, cwe, severity, description, evidence,
   `auto_fixable`, `fix_hint`) — no prose, no markdown fences. The orchestrator must not
   proceed until this JSON is valid.
2. **`vuln-triage-reporter`** (tools: `Write` only — cannot read source, only receives
   findings JSON in its prompt) turns that JSON into `SECURITY_REPORT.md` written to the
   *target* repo's root: summary table, findings ranked Critical→Low with plain-English
   impact, and a remediation plan splitting auto-fixable vs. needs-human-review.
3. **`vuln-fixer`** (tools: `Read, Edit, Write, Bash`) runs only if `--fix` was passed (or
   the user confirms after seeing the report). It acts *only* on findings marked
   `auto_fixable: true`, re-reads each file immediately before editing (line numbers from
   the scan may be stale), and follows a fixed git workflow: new branch
   `vulnhunter/auto-fixes-<timestamp>` → commit referencing finding IDs → `git push`,
   surfacing the PR-creation URL GitHub prints in the push output. No `gh` CLI dependency
   — opening the actual PR is a manual click in the browser or VS Code afterward. If push
   fails, it must stop and tell the user the manual step rather than failing silently.

The chat output from `/vulnhunt` stays a short summary (counts by severity, auto-fixable
count); full detail always lives in `SECURITY_REPORT.md`, never dumped into the
conversation.

### Why the tool scoping matters

Each agent's `tools:` list in its frontmatter is a hard security boundary, not a
suggestion: the scanner is read-only so the component that *finds* vulnerabilities cannot
introduce new ones; the reporter can only `Write`, so it cannot scan or fix; the fixer is
the only agent allowed to touch git/`gh`. When editing any of the three agent files
(`.claude/agents/*.md`), preserve this separation — don't widen an agent's tool access to
"make it easier," since the narrow scope is the point.

### Fix conventions the fixer follows (`vuln-fixer.md`)

- SQL injection → parameterized queries (`?` for sqlite3, `%s` for psycopg2/MySQLdb).
- Hardcoded secrets → `os.environ[...]`, added to `.env.example` as a placeholder (never
  the real value), with `.env` added to `.gitignore`.
- `eval()`/`exec()` → only fixed if a safe mechanical replacement exists (e.g.
  `ast.literal_eval`); genuine dynamic-eval requirements are left for manual review rather
  than fixed and potentially broken.
- Docker running as root → add a non-root `USER` instruction after deps are installed.
- Debug mode in a prod entrypoint → gate behind an env var defaulting to `False`.

## Architecture: the remediation engine (`/remediate`)

`/remediate` (`.claude/commands/remediate.md`) orchestrates four subagents, same
scoped-tool-access philosophy as `/vulnhunt`:

1. **`vuln-ingest-normalizer`** (tools: `Read, Glob, Write`) parses Tenable CSV, Armis
   JSON, and threat-intel JSON exports into one common schema — see
   `remediation/schema/normalized-finding-schema.md`. Writes
   `remediation/output/normalized-findings.json`. Assigns `asset.type` (the routing key
   for everything downstream) and `remediation_domain` (non-null only for
   `windows-server`/`unix-server` today, since those are the only domains with a working
   fixer).
2. **`remediation-planner`** (tools: `Read, Write`) assigns each finding an `action_type`,
   `automation_target`, `risk_tier` (`auto-approvable` / `needs-change-approval` /
   `manual-only`), `rollback_plan`, and `priority`. Writes `REMEDIATION_PLAN.md` to the
   project root. Defaults to the more conservative risk tier when uncertain — this is a
   deliberate design choice, not caution to relax later.
3. **`remediation-fixer-windows`** / **`remediation-fixer-unix`** (tools: `Read, Write`
   only — no `Bash`, deliberately) generate Ansible playbooks per finding into
   `remediation/output/<finding-id>-<slug>.yml`, only for findings already routed to their
   domain by the planner. They never execute anything — that's the whole safety model of
   this pipeline (see README's "Remediation Engine" section for the full rationale).

### Why network/firewall/IoT findings stay manual-only

`vuln-ingest-normalizer` and `remediation-planner` handle all five asset classes
(windows-server, unix-server, network-routing-switching, network-security-device,
iot-ot-device) — ingestion and planning are asset-agnostic by design. Only fix-generation
is incomplete: there's no `remediation-fixer-network` or `remediation-fixer-iot` yet.
Adding one means adding a new subagent with `tools: Read, Write` (same restricted pattern)
that generates vendor-appropriate config (e.g. Ansible's `cisco.ios`/`junipernetworks.junos`
collections for network gear), plus updating `remediation-planner`'s `automation_target`
assignment to route to it. Don't add real execution capability (`Bash`, SSH, API calls) to
any fixer subagent — every fixer in this project stays artifact-generation-only.

## The demo app (`vulnerable-demo-app/`)

Six labeled, intentional vulnerabilities used as the `/vulnhunt` scoring/demo baseline — if
you modify this app, keep the vuln count and CWE labels in its docstring/comments
accurate, since the README's "expected result" (9 findings, 6 auto-fixed) depends on them:

1. Hardcoded Stripe key (`app.py`, `Dockerfile` `ENV`) — CWE-798
2. SQL injection via string concatenation in `/user` — CWE-89
3. `eval()` on user input in `/calc` — CWE-95
4. Command injection (`shell=True`) in `/ping` — CWE-78
5. `debug=True` in `app.run()` — CWE-489
6. Plaintext password storage in `/register` — CWE-256

Plus Dockerfile-level issues: no `USER` directive (runs as root, CWE-250), unpinned base
image tag, secret baked into an image layer via `ENV`.

**Never deploy this app anywhere reachable** — it exists solely as a scan target.

## Enterprise documentation suite — keep it in sync with the application

`docs/enterprise-suite/` holds 11 HTML documents (an executive brief, 7 technical
references, a POC methodology, and a commercial pricing/SLA page — indexed in
`docs/enterprise-suite/MANIFEST.md`, each also published as a live, shareable Artifact
page at the URL listed there) plus `docs/PRICING.md`, the plain-markdown source of truth
for pricing/SLA terms.

**Whenever a change to the application would make a claim in one of these documents
wrong, stale, or incomplete, update the affected document(s) in the same change.**
`docs/enterprise-suite/MANIFEST.md` has the exact "if you change X, update Y" table and
the republish instructions (edit the local `.html` file, then use the Artifact tool's
`publish` action with that file and the document's existing URL, so it updates in place
rather than creating a duplicate).

This cuts both ways: if `docs/PRICING.md` or the commercial model changes, sweep
`docs/enterprise-suite/pricing.html`, `executive-brief.html`, and
`docs/VR_PLATFORM_COMPARISON.md` for now-stale cost claims (e.g. an old "$0 / free"
framing) before considering the change done.
