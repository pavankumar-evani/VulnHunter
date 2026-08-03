# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

VulnHunter is not a conventional application — it's a Claude Code **extension**: a slash
command plus three scoped subagents that together form an autonomous security-scanning
pipeline. There is no build system, package manifest, or test suite for VulnHunter itself;
the "code" is markdown prompt/config files under `.claude/`. The only runnable code is the
intentionally-vulnerable demo Flask app in `vulnerable-demo-app/`, which exists purely as a
scan target.

## Running the pipeline

```bash
claude
/vulnhunt <path-to-target-repo> [--fix]
/vulnhunt vulnerable-demo-app        # scan+report only
/vulnhunt vulnerable-demo-app --fix  # scan+report, then auto-fix and open a PR
```

There is no other tooling to build, lint, or test — modifying this project means editing
the command/agent markdown files directly and re-running `/vulnhunt` against
`vulnerable-demo-app/` to see the effect.

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

## The demo app (`vulnerable-demo-app/`)

Six labeled, intentional vulnerabilities used as the scoring/demo baseline — if you modify
this app, keep the vuln count and CWE labels in its docstring/comments accurate, since the
README's "expected result" (~6 findings, 3-4 auto-fixed) depends on them:

1. Hardcoded Stripe key (`app.py`, `Dockerfile` `ENV`) — CWE-798
2. SQL injection via string concatenation in `/user` — CWE-89
3. `eval()` on user input in `/calc` — CWE-95
4. Command injection (`shell=True`) in `/ping` — CWE-78
5. `debug=True` in `app.run()` — CWE-489
6. Plaintext password storage in `/register` — CWE-256

Plus Dockerfile-level issues: no `USER` directive (runs as root, CWE-250), unpinned base
image tag, secret baked into an image layer via `ENV`.

**Never deploy this app anywhere reachable** — it exists solely as a scan target.
