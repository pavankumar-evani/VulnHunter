# VulnHunter Headless CLI

A thin Python wrapper around `claude -p` (Claude Code's non-interactive mode) that lets
`/vulnhunt` and `/remediate` run from a script, a CI job, or a cron schedule instead of
requiring a human typing into an interactive Claude Code session.

## Why a wrapper instead of reimplementing the pipelines in Python

The scanning/planning/fixing logic lives entirely in `.claude/agents/*.md` and
`.claude/commands/*.md`. This CLI does not duplicate that logic — it only constructs the
right `claude -p "..."` invocation and handles the surrounding plumbing (binary discovery,
audit logging, exit codes). That keeps the prompts as the single source of truth: edit an
agent's `.md` file once, and both the interactive and headless paths pick it up.

## ⚠️ Cost warning

**Every non-dry-run invocation calls the real Claude API and spends real usage/credits.**
Use `--dry-run` first to see exactly what would run. A `--max-budget-usd` cap (default
$2.00) is applied to every real invocation as a safety net, but you are still responsible
for understanding what a `/vulnhunt --fix` or `/remediate --generate` run costs against
your actual Claude plan before running it for real, especially in CI where it might run
on every push.

## Usage

```bash
# Preview the command without spending anything
python cli/vulnhunter.py --dry-run scan vulnerable-demo-app --fix

# Actually run it (spends API usage)
python cli/vulnhunter.py scan vulnerable-demo-app --fix

# Same for the remediation pipeline
python cli/vulnhunter.py --dry-run remediate --generate
python cli/vulnhunter.py remediate --generate
```

## Options

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | off | Print the command that would run; never calls the API |
| `--claude-bin` | auto-discovered | Path to the `claude` binary (see discovery order below) |
| `--max-budget-usd` | `2.00` | Spend cap passed to Claude Code for this invocation |
| `--permission-mode` | `acceptEdits` | Claude Code permission mode — tune to your org's policy |

## `claude` binary discovery order

1. `CLAUDE_BIN` environment variable (explicit override — use this in CI)
2. `claude` on `PATH`
3. `CLAUDE_CODE_EXECPATH` environment variable (only set inside an active Claude Code
   session — useful for testing this wrapper from within Claude Code, **not** a
   substitute for properly installing `claude` in a real CI runner)

## Audit logging

Every real (non-dry-run) invocation writes a timestamped JSON record to
`.vulnhunter/logs/<timestamp>-<pipeline>.json` containing the exact command run and its
full stdout/stderr. This directory is gitignored (it's runtime output, and may contain
scan results) — it's the seed of the audit trail a real deployment needs; see
[KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md)'s commercialization roadmap for what a
production-grade audit trail (who approved what, tied to a real user identity) would add
on top of this.

## Testing

`tests/test_cli.py` covers command construction and binary discovery as pure-function
unit tests, plus one subprocess test that runs the actual CLI script with `--dry-run` —
none of it calls the real Claude API, so it's safe to run in CI on every push.

```bash
python -m unittest tests.test_cli -v
```

## What this is not (yet)

This is a CLI, not a service. It runs one pipeline invocation and exits — there's no
queue, no web UI, no persistence beyond the flat audit log files, and no way for someone
without shell access to trigger a run or review results. That's Tier 2b (web dashboard)
in the commercialization roadmap.
