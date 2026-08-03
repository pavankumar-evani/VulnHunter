# VulnHunter — AI Commands & Agents Reference

**How to use this doc:** the reference for every AI-facing entry point in this repo —
exact slash-command syntax, every subagent's name/purpose/tool-scope (pulled directly
from each `.claude/agents/*.md` file's frontmatter, not guessed), the headless CLI, and
the dashboard's AI-assist feature. If you want a task-oriented walkthrough
instead, see [USER_GUIDE.md](USER_GUIDE.md). For why the tool-scoping model exists at
all, see [KNOWLEDGE_TRANSFER.md §3.3 and §4.3](../KNOWLEDGE_TRANSFER.md#33-why-subagents-with-scoped-tools-specifically).
Also see [FAQ.md](FAQ.md), [INTEGRATIONS.md](INTEGRATIONS.md),
[REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md), or the [docs/README.md](README.md)
index.

---

## 1. Slash commands (`.claude/commands/`)

Both commands are Claude Code custom slash commands, discovered automatically when a
Claude Code session starts with this repo as the working directory. Each orchestrates a
chain of subagents via the `Task` tool — neither implements scanning/fixing logic itself.

### `/vulnhunt`

Source: [`.claude/commands/vulnhunt.md`](../.claude/commands/vulnhunt.md)

```
/vulnhunt [path-to-target-repo] [--fix]
```

- `allowed-tools: Task, Read, Bash`
- `path-to-target-repo` — defaults to the current directory if omitted.
- `--fix` — if present anywhere in the arguments, auto-fixes are applied at the end
  without asking; if absent, the command stops after the report and explicitly asks the
  user whether to proceed with fixes before ever invoking `vuln-fixer`.
- Orchestration: delegates to `vuln-scanner` → `vuln-triage-reporter` →
  (conditionally) `vuln-fixer`, printing a short severity/auto-fixable summary in chat
  and leaving full detail in `SECURITY_REPORT.md`.

### `/remediate`

Source: [`.claude/commands/remediate.md`](../.claude/commands/remediate.md)

```
/remediate [--generate]
/remediate [file1] [file2] ... [--generate]
```

- `allowed-tools: Task, Read, Bash`
- With no file arguments, ingests the bundled sample data in `remediation/sample-data/`
  (`tenable_export.csv`, `armis_export.json`, `threat_intel.json`); pass different paths
  to ingest other files instead.
- `--generate` — if present, also generates Ansible playbooks at the end; if absent, the
  command stops after `REMEDIATION_PLAN.md` and asks the user whether to proceed with
  generation.
- Orchestration: `vuln-ingest-normalizer` → `threat-intel-enricher` (non-blocking if
  enrichment fails — the pipeline proceeds to planning and notes KEV/EPSS data is
  unavailable rather than stopping entirely) → `remediation-planner` →
  (conditionally, split by domain) `remediation-fixer-windows` and
  `remediation-fixer-unix`, which "can run independently of each other" per the command
  file.

---

## 2. Subagents (`.claude/agents/`)

Tool lists below are copied verbatim from each file's YAML frontmatter — not summarized
or approximated. All eight run on `model: sonnet`.

| Agent | Pipeline | Tools | Purpose |
|---|---|---|---|
| [`vuln-scanner`](../.claude/agents/vuln-scanner.md) | `/vulnhunt` | `Read, Grep, Glob, Bash` | Statically scans a codebase for injection flaws, hardcoded secrets, auth/crypto weaknesses, insecure config, risky dependencies, and unsafe Docker practices across Python, JavaScript/TypeScript, Java, Go, PHP, and Perl. Read-only by design — no `Edit`/`Write` in its tool list, so it is architecturally incapable of modifying anything it scans. Outputs a structured JSON findings array. |
| [`vuln-triage-reporter`](../.claude/agents/vuln-triage-reporter.md) | `/vulnhunt` | `Write` | Takes the raw JSON findings and writes `SECURITY_REPORT.md` — a ranked, plain-English report. `Write`-only: it cannot re-scan code or "helpfully" fix anything, only organize and communicate what it's given. |
| [`vuln-fixer`](../.claude/agents/vuln-fixer.md) | `/vulnhunt` | `Read, Edit, Write, Bash` | Applies fixes only for findings marked `auto_fixable: true` (parameterizing SQL, moving secrets to env vars, dropping container root, etc.). Git workflow is always new-branch → commit → push; never commits to `main`, and stops with a clear manual-step message if the push fails rather than silently giving up. |
| [`vuln-ingest-normalizer`](../.claude/agents/vuln-ingest-normalizer.md) | `/remediate` | `Read, Glob, Write` | Parses Tenable CSV, Armis JSON, and manual threat-intel JSON into one common Finding schema (`remediation/schema/normalized-finding-schema.md`), assigning stable sequential `FIND-N` IDs and classifying each finding's `asset.type`. Does not assess risk or plan fixes — format translation only. |
| [`threat-intel-enricher`](../.claude/agents/threat-intel-enricher.md) | `/remediate` | `Read, Write, Bash` | Runs `remediation/enrichment/kev_epss.py` via Bash to attach real CISA KEV and FIRST.org EPSS data to every finding with a CVE. If the script fails (e.g. no network), it reports that plainly rather than fabricating KEV/EPSS values. Does not assess remediation risk tiers or priority itself. |
| [`remediation-planner`](../.claude/agents/remediation-planner.md) | `/remediate` | `Read, Write` | Assigns each finding an `action_type`, `automation_target`, `risk_tier` (`auto-approvable`/`needs-change-approval`/`manual-only`), `rollback_plan`, and threat-intel-aware `priority`. Writes `REMEDIATION_PLAN.md`. Writes no scripts or playbooks itself and never touches infrastructure. |
| [`remediation-fixer-windows`](../.claude/agents/remediation-fixer-windows.md) | `/remediate` | `Read, Write` | Generates reviewable Ansible playbooks (WinRM-targeted) for findings with `remediation_domain == "windows-server"`. No `Bash`, no network tool — cannot connect to or run anything against a real host even if instructed to. |
| [`remediation-fixer-unix`](../.claude/agents/remediation-fixer-unix.md) | `/remediate` | `Read, Write` | Generates reviewable Ansible playbooks (SSH-targeted) for findings with `remediation_domain == "unix-server"`. Same `Read`/`Write`-only tool scope and the same "cannot execute anything" guarantee as the Windows fixer. |

The pattern across every pair of "does the finding, does the writing" subagents is
deliberate: a subagent that finds problems cannot also create them, and a subagent that
generates a fix artifact cannot run it. See
[KNOWLEDGE_TRANSFER.md §3.3](../KNOWLEDGE_TRANSFER.md#33-why-subagents-with-scoped-tools-specifically)
for the full design rationale.

---

## 3. Headless CLI (`cli/vulnhunter.py`)

```bash
python cli/vulnhunter.py [--dry-run] [--claude-bin PATH] [--max-budget-usd N] [--permission-mode MODE] scan <path> [--fix]
python cli/vulnhunter.py [--dry-run] [--claude-bin PATH] [--max-budget-usd N] [--permission-mode MODE] remediate [--generate]
```

- `scan` and `remediate` are the two subcommands, mapping 1:1 to `/vulnhunt` and
  `/remediate`. `cli/vulnhunter.py` constructs and runs the equivalent `claude -p "..."`
  invocation — it is a wrapper, not a reimplementation, so the prompts in
  `.claude/agents/*.md`/`.claude/commands/*.md` remain the single source of truth for
  both the interactive and headless paths.
- Flags: `--dry-run` (print the command, call nothing), `--claude-bin` (override binary
  discovery), `--max-budget-usd` (spend cap, default `2.00`), `--permission-mode`
  (Claude Code permission mode, default `acceptEdits`).
- Full flag table and binary-discovery order: [cli/README.md](../cli/README.md).

---

## 4. Dashboard AI-assist (`/api/ai-assist`, `/ai-assist` page)

The dashboard's `/api/*` surface (`dashboard/app.py`) exposes an `/api/run` endpoint that
triggers either pipeline via the same CLI wrapper described above, using a
**dry-run-preview-by-default, explicit-confirm-to-spend** pattern: a request without
`confirm: true` only returns what *would* run, spending nothing; setting `confirm: true`
executes the real (paid) pipeline invocation. See `dashboard/app.py`'s `api_run_post`
handler and [dashboard/README.md](../dashboard/README.md#the-run-and-servicenow-safety-design)
for that existing behavior.

`/api/ai-assist` (POST) follows the identical pattern for a per-finding AI action, backed
by `dashboard/ai_assist.py`'s pure `build_ai_assist_prompt(finding, action)` function:

```json
// Request
{"finding_id": "FIND-12", "action": "explain", "confirm": false}

// Response when confirm is false (default) - no API call made, zero cost
{"dry_run": true, "prompt": "Finding FIND-12: ...", "message": "Preview only ..."}

// Response when confirm is true - calls the real `claude` CLI (same binary
// discovery as cli/vulnhunter.py) and spends real API usage/credits
{"dry_run": false, "prompt": "Finding FIND-12: ...", "response": "The AI's plain-text reply"}
```

`action` is one of `explain` (plain-English risk explanation), `remediate` (draft
remediation steps), or `summarize` (executive-summary-length blurb) - each maps to a
different instruction appended to the same finding context (ID, title, asset, CVE,
severity, description). `finding_id` accepts either a `/remediate` finding (`FIND-N`) or a
`/vulnhunt` code-scan finding (`VULN-N`) - the endpoint looks up either dataset. A
finding_id that doesn't exist returns `404`; an unrecognized `action` returns `400`.

The `/ai-assist` page in the dashboard wraps this: pick a finding and an action, preview
the exact prompt for free, then explicitly opt in to spend real usage/credits by checking
confirm before asking for real. Reachable directly with a preselected finding via
`/ai-assist?finding_id=FIND-12`, which is how the "Ask AI" link on each Remediation Queue
row opens it.

---

## See also

- [USER_GUIDE.md](USER_GUIDE.md) — how to actually run all of this, day to day.
- [FAQ.md](FAQ.md) — specific questions about scope and safety.
- [INTEGRATIONS.md](INTEGRATIONS.md) — the external systems these pipelines connect to.
- [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) — the full `/remediate` lifecycle.
- [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) and [README.md](../README.md) — the
  canonical architecture and pitch docs this reference draws from.
