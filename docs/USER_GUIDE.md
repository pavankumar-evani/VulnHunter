# VulnHunter — User Guide

**How to use this doc:** read this if you're the person actually running `/vulnhunt` or
`/remediate` day-to-day — interactively, headlessly, or through the dashboard — and want
to know what a command does, what a field on screen means, and what's safe to click.
For *what VulnHunter is and why it's built this way*, read
[KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) first. For the pitch-oriented tour, see
[README.md](../README.md). Other docs in this set: [FAQ.md](FAQ.md),
[AI_COMMANDS.md](AI_COMMANDS.md), [INTEGRATIONS.md](INTEGRATIONS.md),
[REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md),
[COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md), [SUPPORT.md](SUPPORT.md) — or start at
[docs/README.md](README.md) for the full index.

---

## 1. Running the pipelines interactively (inside a Claude Code session)

VulnHunter has no separate server process for its core pipelines — `/vulnhunt` and
`/remediate` are Claude Code slash commands (`.claude/commands/vulnhunt.md` and
`.claude/commands/remediate.md`) that orchestrate a chain of subagents
(`.claude/agents/*.md`). You need Claude Code installed and authenticated, and this repo
as your working directory (subagents are project-scoped — see
[KNOWLEDGE_TRANSFER.md §12](../KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up)).

```bash
cd VulnHunter
claude
```

### `/vulnhunt` — code scanning and fixing

```
/vulnhunt <path>            # scan + report only
/vulnhunt <path> --fix      # scan + report, then auto-fix the safe findings
```

- With no `--fix`, this runs `vuln-scanner` → `vuln-triage-reporter` and writes
  `<path>/SECURITY_REPORT.md`. Read that file — it's the full ranked report.
- With `--fix`, `vuln-fixer` also runs: it creates a new branch
  (`vulnhunter/auto-fixes-<timestamp>`), applies only the findings marked
  `auto_fixable: true`, commits, and pushes. It never commits to `main`. If you omit
  `--fix`, the command asks you before invoking `vuln-fixer` at all — nothing gets fixed
  without an explicit yes.
- Opening the actual pull request is a manual, one-click step: GitHub prints a
  "create a pull request" URL in the `git push` output, or you can use VS Code's Source
  Control panel. There's no `gh` CLI dependency.

### `/remediate` — infrastructure remediation

```
/remediate                        # ingest + normalize + enrich + plan only
/remediate --generate              # additionally generate Ansible playbooks
/remediate <file1> <file2> ...     # ingest specific files instead of the bundled samples
```

- With no arguments, ingests `remediation/sample-data/` (`tenable_export.csv`,
  `armis_export.json`, `threat_intel.json`). Pass different paths (e.g. output from the
  live connectors — see [INTEGRATIONS.md](INTEGRATIONS.md)) to plan against real data.
- The pipeline is `vuln-ingest-normalizer` → `threat-intel-enricher` → `remediation-planner`,
  writing `REMEDIATION_PLAN.md` to the project root. See
  [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) for the full walk-through of every
  stage.
- With `--generate` (or after you confirm when asked), `remediation-fixer-windows` and
  `remediation-fixer-unix` generate one Ansible playbook per eligible finding under
  `remediation/output/`. Findings with no supported fixer yet (network, IoT/OT,
  application, certificate) stay `manual-only` in the plan, with the reason stated.

---

## 2. Running headlessly (`cli/vulnhunter.py`)

For CI, cron, or any automation without a human typing into an interactive session:

```bash
python cli/vulnhunter.py --dry-run scan vulnerable-demo-app --fix   # preview, no cost
python cli/vulnhunter.py scan vulnerable-demo-app --fix              # spends real API usage
python cli/vulnhunter.py --dry-run remediate --generate
python cli/vulnhunter.py remediate --generate
```

`cli/vulnhunter.py` is a thin wrapper around `claude -p` (Claude Code's non-interactive
mode) — it does not reimplement any pipeline logic, so editing an agent's `.md` file
changes behavior for both the interactive and headless paths identically. Key facts, all
from [cli/README.md](../cli/README.md):

- **`--dry-run` never calls the API.** It only prints the command that would run.
- **Every non-dry-run invocation spends real Claude API usage**, capped by
  `--max-budget-usd` (default `$2.00`) as a safety net — not a guarantee you've budgeted
  correctly for your own Claude plan.
- Every real invocation writes an audit record to
  `.vulnhunter/logs/<timestamp>-<pipeline>.json` (command run, full stdout/stderr) —
  gitignored, and the seed of the audit trail described in
  [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md).
- The `claude` binary is discovered via `CLAUDE_BIN` env var → `PATH` → `CLAUDE_CODE_EXECPATH`
  (see `cli/README.md`'s discovery-order table before wiring this into CI).

---

## 3. Using the dashboard

```bash
pip install -r dashboard/requirements.txt
python dashboard/app.py
# open http://127.0.0.1:5050
```

The dashboard (`dashboard/app.py`) is a FastAPI JSON API (`/api/*`) behind a hand-rolled
vanilla-JS single-page frontend (`dashboard/static/`) — no Node/npm build step. It is
**read-mostly**: every page re-reads the real artifacts on disk (git history for
`/vulnhunt`, files under `remediation/` for `/remediate`) on every request. There is no
database and no historical trend view across runs — see
[dashboard/README.md](../dashboard/README.md)'s "What this is NOT (yet)" section.

| Page | Route | Purpose |
|---|---|---|
| Overview | `/` | KPI summary across both pipelines — SLA breached/at-risk/on-track counts, KEV/EPSS coverage, risk-tier and asset-class breakdown. `[SCREENSHOT: Overview]` |
| Code Scan | `/vulnhunt` | The `/vulnhunt` findings table, parsed from `SECURITY_REPORT.md`. `[SCREENSHOT: Code Scan]` |
| Remediation Queue | `/queue` | The **live**, re-scored remediation queue — priority, SLA due date/breach status, and MITRE ATT&CK tags, recomputed on every page load from whatever `remediation/config/priority_rules.yaml` currently says. Sortable client-side. `[SCREENSHOT: Queue]` |
| Remediation Plan | `/remediate` | The **static** snapshot from `REMEDIATION_PLAN.md`, linked to generated playbooks. See [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) for why this and the Queue page are two different (related) things. |
| Playbook detail | `/playbooks/<filename>` | Full content of one generated Ansible playbook, for review before anyone runs it. `[SCREENSHOT: Playbook detail]` |
| Priority Rules | `/priority-rules` | Form-based editor for `remediation/config/priority_rules.yaml`. Save it and the Queue page and Overview KPIs update immediately — no pipeline re-run needed. `[SCREENSHOT: Priority Rules editor]` |
| ServiceNow | `/servicenow` | Previews the exact Incident payload for every finding with **zero credentials required**; only sends anything if you supply real credentials and explicitly confirm. `[SCREENSHOT: ServiceNow preview]` |
| Run Pipeline | `/run` | Form wrapping the headless CLI — dry-run by default, plus a recent-run audit log. `[SCREENSHOT: Run Pipeline]` |
| AI Assist | `/ai-assist` | Ask Claude to explain a finding, draft remediation steps, or write an executive summary — preview the exact prompt for free, explicit confirm to spend real API usage. See [AI_COMMANDS.md §4](AI_COMMANDS.md). `[SCREENSHOT: AI Assist]` |
| Reports | `/reports` | Generate a shareable KPI/SLA/coverage snapshot report (daily/weekly/monthly/quarterly/half-yearly/yearly framing), downloadable as standalone HTML. Every number is real; see the page's own caveat about period aggregation not existing yet (no persistence layer). `[SCREENSHOT: Reports]` |
| Support | `/support` | How to get help, known limitations, before-you-file-a-bug checklist. |
| FAQ | `/faq` | Direct answers to common questions — mirrors [FAQ.md](FAQ.md). |
| `/api/status` | — | Machine-readable health/status JSON, not a UI page. |

The sidebar also has a **tenant switcher** ("All Tenants (MSSP view)" / "Acme Financial
Corp (demo)" / "Northwind Bank (demo)") that partitions the Remediation Queue by asset
category to demo an MSSP-style per-client view. It is a UI-only illustration — not real
per-tenant authentication or data isolation. See [FAQ.md](FAQ.md#does-it-support-multiple-tenantsclients-mssp).

Before exposing this beyond localhost or a trusted network: it has **no authentication or
RBAC** — anyone who can reach the port can view findings and trigger a real, paid pipeline
run. See [dashboard/README.md](../dashboard/README.md) and
[COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) for what's missing before that changes.

---

## 4. Interpreting the fields: severity, priority, risk tier, SLA

These are four different axes, computed by different parts of the system, and it's easy
to conflate them:

- **Severity** (`Critical` / `High` / `Medium` / `Low`) — how bad the underlying issue is
  in isolation. Set by `vuln-scanner` for code findings, or carried over from
  Tenable's `Risk`/CVSS, Armis's `riskLevel`, or the threat-intel entry's own `severity`
  field for infra findings (`vuln-ingest-normalizer`'s normalization rules). It does not
  account for exploitation likelihood or where the asset sits.
- **KEV / EPSS** — real-world exploitation signals attached by `threat-intel-enricher`
  (CISA KEV: confirmed actively exploited, yes/no; EPSS: 0–1 probability of exploitation
  in the next 30 days). These feed **priority**, never severity or risk tier directly.
- **Risk tier** (`auto-approvable` / `needs-change-approval` / `manual-only`) — how safe
  a *fix* is to run, assigned by `remediation-planner` based on blast radius and asset
  criticality (domain controllers, auth servers, and anything with plausible outage risk
  default to `needs-change-approval`). **KEV/EPSS never change risk tier** — an
  actively-exploited CVE on a domain controller is still `needs-change-approval`, just
  more urgent to get approved. This is a deliberate, load-bearing rule — see
  [KNOWLEDGE_TRANSFER.md §4.3](../KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision).
- **Priority** (`High` / `Medium` / `Low` in `REMEDIATION_PLAN.md`, or the finer-grained
  `Critical`/`High`/`Medium`/`Low` you see on the live `/queue` page) — how urgently to
  act. A KEV-listed finding is escalated to top priority regardless of asset type; an
  EPSS ≥ 50% finding is elevated even without KEV listing; otherwise it falls back to
  severity + asset criticality. There are **two separate priority computations** in this
  repo — `remediation-planner`'s one-time snapshot logic and the dashboard's live
  `remediation/config/priority_engine.py` — see
  [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) for why both exist and how they
  relate.
- **SLA due date / breach status** — computed only by the live priority engine
  (`priority_engine.py`), from `sla_days` in `remediation/config/priority_rules.yaml`
  (default: Critical 3 days, High 7, Medium 30, Low 90). `REMEDIATION_PLAN.md`'s static
  snapshot has no SLA field — that's Queue-page-only.

---

## 5. Reviewing and approving a generated Ansible playbook

Every playbook under `remediation/output/*.yml` is written by `remediation-fixer-windows`
or `remediation-fixer-unix`, and both subagents have **only `Read`/`Write` tool access —
no `Bash`, no network tool, no credentials** (their `.claude/agents/*.md` frontmatter, not
a policy that could be prompted around). They cannot execute anything even if a prompt
tried to instruct them to. Before running a generated playbook against anything real:

1. **Open it** — either directly, or via the dashboard's `/playbooks/<filename>` page.
2. **Check the header comment** — every playbook states the finding ID(s) it addresses,
   its risk tier, and a rollback instruction copied from `REMEDIATION_PLAN.md`.
3. **If it says `# CHANGE APPROVAL REQUIRED before running`** — this finding's
   `risk_tier` is `needs-change-approval`. Route it through your organization's normal
   change-management process before anyone runs it. This is not optional and not a
   suggestion the playbook itself can override.
4. **Verify specifics the fixer refused to guess at** — e.g. an exact KB number for a
   Windows patch, or the exact patched package version for a distro. The fixer agents are
   explicitly instructed not to fabricate these; they say "verify against the vendor
   advisory" in a comment instead. Do that verification before running.
5. **Run it through your own reviewed pipeline** — an Ansible Tower/AWX-style approved
   automation platform, or a human running `ansible-playbook` directly after review. This
   repo does not run playbooks for you, by design.

---

## 6. The safety model, in practice

Nothing in this repository ever executes against real infrastructure automatically —
**by construction, not by policy**. In practice, day-to-day, that means:

- `vuln-scanner` cannot edit or create files (no `Edit`/`Write` in its tool list) — the
  stage that finds vulnerabilities cannot introduce new ones.
- `vuln-fixer` always works on a fresh branch and pushes for review; it never commits to
  `main`, and if the push fails it stops and tells you the manual step rather than
  silently doing nothing or falling back to `main`.
- `remediation-fixer-windows`/`remediation-fixer-unix` have no execution or network
  capability at all — this is the single most load-bearing safety property in the whole
  project (see
  [KNOWLEDGE_TRANSFER.md §4.3](../KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision)).
- The headless CLI and the dashboard's `/run` and `/servicenow` forms are **dry-run/preview
  by default** — actually spending API usage or sending a real ServiceNow Incident
  requires an explicit flag (`--dry-run` off) or an explicit confirm checkbox. Neither
  defaults to "on."
- Risk tiers default conservative when uncertain — `remediation-planner` is instructed to
  pick `needs-change-approval` over `auto-approvable` whenever it isn't sure, as a
  deliberate design choice rather than caution to relax later.

---

## 7. Agent-based vs. agentless scanning

This distinction gets asked about often enough to spell out precisely, because
"agent" means two different things in this repo depending on which half you mean.

**`/vulnhunt`'s code scanning is agentless in the security-tooling sense.** It is static
analysis of source code already sitting in a git repository or working directory —
`vuln-scanner` uses `Read`/`Grep`/`Glob`/`Bash` to read files and search patterns. Nothing
is installed on, or connects to, any target system to run this scan; there is no runtime
footprint on a server, container, or endpoint. "Point it at a path" means exactly that —
a filesystem path, not a network target or a fleet of hosts with something installed on
them.

**Infrastructure findings are ingested, not scanned, by VulnHunter.** The vulnerability
data behind `/remediate` — CVEs on hosts, device-risk alerts — comes from Tenable and
Armis, via their own export formats (or, per [INTEGRATIONS.md](INTEGRATIONS.md), their
live APIs once you have credentials). **Whether Tenable or Armis themselves use an
agent-based or agentless scanning approach against your infrastructure is a
configuration choice made in *that vendor's own product*** — Tenable, for instance, has
separate agent-based (Nessus Agent) and agentless (network scanner) deployment modes;
Armis is inherently agentless (passive network/traffic-based device discovery). VulnHunter
does not re-implement, control, or care which mode produced the export it's reading — it
is a **consumer and normalizer** of whatever Tenable/Armis already reported
(`vuln-ingest-normalizer.md`), not a network scanner or an endpoint agent itself. If your
organization needs to decide agent vs. agentless for infrastructure vulnerability
scanning, that decision is made in Tenable/Armis's own console, not in this repository.

("Claude Code subagents," the mechanism behind every VulnHunter pipeline stage, is an
unrelated, third use of the word "agent" — a Claude Code orchestration concept, not a
scanning deployment mode. See [AI_COMMANDS.md](AI_COMMANDS.md) for what each one does.)

---

## See also

- [FAQ.md](FAQ.md) — specific yes/no questions about what this does and doesn't do.
- [AI_COMMANDS.md](AI_COMMANDS.md) — exact syntax/flags/tool-scopes for every AI-facing
  entry point.
- [INTEGRATIONS.md](INTEGRATIONS.md) — what's real, verified, or built-but-unverified for
  every external system this connects to.
- [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md) — the full `/remediate` lifecycle,
  end to end.
- [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) — what this is and is not, compliance-wise.
- [SUPPORT.md](SUPPORT.md) — how to get help or report a bug.
- [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) and [README.md](../README.md) — the
  canonical, repo-root docs this guide summarizes for day-to-day use.
