# VulnHunter — Knowledge Transfer & Product Overview

This document is the single place to understand *what VulnHunter is, why it exists, how
it works, and how to actually run it* — written so anyone picking up this repo cold
(a teammate, a judge, a future you) can get productive without a walkthrough call.

For quick reference, the other docs in this repo are:
- [README.md](README.md) — pitch-oriented overview, architecture diagrams, demo script
- [CLAUDE.md](CLAUDE.md) — instructions for Claude Code when working *on* this repo's code
- [REMEDIATION_PLAN.md](REMEDIATION_PLAN.md) — a real, generated sample output
- [deliverables/](deliverables/) — the hackathon pitch deck (`.pptx`) and project report (`.docx`)

This document goes deeper than either: it's the KT.

---

## 1. Executive Summary

VulnHunter is a **Claude Code extension** — not a standalone application — built for the
Deloitte Claude Code Hackathon. It adds two slash-command pipelines to Claude Code:

| Pipeline | What it does | Status |
|---|---|---|
| **`/vulnhunt`** | Scans source code for vulnerabilities, writes a ranked report, auto-fixes the safe findings on a branch | Built, validated, PR-ready |
| **`/remediate`** | Ingests vulnerability findings from Tenable, Armis, and threat intel; normalizes them; plans remediation by risk; generates reviewable Ansible playbooks for Windows/Unix servers | Built, validated, PR-ready |

Both are implemented as Claude Code **subagents** (`.claude/agents/*.md`) orchestrated by
**slash commands** (`.claude/commands/*.md`) — there is no separate backend, database, or
service to deploy. The "product" is a set of markdown prompt/config files plus one
intentionally vulnerable demo app and some sample vulnerability-scan data, all of which
live in this repository.

**The one idea that ties everything together:** every subagent's tool access is
deliberately restricted so that *safety is architectural, not a matter of prompting
discipline*. A subagent that finds problems cannot also create them; a subagent that
writes fixes cannot execute anything against real infrastructure. See [§4.3](#43-the-safety-model-the-single-most-important-design-decision).

---

## 2. Problem Statement

Two versions of the same underlying problem, one for code and one for infrastructure:

**Code:** Static analysis tools produce reports nobody reads end-to-end. Finding a
vulnerability and *actually fixing it* are two different jobs — a scanner flags a SQL
injection; a person still has to open the file, write the parameterized query, test it,
and get it reviewed. Most tooling stops at the report.

**Infrastructure:** This is the same problem at a much larger scale. In a real enterprise
security program, vulnerability findings arrive from multiple, incompatible sources:

- **Tenable** (or similar scanners) — CVE-based findings against known hosts, with CVSS
  scores and vendor-suggested fixes
- **Armis** — device-risk findings, heavy on IoT/OT and unmanaged devices Tenable-style
  agents can't reach (cameras, building automation controllers, phones)
- **Manual/analyst threat intel** — human-curated findings from threat hunting, vendor
  advisories, and external attack-surface sweeps

...landing on assets as different as **Windows servers, Unix servers, end-user devices,
network routing/switching, and network security devices (firewalls)**. Each source has
its own schema, its own severity scale, its own asset identifiers. Turning any of this
into an actual, safe fix — patching a CVE, tightening a firewall rule, disabling an
exposed service — is almost entirely manual today, and the manual translation step is
exactly where backlogs pile up.

**The ask that started this second half of the project** (paraphrased from the
conversation that drove it): *"We have vulnerabilities detected from Tenable, manual
threat intel, and Armis, and we have to remediate them across Windows servers, end-user
devices, Unix servers, network routing/switching, and network security devices — instead
of manual remediation effort, is there an AI-based remediation solution that can help?"*

`/remediate` is the direct answer to that question, built to the same safety standard as
`/vulnhunt`.

---

## 3. The Idea — Origin and Why This Approach

### 3.1 Context this was built for

A Claude Code hackathon at Deloitte, judged by Claude itself, open to all participants.
The author's background is cybersecurity, which shaped the choice of project: rather than
a generic CRUD app, build something that is *itself* a demonstration of what an
AI-security-engineer-in-a-box can do — a project that is simultaneously the entrant and a
proof of the judging model (an AI evaluating AI-built security tooling).

### 3.2 Why "find AND fix," not just "find"

Most hackathon security projects stop at a scanner — a linter wrapper with an LLM
narrating the output. The differentiator here is closing the loop: **scan → triage → fix
→ branch/PR**, with a human decision point before anything ships. That loop is what makes
the project feel agentic (multiple cooperating subagents with distinct responsibilities)
rather than "I called an API and printed the response."

### 3.3 Why subagents with scoped tools, specifically

The design choice that recurs through every stage of this project: **give each subagent
only the tools its job requires, and let that scoping *be* the safety mechanism.**

- `vuln-scanner` can `Read`/`Grep`/`Glob`/`Bash` but not `Edit`/`Write` — the tool that
  *finds* vulnerabilities is architecturally incapable of introducing new ones.
- `vuln-triage-reporter` can only `Write` — it cannot re-scan or "helpfully" fix anything,
  it only organizes what it's told.
- `vuln-fixer` can `Read`/`Edit`/`Write`/`Bash`, but its git workflow always creates a new
  branch and pushes for review — it is never allowed to commit to `main`.
- `remediation-fixer-windows`/`remediation-fixer-unix` can only `Read`/`Write` — **no
  `Bash`, no network tool, no credentials** — so even if a prompt somehow instructed one
  to "just apply this to the real server," it has no mechanism to do so. This is the
  single most important safety property in the whole project.

This was a deliberate alternative to the originally-suggested idea of running everything
inside a Docker sandbox for safety. Docker wasn't available/working reliably in this
environment (see [§12 Troubleshooting](#12-troubleshooting--things-that-tripped-us-up)),
and tool-scoping turned out to be a *better* safety story anyway: it doesn't depend on
container escape resistance, it's auditable by reading three lines of YAML frontmatter,
and it's enforced by Claude Code itself, not by infrastructure the project has to stand up.

### 3.4 Why extend into infrastructure remediation

`/vulnhunt` alone answers "can an agent fix code vulnerabilities safely." The natural
next question — and the one that came up mid-hackathon — was whether the same pattern
generalizes to the much messier, much higher-stakes world of enterprise infrastructure
vulnerability management. `/remediate` is that generalization: same philosophy
(ingest → normalize → plan by risk → generate reviewable fixes), same safety model
(no fixer subagent can execute against real infrastructure), extended to a domain where
the "real infrastructure" in question is Windows servers, Unix servers, network gear, and
IoT/OT devices instead of a single demo app's source files.

---

## 4. Product / Solution Details

### 4.1 `/vulnhunt` — Code Scanning & Fixing Pipeline

```
/vulnhunt <path> [--fix]
        │
        ▼
  vuln-scanner            Read, Grep, Glob, Bash        → JSON findings
        │                  (read-only, cannot modify anything)
        ▼
  vuln-triage-reporter    Write only                     → SECURITY_REPORT.md
        │
        ▼
  vuln-fixer              Read, Edit, Write, Bash        → new branch + push (only if --fix)
```

**What it finds:** injection flaws (SQL, command, code/`eval`), hardcoded secrets,
auth/crypto weaknesses, insecure configuration, risky pinned dependencies, and unsafe
Docker practices. Each finding gets a severity (Critical/High/Medium/Low), a CWE ID where
applicable, and an `auto_fixable` flag.

**What it fixes automatically:** only findings marked `auto_fixable: true` — mechanical,
behavior-preserving changes like parameterizing a query, moving a secret to an environment
variable, or dropping container root privileges. Anything needing a real design decision
(replacing `eval()` where the app's behavior depends on it, migrating password storage) is
explicitly left for a human, with a stated reason.

**Validated result** (against the included `vulnerable-demo-app/`): 9 findings (4
Critical, 2 High, 2 Medium, 1 Low), 6 auto-fixed on branch
`vulnhunter/auto-fixes-20260803` and pushed, 3 flagged for manual review. See
`vulnerable-demo-app/SECURITY_REPORT.md` on that branch for the full generated report.

### 4.2 `/remediate` — Infrastructure Remediation Pipeline

```
/remediate [--generate]
        │
        ▼
  vuln-ingest-normalizer     Read, Glob, Write   → normalizes Tenable CSV / Armis JSON /
        │                                          threat-intel JSON into one Finding schema
        ▼
  threat-intel-enricher      Read, Write, Bash   → adds live CISA KEV + EPSS data to
        │                                          every finding with a CVE
        ▼
  remediation-planner        Read, Write         → REMEDIATION_PLAN.md: action type,
        │                                          risk tier, priority (KEV/EPSS-aware), rollback
        ▼
  ┌─────────────────────┴─────────────────────┐
  ▼                                            ▼
remediation-fixer-windows          remediation-fixer-unix
Read, Write (no Bash/network)      Read, Write (no Bash/network)
→ Ansible playbooks                → Ansible playbooks
(windows-server findings only)     (unix-server findings only)
```

**Ingestion:** `vuln-ingest-normalizer` reads Tenable's CSV export format, Armis's
device-risk JSON, and manually-curated threat-intel JSON, and maps every record into one
common schema (documented in
[`remediation/schema/normalized-finding-schema.md`](remediation/schema/normalized-finding-schema.md)).
It also classifies each finding's `asset.type` — **six classes today, spanning OS,
infrastructure, application, and certificate layers, not just code**: `windows-server`,
`unix-server` (OS-level), `network-routing-switching`, `network-security-device`,
`iot-ot-device` (infrastructure-level), `application` (library/framework CVEs like
Log4Shell, where the fix is a code/dependency upgrade, not an OS patch), and
`certificate` (TLS/SSL lifecycle findings — expiry, deprecated protocols — which usually
have no CVE at all). This classification is what routes a finding to a fixer, or
correctly to "no fixer yet."

**Enrichment:** `threat-intel-enricher` calls two real, free, public, no-auth-required
APIs — verified against the live endpoints during development, not mocked like the
Tenable/Armis connectors:
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — is this
  CVE confirmed being actively exploited in the wild?
- **[EPSS](https://www.first.org/epss/)** (FIRST.org) — a probabilistic 0–1 score of
  exploitation likelihood in the next 30 days.

Both get added to every finding with a CVE (`null` for the many findings that don't have
one — certificate and device-policy findings especially). See
[remediation/enrichment/kev_epss.py](remediation/enrichment/kev_epss.py).

**Planning:** `remediation-planner` assigns every finding an `action_type` (patch,
config-change, service-disable, network-restriction, credential-rotation,
firmware-update, or manual-investigation), an `automation_target`, a `risk_tier`
(`auto-approvable` / `needs-change-approval` / `manual-only`), a `rollback_plan`, and a
`priority`. Priority is now threat-intel-aware: a KEV-listed finding is escalated to top
priority regardless of asset type; a high-EPSS (≥50%) finding is elevated even without
KEV listing. **Crucially, KEV/EPSS affect priority, never `risk_tier`** — an
actively-exploited CVE on a domain controller is still `needs-change-approval`, just more
urgent to get approved. The planner defaults to the more conservative risk tier whenever
uncertain — a deliberate design choice, not caution to relax later.

**Fix generation:** `remediation-fixer-windows` and `remediation-fixer-unix` generate
Ansible playbooks for findings already routed to their domain. They never execute
anything — every generated playbook is a `.yml` file under `remediation/output/`, with a
comment header naming the finding it addresses, the risk tier, and a rollback instruction,
ready for human (or your org's Ansible Tower/AWX-style approved pipeline) review.

**Validated result** (against the included mock Tenable/Armis/threat-intel exports,
enriched with real live KEV/EPSS data): 14 findings normalized across all 3 sources and
6 asset classes; 6 are KEV-listed (confirmed actively exploited — including Log4Shell and
PrintNightmare) and 7 have EPSS ≥ 50%; 7 (4 Windows Server, 3 Unix Server) got a generated
playbook; 7 (1 core network switch, IoT/OT/mobile devices, 1 Log4Shell application
finding, 2 certificate/TLS findings) are fully planned but correctly left `manual-only`,
since no fixer exists yet for those asset classes — see
[`REMEDIATION_PLAN.md`](REMEDIATION_PLAN.md) for the full generated report.

### 4.3 The Safety Model (the single most important design decision)

Nothing in this repository ever executes against real infrastructure automatically —
by construction, not by policy:

1. **Fixer subagents have no execution capability.** `remediation-fixer-windows`/`-unix`
   have `tools: Read, Write` only in their frontmatter. No `Bash`. No network tool. No
   credentials. They cannot connect to a host even if a prompt tried to instruct them to.
2. **`vuln-fixer` (code pipeline) never touches `main`.** Its git workflow is always:
   new branch → commit → push. If push fails, it stops and tells the user the manual
   step — it never silently gives up or falls back to committing on `main`.
3. **Risk tiers default conservative.** Domain controllers, auth servers, bastion hosts,
   and anything with plausible outage risk get `needs-change-approval`, not
   `auto-approvable`, even when the underlying fix is mechanical.
4. **Every artifact is reviewable, not self-executing.** A generated Ansible playbook, a
   pushed branch, a written report — a human (or an org's existing change-managed
   automation platform) is always the one who runs it.

---

## 5. Who This Is For / Use Cases

| Audience | How they'd use this |
|---|---|
| **Security engineers / AppSec teams** | Point `/vulnhunt` at a real codebase to get a fast baseline scan + auto-fix PR for the mechanical findings, freeing review time for the ones that need judgment. |
| **Vulnerability management / SOC teams** | Point `/remediate` at real Tenable/Armis exports (swap in live API pulls — see [§9 Roadmap](#9-roadmap)) to turn a raw finding backlog into a prioritized, risk-tiered remediation queue with ready-to-review fix automation. |
| **Platform/DevOps teams** | Use the generated Ansible playbooks as a starting point for an existing Ansible Tower/AWX pipeline, rather than writing remediation playbooks from scratch for every CVE. |
| **Hackathon judges / reviewers** | This document + [README.md](README.md) + [deliverables/](deliverables/) for the full pitch; [§12](#12-troubleshooting--things-that-tripped-us-up) for an honest account of what broke and how it was fixed. |
| **Anyone extending this project** | [§9 Roadmap](#9-roadmap) and [§6 Step 8](#step-8-extend-it) for exactly what a new fixer subagent needs. |

---

## 6. Step-by-Step Knowledge Transfer

### Prerequisites

- **Claude Code** installed and authenticated (this project *is* a Claude Code extension —
  there's nothing to run without it).
- **git** — that's it. No `gh` CLI, no Docker, no other tooling is required to run either
  pipeline (both were deliberately designed to drop these dependencies — see
  [§12](#12-troubleshooting--things-that-tripped-us-up)).
- Python 3.x only if you want to run the test suite or the demo app standalone.

### Step 1: Open the project

```bash
git clone https://github.com/Deloitte-US-Consulting/VulnHunter.git
cd VulnHunter
claude
```

Claude Code auto-discovers the subagents and commands under `.claude/` the moment you
start a session with this directory as the working directory. If you're on the
`feature/remediation-engine` branch, both pipelines are present; `master` currently only
has `/vulnhunt`.

### Step 2: Run `/vulnhunt` (scan + report only)

```
/vulnhunt vulnerable-demo-app
```

This runs `vuln-scanner` → `vuln-triage-reporter` and writes
`vulnerable-demo-app/SECURITY_REPORT.md`. Read that file — it's the full ranked report
with plain-English impact per finding.

### Step 3: Run `/vulnhunt` with auto-fix

```
/vulnhunt vulnerable-demo-app --fix
```

This additionally runs `vuln-fixer`, which creates a new branch (named
`vulnhunter/auto-fixes-<timestamp>`), applies the mechanical fixes, commits, and pushes.
It prints the PR-creation URL GitHub returns on push — open that link (or use VS Code's
Source Control panel) to actually open the PR; this pipeline deliberately has no `gh` CLI
dependency, so opening the PR itself is a manual, one-click step.

### Step 4: Run `/remediate` (ingest + plan only)

```
/remediate
```

With no arguments, this ingests the sample data in `remediation/sample-data/`
(`tenable_export.csv`, `armis_export.json`, `threat_intel.json`), normalizes it into
`remediation/output/normalized-findings.json`, and writes `REMEDIATION_PLAN.md` to the
project root. To point it at different files, pass paths as arguments to the command.

### Step 5: Run `/remediate` with fix generation

```
/remediate --generate
```

This additionally runs `remediation-fixer-windows` and `remediation-fixer-unix` against
the findings the planner routed to each domain, writing one Ansible playbook per finding
under `remediation/output/`. Findings with no supported fixer (network devices, IoT/OT)
are left in the plan as `manual-only`, with the reason stated.

### Step 6: Read the generated artifacts

- `vulnerable-demo-app/SECURITY_REPORT.md` — code scan results
- `REMEDIATION_PLAN.md` — infra remediation queue, risk tiers, rollback plans
- `remediation/output/*.yml` — generated, human-reviewable Ansible playbooks
- `remediation/output/normalized-findings.json` — the common schema output, useful if
  you're building something else on top of the normalizer

**None of these need to be taken on faith** — step 7 shows you how to verify them.

### Step 7: Run the test suite

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

33 tests validate the real artifacts described above (reading git history for the
`/vulnhunt` branches, and the generated files for `/remediate`) — not mocked agent
behavior. Expect `OK` with 0 failures; `tests/test_results.txt` has a captured run. Re-run
this after editing any `.claude/agents/*.md` or `.claude/commands/*.md` file to catch
drift.

### Step 8: Run it headlessly (CI/automation, no interactive session)

```bash
python cli/vulnhunter.py --dry-run scan vulnerable-demo-app --fix   # preview only
python cli/vulnhunter.py scan vulnerable-demo-app --fix              # spends real API usage
python cli/vulnhunter.py --dry-run remediate --generate
python cli/vulnhunter.py remediate --generate
```

`cli/vulnhunter.py` is a thin wrapper around `claude -p` (Claude Code's non-interactive
mode) — it doesn't reimplement any pipeline logic, it just removes the requirement for a
human to be typing into a live session, which is what makes this usable from CI, cron, or
any other automation. **Every non-dry-run invocation spends real Claude API usage** — see
[cli/README.md](cli/README.md) before wiring this into anything that runs unattended or
on every push. `tests/test_cli.py` covers the command-construction logic without ever
calling the real API.

### Step 8.5: View it in the dashboard

```bash
pip install -r dashboard/requirements.txt
python dashboard/app.py
# open http://127.0.0.1:5050
```

A read-mostly web UI over the same artifacts: KPI overview, both findings tables, the
remediation queue linked to generated playbooks, and a `/run` page that wraps the CLI
above (dry-run by default, same cost posture). See [dashboard/README.md](dashboard/README.md)
for the full page list and — importantly — what this MVP deliberately does not have yet
(auth, persistence, a job queue) before considering exposing it beyond localhost.

### Step 9: Extend it

The most likely next build-out, per [§9 Roadmap](#9-roadmap), is a new remediation fixer
for network devices or IoT/OT. To add one:

1. Create `.claude/agents/remediation-fixer-network.md` with **`tools: Read, Write`
   only** — do not widen this to include `Bash` or any network/execution tool; that
   restriction is the safety model, not an oversight to fix.
2. Follow the pattern in `remediation-fixer-windows.md`/`remediation-fixer-unix.md`:
   generate vendor-appropriate config (e.g. Ansible's `cisco.ios`/`junipernetworks.junos`
   collections) into `remediation/output/<finding-id>-<slug>.yml`, with the same
   finding-ID/rollback/change-approval-marker conventions.
3. Update `remediation-planner.md`'s `automation_target` assignment rule to route
   `network-routing-switching` findings to the new fixer instead of `manual-only`.
4. Update `.claude/commands/remediate.md` to delegate the relevant findings subset to the
   new fixer.
5. Add test cases to `tests/test_pipeline_artifacts.py` mirroring
   `RemediationPlaybooksMatchThePlan` for the new fixer, and re-run the suite.

---

## 7. Repository Map

```
.
├── .claude/
│   ├── agents/
│   │   ├── vuln-scanner.md               /vulnhunt: read-only code scanner
│   │   ├── vuln-triage-reporter.md       /vulnhunt: write-only report generator
│   │   ├── vuln-fixer.md                 /vulnhunt: fixes + branch/push
│   │   ├── vuln-ingest-normalizer.md     /remediate: multi-source ingestion
│   │   ├── threat-intel-enricher.md      /remediate: live CISA KEV + EPSS enrichment
│   │   ├── remediation-planner.md        /remediate: risk-tiered, threat-intel-aware planning
│   │   ├── remediation-fixer-windows.md  /remediate: Windows Ansible playbooks
│   │   └── remediation-fixer-unix.md     /remediate: Unix Ansible playbooks
│   └── commands/
│       ├── vulnhunt.md                   orchestrates the code pipeline
│       └── remediate.md                  orchestrates the infra pipeline
├── .github/
│   ├── workflows/ci.yml       runs the full test suite on every push/PR
│   ├── CODEOWNERS, ISSUE_TEMPLATE/, PULL_REQUEST_TEMPLATE.md
├── cli/
│   ├── vulnhunter.py          headless CLI wrapper around `claude -p` (no API calls
│   │                          from the prompt logic itself - see cli/README.md)
│   └── README.md              usage, cost warning, binary discovery order
├── dashboard/
│   ├── app.py                 Flask dashboard - Overview/Queue/Plan/Priority Rules/
│   │                          ServiceNow/Code Scan/Run Pipeline, sidebar nav
│   ├── data.py                 parses real artifacts + wraps priority_engine/attack_mapping
│   ├── templates/, static/     Jinja2 templates + CSS (sidebar layout, SLA/priority badges)
│   ├── requirements.txt        flask, pyyaml, requests
│   └── README.md                scope, safety design, and explicit "not yet" list
├── remediation/
│   ├── sample-data/       mock Tenable/Armis/threat-intel exports (14 findings: OS,
│   │                      infra, IoT/OT, application, and certificate categories)
│   ├── schema/            normalized Finding schema documentation (now includes kev/epss)
│   ├── connectors/        live Tenable/Armis/ServiceNow API clients - built, unit-tested
│   │                      against mocked HTTP, unverified against a real tenant (see README)
│   ├── enrichment/        live CISA KEV + EPSS client (verified against real public
│   │                      endpoints) + MITRE ATT&CK keyword-tagging heuristic
│   ├── config/            configurable priority/SLA rules engine (YAML + Python),
│   │                      editable live from the dashboard's /priority-rules page
│   └── output/            normalized findings + generated playbooks (generated, not hand-written)
├── vulnerable-demo-app/   intentionally vulnerable Flask app — /vulnhunt's scan target
├── tests/
│   ├── test_pipeline_artifacts.py   35 automated tests, stdlib only
│   ├── test_cli.py                  13 tests for the headless CLI (no real API calls)
│   ├── test_dashboard.py            25 tests for the dashboard (Flask test client, no real server)
│   ├── test_connectors.py           18 tests for the Tenable/Armis connectors (mocked HTTP)
│   ├── test_enrichment.py           13 tests for KEV/EPSS enrichment (mostly mocked, 1 live)
│   ├── test_priority_engine.py      14 tests for the configurable priority/SLA engine
│   ├── test_attack_mapping.py       11 tests for the MITRE ATT&CK keyword heuristic
│   ├── test_servicenow_connector.py 16 tests for the ServiceNow adapter (mocked HTTP)
│   └── test_results.txt             a captured passing run (145/145)
├── deliverables/
│   ├── VulnHunter_Hackathon_Deck.pptx     Deloitte-branded pitch deck
│   └── VulnHunter_Project_Report.docx     full project & test report
├── LICENSE, SECURITY.md, CHANGELOG.md
├── REMEDIATION_PLAN.md    a real, generated sample /remediate output
├── README.md              pitch-oriented overview + demo script
├── CLAUDE.md              instructions for Claude Code working on this repo
├── TEST_CASES.md          formal test case log: steps, expected vs. actual, per test
└── KNOWLEDGE_TRANSFER.md  this document
```

---

## 8. Test Evidence & Results

145 tests, 0 failures, across eight suites. None of it calls the real Claude API (see
each file's docstring for why that's a hard rule, not an oversight) — the one deliberate
exception is `test_enrichment.py`'s live smoke test, which calls the real, free, public
CISA KEV/EPSS APIs (safe: no auth, no cost, and it skips itself rather than failing if
network is unavailable).

| Test file | What it checks | Count |
|---|---|---|
| `tests/test_pipeline_artifacts.py` | Both pipelines' real output artifacts — see breakdown below | 35 |
| `tests/test_cli.py` | Headless CLI command construction, binary discovery, one real dry-run subprocess call | 13 |
| `tests/test_dashboard.py` | Dashboard data parsing + every route (incl. live queue, priority-rules editor, ServiceNow preview) | 25 |
| `tests/test_connectors.py` | Live Tenable/Armis connector auth/pagination/mapping logic against mocked HTTP | 18 |
| `tests/test_enrichment.py` | CISA KEV + EPSS enrichment logic, mostly mocked plus one real live-API smoke test | 13 |
| `tests/test_priority_engine.py` | Configurable priority scoring + SLA computation against the real rules file | 14 |
| `tests/test_attack_mapping.py` | MITRE ATT&CK keyword heuristic, including deliberate non-matches | 11 |
| `tests/test_servicenow_connector.py` | ServiceNow Table API adapter — idempotency, body construction, batch error handling | 16 |

`test_pipeline_artifacts.py` breakdown:

| Test class | What it checks | Count |
|---|---|---|
| `VulnHuntScannerFindsRealVulnerabilities` | The vulnerable baseline genuinely contains the claimed flaws | 7 |
| `VulnHuntFixerAppliesOnlyApprovedFixes` | The fix branch fixes exactly the auto-fixable findings, nothing else | 8 |
| `VulnHuntReportIsAccurate` | `SECURITY_REPORT.md`'s stated numbers match reality | 3 |
| `RemediationNormalizedFindingsAreWellFormed` | Schema correctness, asset classification, no fabricated CVEs | 7 |
| `RemediationPlanIsConsistentWithFindings` | Every finding is accounted for in the plan | 2 |
| `RemediationPlaybooksMatchThePlan` | Generated playbooks exactly match automatable findings | 5 |
| `NoRealSecretsLeakedAnywhere` | No real-looking secret patterns anywhere in tracked files | 1 |

**For the full test case log** — every test's individual steps, preconditions, expected
result, and actual result, with a TC-ID for traceability — see
**[TEST_CASES.md](TEST_CASES.md)**.

The suite itself caught 3 real issues worth being upfront about: two false-positive test
assertions (matching comment prose instead of actual code — fixed by tightening the
regexes), and one real GitHub secret-scanning block on a fake API key that was
realistic enough to trip Stripe's key-format detector (fixed by reformatting the fake
key and rewriting the not-yet-pushed local git history to remove it everywhere). Full
detail on all three in TEST_CASES.md's "Notable findings" section.

---

## 9. Roadmap — Path to Commercial-Grade

This project is a Claude Code extension, validated and demoable, not yet a commercial
product. The gap between the two is real engineering, not polish — laid out here in three
tiers so priority and sequencing are explicit rather than an undifferentiated backlog.

### Tier 1 — Repo & Trust Hygiene ✅ Done

Fast, low-risk, makes the repo look maintained rather than dropped: `LICENSE`,
`SECURITY.md`, CI (`.github/workflows/ci.yml`) running the full test suite on every
push/PR, `CODEOWNERS`, issue/PR templates, `CHANGELOG.md`, README badges.

### Tier 2 — Make It an Actual Tool (core items done, hardening ongoing)

Usable by someone who isn't running Claude Code interactively:

1. **Headless CLI (`cli/vulnhunter.py`)** ✅ Done — wraps `claude -p` so either pipeline
   runs from a script/CI/cron without a human in an interactive session, without
   duplicating any prompt logic. Every real invocation spends API usage/credits — see
   [cli/README.md](cli/README.md).
2. **Web dashboard (`dashboard/`)** ✅ MVP done — findings, remediation queue, generated
   playbooks, and a run-trigger page, reading off the same real artifacts. Built with
   Flask/Jinja2 rather than React because Node.js wasn't available in the build
   environment; see [dashboard/README.md](dashboard/README.md) for that tradeoff and,
   more importantly, what this MVP still lacks (auth/RBAC, persistence, a job queue,
   multi-tenancy) before it's more than a local/trusted-network tool.
3. **Live Tenable/Armis connectors (`remediation/connectors/`)** ✅ Built, ⚠️ unverified
   against a real tenant — implements each vendor's publicly documented API contract
   (Tenable's async vulnerability export workflow; Armis's token auth + paginated AQL
   search), writing output in the exact same file shapes as the samples so
   `vuln-ingest-normalizer.md` needs zero changes. 18 tests cover the logic against
   mocked HTTP responses shaped like each vendor's documentation — but no real API
   credentials were available while building this, so it has never actually talked to a
   live Tenable/Armis tenant. See [remediation/connectors/README.md](remediation/connectors/README.md)
   for exactly what "tested" does and doesn't mean here, and what to verify before
   pointing it at a real account.
4. **CISA KEV + EPSS threat-intel enrichment (`remediation/enrichment/`)** ✅ Done, ✅
   verified against the real live public APIs — unlike the Tenable/Armis connectors,
   both CISA's KEV feed and FIRST.org's EPSS API are free and require no credentials, so
   this was built AND tested against production endpoints during development. Moves
   prioritization beyond raw CVSS: a KEV-listed finding (confirmed actively exploited)
   or high-EPSS finding (≥50% near-term exploitation probability) is escalated to top
   priority regardless of asset type — though never auto-approved purely because of
   that; risk tier still gates what's safe to automate. See
   [remediation/enrichment/kev_epss.py](remediation/enrichment/kev_epss.py).
5. **Application and certificate asset classes** ✅ Done — `asset.type` now spans
   `application` (library/framework CVEs like Log4Shell, fixed via the app's own
   build/release pipeline, not an OS patch) and `certificate` (TLS/SSL lifecycle
   findings — expiry, deprecated protocols — which usually carry no CVE at all). Both
   route to `manual-only` today, same honest-gap treatment as network/IoT, since no
   fixer exists yet for either.
6. **Persistence + audit log** — a database of runs, findings, and who approved what,
   replacing the flat JSON audit files the CLI writes today and the dashboard reads.

Also planned in this tier, lower priority than the items above:
- **`remediation-fixer-network`** — vendor CLI config diffs (Cisco IOS/IOS XE, Junos) via
  Ansible's network collections, same `Read`/`Write`-only tool scoping as the existing
  fixers.
- **`remediation-fixer-iot`** — realistically a per-vendor integration effort given how
  fragmented IoT/OT management APIs are; start with the highest-volume device types in a
  real fleet (Armis-visible cameras and building-automation controllers).
- **`remediation-fixer-application`** — a library/dependency upgrade goes through the
  app's own build/release pipeline (Maven/Gradle, npm, pip, ...) — a fundamentally
  different mechanism per language/package manager, unlike the OS-level fixers' shared
  Ansible approach.
- **Certificate/TLS fixer** — mechanically simple (renew via ACME, disable a deprecated
  protocol in a config file) but organization-specific enough (which CA, which ACME
  client, which web server) that no generic fixer exists yet.
- **Mobile/endpoint remediation via MDM** — findings like "outdated iOS version" route
  through an MDM platform's compliance policies (Intune/Jamf API), a different
  integration entirely from infra automation.

### Tier 3 — Enterprise / Commercial Ready (partially started)

What a real buyer's security architect will actually ask for. Some of this is now real
(see below); the rest needs business decisions this document can't make unilaterally.

**Done:**
- **ServiceNow ticketing integration** (`remediation/connectors/servicenow_connector.py`)
  — creates an Incident per finding via the Table API, idempotent (checks
  `correlation_id` before creating a duplicate), with a preview mode in the dashboard's
  `/servicenow` page that shows exactly what would be sent without needing real
  credentials. Same "built against docs, unverified against a live instance" caveat as
  the Tenable/Armis connectors.
- **Configurable priority rules + SLA tracking**
  (`remediation/config/priority_engine.py`, editable at `/priority-rules`) — an admin
  can retune severity/asset-criticality/KEV/EPSS weights and SLA windows per priority
  tier, and see the `/queue` page and Overview KPIs update immediately, with no pipeline
  re-run. This is deliberately a *separate* live-scoring layer from
  `remediation-planner`'s own baked-in prompt logic — see
  [remediation/config/README.md](remediation/config/README.md) if one exists, or the
  module docstring, for that distinction.
- **MITRE ATT&CK tagging** (`remediation/enrichment/attack_mapping.py`) — a keyword
  heuristic, explicitly documented as such (not authoritative technique attribution),
  surfaced on the `/queue` page.
- **Modernized dashboard nav** — a sidebar layout (Overview / Code Scan / Remediation
  Queue / Remediation Plan / Priority Rules / ServiceNow / Run Pipeline), still Flask/
  Jinja2 (Node.js unavailable in the build environment at time of writing — see §12).

**Not started, needs a business/architecture decision first:**
- **Auth, RBAC, SSO, multi-tenancy** — the current dashboard has zero authentication and
  zero persistence; every request re-reads local files. "One tenant = one client" MSSP
  architecture needs a real database and auth layer *before* it needs more features —
  see §11 below for why this can't be bolted on incrementally.
- **Compliance certification (SOC2, NIST, etc.)** — not a coding task. SOC2 is an audit
  by a licensed CPA firm over months of operational evidence; NIST CSF alignment is a
  self-attestation or third-party assessment. This repo can build toward the *controls*
  (audit logging, RBAC, encryption) but cannot claim "compliant" — doing so, especially
  when pitching to banks, is a legal/regulatory risk, not a feature gap.
- **Deployment + pricing model** — SaaS vs. self-hosted, and a real answer to "what does
  this cost per customer given Claude API usage at scale."

---

## 11. The Enterprise/MSSP Platform Ask — Scope Reality Check

Partway through this project, the ask expanded to: modern intuitive dashboards with
KPIs/SLAs, a full "industry tool"-grade menu, dark-web monitoring, SIEM/XDR/pentest-tool
integration, NIST/SOC2 compliance, a configurable priority engine, ServiceNow, built-in
AI, MITRE ATT&CK-style detection, scheduled reporting (daily through yearly), and
multi-tenant MSSP architecture — explicitly framed as needing to out-compete "industry
tools." Worth being explicit about what that actually describes and what came of it,
since it's a different category of ask than everything before it in this document.

**What that ask describes:** a platform comparable to Qualys VMDR + Tenable.io +
ServiceNow SecOps + a threat-intel platform (Recorded Future/Flashpoint-class) combined.
That's a multi-year, multi-team product category — not a feature list a coding session
finishes.

**What was actually built from it** (real, tested, described above): the ServiceNow
adapter, the configurable priority/SLA engine, MITRE ATT&CK tagging, and a modernized
dashboard nav.

**What was deliberately NOT built, and why:**
- **Dark-web monitoring** — real providers (Recorded Future, Flashpoint, DarkOwl, KELA)
  maintain that access through years of specialized, legally-vetted infrastructure.
  Building a crawler to access dark-web marketplaces/forums ourselves is a different risk
  category than everything else in this repo. The right architecture is a **vendor API
  adapter** (same connector pattern as Tenable/Armis/ServiceNow) once a specific vendor
  and contract exists — not a scraper.
- **SIEM/XDR/pentest-tool adapters (beyond ServiceNow)** — the connector *pattern* is
  proven three times over now (Tenable, Armis, ServiceNow); adding Splunk, Sentinel,
  QRadar, CrowdStrike, or Defender adapters is the same pattern again, gated on picking
  one and having its API docs (or better, a real sandbox) to build against.
- **"AI-based anomaly/behavioral detection"** — a distinct, open-ended ML engineering
  effort (model selection, training data, false-positive tuning), not something to bolt
  on alongside everything else here without its own dedicated scope discussion.
- **Multi-tenant MSSP architecture** — requires the database + auth foundation from Tier
  3 above *first*. Building tenant isolation on top of a filesystem-reading Flask MVP
  would mean rebuilding it twice.
- **NIST/SOC2/"any relevant compliance"** — see Tier 3 above. Not a code deliverable.

None of this is a "no" — it's each of these being its own real scope of work, most of
which need a decision (which vendor, which cloud, which compliance framework actually
matters for this business) before code is the bottleneck.

---

## 12. Troubleshooting / Things That Tripped Us Up

Documented honestly, since these are exactly the things a judge or a teammate is likely
to hit too:

- **`winget` is blocked by Group Policy on locked-down corporate machines**, and there's
  often no `gh` CLI, Chocolatey, or GitHub Desktop available either. `vuln-fixer` was
  redesigned to stop at `git push` instead of calling `gh pr create` — GitHub prints a
  "create a pull request" URL in the push output regardless, so opening the PR is a
  one-click manual step rather than a hard CLI dependency.
- **Docker Desktop can be unreliable/unavailable** on a given machine (engine API errors,
  or not installed at all). The project doesn't need it: the "sandboxed execution" safety
  story was replaced with tool-scoping (see [§3.3](#33-why-subagents-with-scoped-tools-specifically)),
  which turned out to be a stronger design anyway.
- **GitHub's secret-scanning push protection will block a push** if your demo/fixture
  data contains anything shaped like a real credential — even an intentionally-fake one,
  if the format matches closely enough (this happened with a fake Stripe key in this very
  repo's history). Fix: reformat the fake value so it clearly doesn't match the real
  provider's key regex (e.g. insert underscores a real key would never contain), and if
  the flagged commit hasn't been pushed yet, rewrite it locally
  (`git commit --amend` / `git rebase --onto`) rather than pushing a "removed in a later
  commit" fix — the flagged string still exists in history either way until the
  *original* commit is rewritten.
- **Claude Code subagents are project-scoped.** They only load when a Claude Code session
  starts with this repository as the working directory — you cannot invoke
  `vuln-scanner` or `remediation-planner` from an unrelated project's session. If you're
  validating changes to the agent prompts without wanting to start a full interactive
  session each time, the approach used throughout this project's own development was to
  manually walk through each agent's documented instructions and produce the same
  artifacts it would, then validate those artifacts with the test suite — effectively
  treating the `.md` agent files as a spec and dry-running it by hand.
- **This environment has no LibreOffice/Node.js**, which affects only the deliverables
  build tooling, not the product itself: the pitch deck was built with `python-pptx`
  instead of the more commonly available JS `docx`/`pptx` tooling, and visual QA relied
  on the Deloitte template's own structural validator script rather than rendered
  page images.

---

## 13. Appendix

- **Repository:** https://github.com/Deloitte-US-Consulting/VulnHunter
- **Branches:** `master` (code pipeline scaffold), `vulnhunter/auto-fixes-20260803`
  (validated `/vulnhunt --fix` output), `feature/remediation-engine` (the `/remediate`
  pipeline, test suite, and this document)
- **Deliverables:** [`deliverables/VulnHunter_Hackathon_Deck.pptx`](deliverables/VulnHunter_Hackathon_Deck.pptx),
  [`deliverables/VulnHunter_Project_Report.docx`](deliverables/VulnHunter_Project_Report.docx)
