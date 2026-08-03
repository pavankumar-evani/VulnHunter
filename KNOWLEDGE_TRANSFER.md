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
environment (see [§10 Troubleshooting](#10-troubleshooting--things-that-tripped-us-up)),
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
  vuln-ingest-normalizer   Read, Glob, Write   → normalizes Tenable CSV / Armis JSON /
        │                                        threat-intel JSON into one Finding schema
        ▼
  remediation-planner      Read, Write         → REMEDIATION_PLAN.md: action type,
        │                                        risk tier, rollback plan, priority
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
It also classifies each finding's `asset.type` (windows-server, unix-server,
network-routing-switching, network-security-device, iot-ot-device) — this classification
is what routes a finding to a fixer, or correctly to "no fixer yet."

**Planning:** `remediation-planner` assigns every finding an `action_type` (patch,
config-change, service-disable, network-restriction, credential-rotation,
firmware-update, or manual-investigation), an `automation_target`, a `risk_tier`
(`auto-approvable` / `needs-change-approval` / `manual-only`), a `rollback_plan`, and a
`priority`. It defaults to the more conservative risk tier whenever uncertain — this is a
deliberate design choice, not caution to relax later.

**Fix generation:** `remediation-fixer-windows` and `remediation-fixer-unix` generate
Ansible playbooks for findings already routed to their domain. They never execute
anything — every generated playbook is a `.yml` file under `remediation/output/`, with a
comment header naming the finding it addresses, the risk tier, and a rollback instruction,
ready for human (or your org's Ansible Tower/AWX-style approved pipeline) review.

**Validated result** (against the included mock Tenable/Armis/threat-intel exports): 11
findings normalized across all 3 sources and 4 asset classes; 7 (4 Windows Server, 3 Unix
Server) got a generated playbook; 4 (1 core network switch, 3 IoT/OT/mobile devices) are
fully planned but correctly left `manual-only`, since no fixer exists yet for those asset
classes — see [`REMEDIATION_PLAN.md`](REMEDIATION_PLAN.md) for the full generated report.

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
| **Hackathon judges / reviewers** | This document + [README.md](README.md) + [deliverables/](deliverables/) for the full pitch; [§10](#10-troubleshooting--things-that-tripped-us-up) for an honest account of what broke and how it was fixed. |
| **Anyone extending this project** | [§9 Roadmap](#9-roadmap) and [§6 Step 8](#step-8-extend-it) for exactly what a new fixer subagent needs. |

---

## 6. Step-by-Step Knowledge Transfer

### Prerequisites

- **Claude Code** installed and authenticated (this project *is* a Claude Code extension —
  there's nothing to run without it).
- **git** — that's it. No `gh` CLI, no Docker, no other tooling is required to run either
  pipeline (both were deliberately designed to drop these dependencies — see
  [§10](#10-troubleshooting--things-that-tripped-us-up)).
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
│   │   ├── remediation-planner.md        /remediate: risk-tiered planning
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
│   ├── app.py                 Flask MVP dashboard - findings, queue, playbooks, run form
│   ├── data.py                 parses the same real artifacts, no pipeline logic of its own
│   ├── templates/, static/     Jinja2 templates + CSS
│   ├── requirements.txt        flask (only new runtime dependency in the whole repo)
│   └── README.md                scope, safety design, and explicit "not yet" list
├── remediation/
│   ├── sample-data/       mock Tenable/Armis/threat-intel exports
│   ├── schema/            normalized Finding schema documentation
│   └── output/            normalized findings + generated playbooks (generated, not hand-written)
├── vulnerable-demo-app/   intentionally vulnerable Flask app — /vulnhunt's scan target
├── tests/
│   ├── test_pipeline_artifacts.py   33 automated tests, stdlib only
│   ├── test_cli.py                  13 tests for the headless CLI (no real API calls)
│   ├── test_dashboard.py            14 tests for the dashboard (Flask test client, no real server)
│   └── test_results.txt             a captured passing run (60/60)
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

60 tests, 0 failures, across three suites — the original pipeline-artifact tests plus the
CLI and dashboard added in the commercialization build-out. None of it calls the real
Claude API (see each file's docstring for why that's a hard rule, not an oversight).

| Test file | What it checks | Count |
|---|---|---|
| `tests/test_pipeline_artifacts.py` | Both pipelines' real output artifacts — see breakdown below | 33 |
| `tests/test_cli.py` | Headless CLI command construction, binary discovery, one real dry-run subprocess call | 13 |
| `tests/test_dashboard.py` | Dashboard data parsing + every route (Flask test client, in-process, no server) | 14 |

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

### Tier 2 — Make It an Actual Tool (in progress)

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
3. **Live Tenable/Armis connectors** — replace static sample-file ingestion with real API
   clients. The normalizer's common schema doesn't change; only the source-detection
   logic gains real API clients alongside the file-parsing it already does. Needs real
   API credentials to build against and test properly — a business/access decision, not
   a coding one.
4. **Persistence + audit log** — a database of runs, findings, and who approved what,
   replacing the flat JSON audit files the CLI writes today and the dashboard reads.

Also planned in this tier, lower priority than the four above:
- **`remediation-fixer-network`** — vendor CLI config diffs (Cisco IOS/IOS XE, Junos) via
  Ansible's network collections, same `Read`/`Write`-only tool scoping as the existing
  fixers.
- **`remediation-fixer-iot`** — realistically a per-vendor integration effort given how
  fragmented IoT/OT management APIs are; start with the highest-volume device types in a
  real fleet (Armis-visible cameras and building-automation controllers).
- **Mobile/endpoint remediation via MDM** — findings like "outdated iOS version" route
  through an MDM platform's compliance policies (Intune/Jamf API), a different
  integration entirely from infra automation.

### Tier 3 — Enterprise / Commercial Ready (not started)

What a real buyer's security architect will actually ask for, requiring business
decisions this document can't make unilaterally:

- **Auth, RBAC, SSO** — who is allowed to approve a domain-controller change?
- **Ticketing integration** — ServiceNow/Jira sync, Slack/Teams notifications.
- **Compliance story** — data handling and residency for vulnerability data sent to an
  LLM, a SOC2-style audit trail of every AI recommendation and human approval.
- **Deployment + pricing model** — SaaS vs. self-hosted, and a real answer to "what does
  this cost per customer given Claude API usage at scale."

---

## 10. Troubleshooting / Things That Tripped Us Up

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

## 11. Appendix

- **Repository:** https://github.com/Deloitte-US-Consulting/VulnHunter
- **Branches:** `master` (code pipeline scaffold), `vulnhunter/auto-fixes-20260803`
  (validated `/vulnhunt --fix` output), `feature/remediation-engine` (the `/remediate`
  pipeline, test suite, and this document)
- **Deliverables:** [`deliverables/VulnHunter_Hackathon_Deck.pptx`](deliverables/VulnHunter_Hackathon_Deck.pptx),
  [`deliverables/VulnHunter_Project_Report.docx`](deliverables/VulnHunter_Project_Report.docx)
