# VulnHunter 🔍🛡️

[![CI](https://github.com/Deloitte-US-Consulting/VulnHunter/actions/workflows/ci.yml/badge.svg)](https://github.com/Deloitte-US-Consulting/VulnHunter/actions/workflows/ci.yml)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-lightgrey.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-33%2F33%20passing-brightgreen.svg)](TEST_CASES.md)

**An autonomous Claude Code security agent that finds vulnerabilities — in source code
and across enterprise infrastructure — and fixes the safe ones automatically.**

Built for the Deloitte Claude Code Hackathon. Two pipelines, one philosophy:

- **`/vulnhunt`** — scan a codebase, report findings, auto-fix the safe ones. See
  [below](#what-vulnhunt-does).
- **`/remediate`** — ingest vulnerability/asset-risk data from Tenable, Armis, and manual
  threat intel, normalize it, plan remediation by risk tier, and generate reviewable
  fix automation for supported asset classes. See [Remediation Engine](#remediation-engine-remediate).

📖 **New here?** [KNOWLEDGE_TRANSFER.md](KNOWLEDGE_TRANSFER.md) has the full picture: problem
statement, the idea and why it's built this way, product/solution details for both
pipelines, step-by-step instructions to actually run everything, test evidence, and a
troubleshooting log of what broke and how it was fixed. For the detailed test case log
(33 test cases, steps, expected vs. actual results), see [TEST_CASES.md](TEST_CASES.md).

## The problem

Static analysis tools produce reports nobody reads. Security debt piles up because
finding a vulnerability and *actually fixing it* are two different jobs, and most tools
only do the first one. This is true of source code, and it's arguably a bigger problem
for infrastructure: a vulnerability management program can generate thousands of findings
across Tenable, Armis, and analyst threat intel, and turning each one into an actual fix
across Windows, Unix, network, and IoT/OT assets is almost entirely manual today.

## What `/vulnhunt` does

One command — `/vulnhunt <path>` — runs a 3-stage agent pipeline:

1. **Scan** — a read-only subagent (`vuln-scanner`) statically analyzes the target repo
   for injection flaws, hardcoded secrets, insecure config, risky dependencies, and
   unsafe Docker practices. Outputs structured findings with severity + CWE.
2. **Triage & Report** — a second subagent (`vuln-triage-reporter`) turns raw findings
   into a clean, ranked `SECURITY_REPORT.md`, explaining real-world impact in plain
   English, not just CWE jargon.
3. **Fix** — a third subagent (`vuln-fixer`) applies safe, mechanical fixes (parameterize
   a SQL query, move a hardcoded secret to an environment variable, drop container
   privileges) to a new git branch and pushes it, ready for a pull request. Anything that
   needs a real design decision is explicitly left for a human, with a reason why.

Each stage is a separate Claude Code subagent with its own scoped tool access —
`vuln-scanner` is read-only by design, so the tool that finds vulnerabilities literally
cannot introduce new ones.

## Architecture

```
/vulnhunt <path> [--fix]        (slash command, orchestrates the pipeline)
        │
        ▼
  vuln-scanner            Read, Grep, Glob, Bash        → JSON findings
        │
        ▼
  vuln-triage-reporter    Write                          → SECURITY_REPORT.md
        │
        ▼
  vuln-fixer              Read, Edit, Write, Bash        → branch + push (only if --fix)
```

## Demo

A deliberately vulnerable Flask app lives in `vulnerable-demo-app/` with 6 planted,
labeled vulnerabilities in `app.py` (SQL injection, command injection, `eval()` misuse,
hardcoded API key, plaintext passwords, debug mode) plus 3 more in its `Dockerfile`
(secret baked into an image layer, root user, unpinned base image) — 9 total. This is
what we run VulnHunter against on stage.

```bash
# 1. Point VulnHunter at the vulnerable demo app
claude
/vulnhunt vulnerable-demo-app

# 2. Review SECURITY_REPORT.md, then let it auto-fix the safe findings
/vulnhunt vulnerable-demo-app --fix
```

Expected result: 9 findings detected in seconds (4 Critical, 2 High, 2 Medium, 1 Low), 6
auto-fixed on a pushed branch, 3 flagged for human review with a clear reason each (e.g.
"removing eval() here requires redesigning the /calc endpoint — needs a human decision").
Opening the actual PR from that branch is one click away in GitHub's web UI or VS Code's
Source Control panel.

## Why this approach

- **Separation of concerns mirrors real security teams**: a scanner shouldn't have write
  access, a fixer should never guess on ambiguous cases. This is also VulnHunter's safety
  mechanism instead of container sandboxing — `vuln-scanner` is architecturally incapable
  of modifying files (no Edit/Write tool access at all), and `vuln-fixer` only ever acts
  on findings pre-approved as `auto_fixable` by the scan stage, on a fresh branch, never
  on `main` directly.
- **It's demoable end-to-end in under 2 minutes.**
- **It scales**: point it at any repo, any language, no retraining — it's prompting +
  tool scoping, not a bespoke rules engine.
- **Zero extra tooling**: only `git`, which is already everywhere — no `gh` CLI or Docker
  runtime required to run the pipeline itself.

## Remediation Engine (`/remediate`)

Vulnerability management in a real enterprise isn't one tool — it's Tenable scan results,
Armis device-risk alerts (heavy on IoT/OT and unmanaged devices), and analyst-curated
threat intel, landing on assets as different as domain controllers, Linux database
servers, core switches, firewalls, and IP cameras. `/remediate` turns that firehose into a
prioritized, safety-gated remediation plan — and, for the asset classes it supports today,
into ready-to-review fix automation.

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
Read, Write → Ansible playbooks    Read, Write → Ansible playbooks
(windows-server findings only)     (unix-server findings only)
```

### Supported asset classes today

| Asset class | Ingested & planned? | Automated fix generation? |
|---|---|---|
| Windows Server | Yes | Yes — `remediation-fixer-windows` |
| Unix/Linux Server | Yes | Yes — `remediation-fixer-unix` |
| Network routing/switching | Yes | Not yet — plan flags it, no fixer exists |
| Network security devices (firewalls) | Yes | Not yet — plan flags it, no fixer exists |
| IoT/OT devices, mobile/endpoints | Yes | Not yet — plan flags it, no fixer exists |

Every asset class gets ingested, normalized, and included in the risk-tiered plan — the
gap for network/firewall/IoT devices is fix-generation automation, not visibility. Adding
`remediation-fixer-network` (vendor CLI config diffs via Ansible's network collections)
and a per-vendor IoT/OT fixer is the natural next step; the schema and planner already
account for them (see `remediation/schema/normalized-finding-schema.md`).

### The safety model — no auto-execution, ever

This is the most important design decision in the whole engine: **nothing generated by
`/remediate` ever runs against real infrastructure automatically.**

- `remediation-fixer-windows` and `remediation-fixer-unix` only have `Read`/`Write` tool
  access — no `Bash`, no network reach, no credentials. They are architecturally incapable
  of connecting to a real host, the same way `vuln-scanner` is architecturally incapable
  of writing files.
- Every generated Ansible playbook is an artifact for a human — or your org's existing
  approved automation platform (Ansible Tower/AWX, Intune, SCCM) with its own RBAC — to
  review and run.
- `remediation-planner` assigns a `risk_tier` to every finding (`auto-approvable` /
  `needs-change-approval` / `manual-only`) based on blast radius and asset criticality —
  domain controllers, auth servers, and anything with a plausible outage risk are flagged
  for change-management sign-off, never treated as auto-approvable by default.
- Every playbook includes a pre-change state check and an explicit rollback instruction
  copied from the plan, so a reviewer isn't starting from zero.

### Demo

```bash
claude
/remediate                 # ingests remediation/sample-data/* by default
# review REMEDIATION_PLAN.md
/remediate --generate       # generates the Ansible playbooks for auto-remediable findings
```

Expected result (against the included sample Tenable/Armis/threat-intel exports): 11
findings normalized (6 Tenable, 3 Armis, 2 threat intel) across 4 asset classes; 7 are
eligible for automated fix generation (4 Windows Server, 3 Unix Server) and land in
`remediation/output/` as reviewable playbooks; the remaining 4 (a core Cisco switch, two
IoT/OT devices, one mobile endpoint) are fully planned in `REMEDIATION_PLAN.md` with a
clear reason no fixer exists yet.

## Project structure

```
.
├── .claude/
│   ├── agents/
│   │   ├── vuln-scanner.md
│   │   ├── vuln-triage-reporter.md
│   │   ├── vuln-fixer.md
│   │   ├── vuln-ingest-normalizer.md
│   │   ├── remediation-planner.md
│   │   ├── remediation-fixer-windows.md
│   │   └── remediation-fixer-unix.md
│   └── commands/
│       ├── vulnhunt.md
│       └── remediate.md
├── cli/
│   ├── vulnhunter.py            # headless CLI: run either pipeline without an
│   │                            #   interactive session (see cli/README.md)
│   └── README.md
├── dashboard/
│   ├── app.py                  # Flask MVP dashboard reading real artifacts (see below)
│   ├── data.py                 # parses SECURITY_REPORT.md / REMEDIATION_PLAN.md / etc.
│   └── README.md
├── remediation/
│   ├── sample-data/            # mock Tenable/Armis/threat-intel exports
│   ├── schema/                 # normalized Finding schema doc
│   └── output/                 # normalized findings + generated playbooks land here
├── vulnerable-demo-app/        # intentionally vulnerable Flask app for the /vulnhunt demo
│   ├── app.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── init_db.py
├── tests/                       # 46 tests (33 pipeline artifacts + 13 CLI), see TEST_CASES.md
├── .github/                     # CI workflow, issue/PR templates, CODEOWNERS
├── LICENSE, SECURITY.md, CHANGELOG.md
├── REMEDIATION_PLAN.md
└── README.md
```

## Disclaimer

`vulnerable-demo-app/` is intentionally insecure and exists **only** to demonstrate
VulnHunter. Do not deploy it anywhere reachable.

`remediation/sample-data/` contains fabricated Tenable/Armis/threat-intel exports for
demo purposes — hostnames, IPs, and device names are all fictional. The CVE IDs
referenced are real, public CVEs used only to make the remediation guidance realistic;
no exploit code or technique detail is included anywhere in this repo. Generated
playbooks in `remediation/output/` are unreviewed drafts and must never be run against
real infrastructure without human review and, where flagged, formal change approval.
