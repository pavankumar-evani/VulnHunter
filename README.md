# VulnHunter 🔍🛡️

[![CI](https://github.com/pavankumar-evani/VulnHunter/actions/workflows/ci.yml/badge.svg)](https://github.com/pavankumar-evani/VulnHunter/actions/workflows/ci.yml)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-lightgrey.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-597%2F597%20passing-brightgreen.svg)](TEST_CASES.md)

**An autonomous Claude Code security agent that finds vulnerabilities — in source code
and across enterprise infrastructure — and fixes the safe ones automatically.**

Built for the Deloitte Claude Code Hackathon. Two pipelines, one philosophy:

- **`/vulnhunt`** — scan a codebase, report findings, auto-fix the safe ones. See
  [below](#what-vulnhunt-does).
- **`/remediate`** — ingest vulnerability/asset-risk data from Tenable, Armis, and manual
  threat intel, normalize it, plan remediation by risk tier, and generate reviewable
  fix automation for supported asset classes. See [Remediation Engine](#remediation-engine-remediate).

🚀 **Just want it running?** [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) is the
5-minute clone-to-running-dashboard path.

📖 **New here?** [KNOWLEDGE_TRANSFER.md](KNOWLEDGE_TRANSFER.md) has the full picture: problem
statement, the idea and why it's built this way, product/solution details for both
pipelines, step-by-step instructions to actually run everything, test evidence, and a
troubleshooting log of what broke and how it was fixed. For the detailed test case log
(597 test cases, steps, expected vs. actual results), see [TEST_CASES.md](TEST_CASES.md).
For task-oriented usage docs, FAQs, AI commands, integrations, and remediation
workflows, see the [docs/](docs/README.md) folder.

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
(secret baked into an image layer, root user, unpinned base image) — 9 total, plus 9
more in two more fixture files, `ai_assistant.py` (AI/ML: hardcoded LLM API key,
insecure model deserialization, prompt injection, excessive agency) and `admin_api.py`
(secrets/API-authorization: hardcoded AWS keys, hardcoded JWT secret, unauthenticated
admin route, wildcard CORS, mass assignment) — 18 total. This is what we run VulnHunter
against on stage.

```bash
# 1. Point VulnHunter at the vulnerable demo app
claude
/vulnhunt vulnerable-demo-app

# 2. Review SECURITY_REPORT.md, then let it auto-fix the safe findings
/vulnhunt vulnerable-demo-app --fix
```

Expected result: 18 findings detected in seconds (9 Critical, 6 High, 2 Medium, 1 Low),
11 auto-fixed on a pushed branch, 7 flagged for human review with a clear reason each
(e.g. "removing eval() here requires redesigning the /calc endpoint — needs a human
decision"; "requires plugging into the app's actual authentication/authorization
system, which cannot be inferred or invented safely by an automated fixer" for the
unauthenticated admin route). Opening the actual PR from that branch is one click away
in GitHub's web UI or VS Code's Source Control panel.

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

Vulnerability management in a real enterprise isn't one tool, and it's not just code
either. It's Tenable scan results, Armis device-risk alerts (heavy on IoT/OT and
unmanaged devices), and analyst-curated threat intel, landing on assets as different as
domain controllers, Linux database servers, core switches, an internal Java application,
and an expiring TLS certificate. `/remediate` covers **OS-level, infrastructure-level,
application-level, and certificate-level** findings — not just source code — and turns
that firehose into a prioritized, threat-intel-aware, safety-gated remediation plan.

```
/remediate [--generate]
        │
        ▼
  vuln-ingest-normalizer     Read, Glob, Write   → normalizes Tenable CSV / Armis JSON /
        │                                          threat-intel JSON into one Finding schema
        ▼
  threat-intel-enricher      Read, Write, Bash   → adds real CISA KEV + EPSS data to
        │                                          every finding with a CVE (live public APIs)
        ▼
  remediation-planner        Read, Write         → REMEDIATION_PLAN.md: action type, risk
        │                                          tier, priority (KEV/EPSS-aware), rollback
        ▼
  ┌─────────────────────┴─────────────────────┐
  ▼                                            ▼
remediation-fixer-windows          remediation-fixer-unix
Read, Write → Ansible playbooks    Read, Write → Ansible playbooks
(windows-server findings only)     (unix-server findings only)
```

### Threat-intel-aware prioritization, not just CVSS

CVSS measures theoretical severity, not real-world risk. `threat-intel-enricher` calls two
real, free, public APIs — no credentials, verified against the live endpoints during
development — and `remediation-planner` uses them to override pure asset-criticality
heuristics:

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — is this
  CVE *confirmed* being actively exploited in the wild right now? A KEV-listed finding is
  escalated to top priority regardless of asset type.
- **[EPSS](https://www.first.org/epss/)** (FIRST.org) — a 0–100% probability of
  exploitation in the next 30 days. Catches high-risk CVEs KEV hasn't confirmed yet — in
  our own sample data, an OpenSSL DoS (not KEV-listed) scores 70.6% EPSS, and an OpenSSH
  regression (also not KEV-listed) scores 99.5%.

KEV/EPSS affect **priority** (how urgently to act) — never `risk_tier` (how safe a fix is
to auto-apply). An actively-exploited CVE on a domain controller is still
`needs-change-approval`, just more urgent to get approved.

### Supported asset classes today

| Asset class | Ingested & planned? | Automated fix generation? |
|---|---|---|
| Windows Server (OS-level) | Yes | Yes — `remediation-fixer-windows` |
| Unix/Linux Server (OS-level) | Yes | Yes — `remediation-fixer-unix` |
| Network routing/switching (infra) | Yes | Not yet — plan flags it, no fixer exists |
| Network security devices/firewalls (infra) | Yes | Not yet — plan flags it, no fixer exists |
| IoT/OT devices, mobile/endpoints | Yes | Not yet — plan flags it, no fixer exists |
| Application (library/framework CVEs, e.g. Log4Shell) | Yes | Not yet — needs a per-language fixer |
| Certificate/TLS (expiry, deprecated protocols) | Yes | Not yet — needs CA/ACME integration |

Every asset class gets ingested, normalized, enriched with KEV/EPSS, and included in the
risk-tiered plan — the gap for network/firewall/IoT/application/certificate findings is
fix-generation automation, not visibility. See
[KNOWLEDGE_TRANSFER.md's roadmap](KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade)
for what each remaining fixer needs.

### Live dashboard: SLA tracking, configurable priorities, ATT&CK, ServiceNow

`python dashboard/app.py` runs a FastAPI JSON API behind a vanilla-JS single-page
frontend (client-side routing, no Node/npm build step - see
[dashboard/README.md](dashboard/README.md#why-fastapi--vanilla-js-not-nodereact-or-staying-on-flaskjinja2))
with a sidebar-navigation dashboard:
- **Live Remediation Queue** (`/queue`) — every finding re-scored on each page load from
  whatever `remediation/config/priority_rules.yaml` currently says, with SLA due dates/
  breach status and MITRE ATT&CK technique tags (a keyword heuristic, not authoritative
  attribution — see the module docstring).
- **Priority Rules** (`/priority-rules`) — a form-based YAML editor; save it and the
  queue/SLA KPIs update immediately, no pipeline re-run needed.
- **ServiceNow** (`/servicenow`) — previews the exact Incident payload for every finding
  with zero credentials required; only sends anything if you provide real credentials
  and explicitly confirm.
- **Overview** — SLA breached/at-risk/on-track counts alongside the existing KEV/EPSS
  and asset-coverage KPIs, live-refreshed every 20s.
- **AI Assist** (`/ai-assist`) — ask Claude to explain a finding, draft remediation
  steps, or write an executive summary; same dry-run-preview-first safety pattern.
- **Reports** (`/reports`) — generate a real, downloadable KPI/SLA/coverage snapshot.
- **Exceptions** (`/exceptions`) — a documented, time-boxed risk-acceptance workflow:
  request, approve, auto-expire, or revoke a waiver for a finding that can't be
  remediated on schedule.
- **Asset Inventory** (`/assets`) — every asset with findings against it, aggregated,
  with an editable owner/team.
- **Filtering** on Code Scan/Queue/Remediation Plan (severity, category, asset type,
  risk tier, KEV-only), and an illustrative (demo, not real) MSSP tenant switcher.

See [dashboard/README.md](dashboard/README.md) for what this MVP still doesn't have
(auth, persistence, multi-tenancy) before considering it beyond a local/trusted-network
tool.

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

Expected result (against the included sample Tenable/Armis/threat-intel exports): 15
findings normalized (10 Tenable, 3 Armis, 2 threat intel) across 7 asset classes,
enriched with real CISA KEV/EPSS data (7 KEV-listed, 8 with EPSS ≥ 50%); 7 are eligible
for automated fix generation (4 Windows Server, 3 Unix Server) and land in
`remediation/output/` as reviewable playbooks; the remaining 8 (a core Cisco switch, a
perimeter firewall, an IoT camera and OT controller, a mobile endpoint, a
Log4Shell-vulnerable application, and 2 certificate/TLS findings) are fully planned in
`REMEDIATION_PLAN.md` with a clear reason no fixer exists yet for that asset class.

### Optional: bulk real-CVE sample data (8,081 more findings)

The 15 findings above are the original, individually hand-curated set. Separately,
`remediation/sample-data/generate_bulk_findings.py` sources real, distinct CVEs per
category from NVD's public CVE API - real CVE IDs, CVSS scores, and vendor
descriptions, not fabricated: ~1,100 each for OS Windows, OS Linux, Network, Network
Security, and Cloud Infrastructure; ~1,100 for a realistic "OS Applications" category
(browsers, PDF readers, dev tools, media/utility software, drivers - Chrome, Firefox,
Adobe Acrobat Reader, VS Code, Notepad++, VLC, 7-Zip, and more); ~300 each for
Certificate, SCA, and DAST; ~1,100 for OT/IoT via the Armis connector; and three more
recently-added categories, each hand-authored from real, independently-verified rule
sets rather than CVE-fetched, same reasoning DAST already documents: ~220 Infrastructure-
as-Code misconfigurations (real Checkov rule IDs against fictional Terraform/
CloudFormation resources), ~219 GitHub/GitLab repository findings (a real-CVE
Dependabot-style half plus a CWE-798 secret-scanning half), and ~218 runtime/container
security findings (real Falco default rule names). `bulk_normalize.py` /
`remediation/enrichment/kev_epss.py` / `remediation/enrichment/poc_enrichment.py` /
`bulk_plan.py` merge, classify, and enrich them the same way `/remediate` does, at a
scale (~8,100 findings) an LLM-subagent pass can't practically handle. Running
`/remediate` fresh (with the default 3 sample files) still produces the original 15 -
the shipped `remediation/output/normalized-findings.json` and `REMEDIATION_PLAN.md` in
this repo already include the bulk-expanded 8,096 total. See that script's module
docstring for exactly what it does and doesn't claim.

## Project structure

```
.
├── .claude/
│   ├── agents/
│   │   ├── vuln-scanner.md
│   │   ├── vuln-triage-reporter.md
│   │   ├── vuln-fixer.md
│   │   ├── vuln-ingest-normalizer.md
│   │   ├── threat-intel-enricher.md
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
│   ├── app.py                  # FastAPI JSON API + SPA shell routes (see below)
│   ├── data.py                 # parses SECURITY_REPORT.md / REMEDIATION_PLAN.md / etc.
│   ├── static/                 # vanilla-JS SPA (client router, page modules) + CSS
│   └── README.md
├── remediation/
│   ├── sample-data/            # mock Tenable/Armis/threat-intel exports
│   ├── schema/                 # normalized Finding schema doc
│   ├── connectors/             # live Tenable/Armis/ServiceNow API clients (unit-tested,
│   │                           #   not yet verified against a real tenant - see its README)
│   │                           #   + generic_connector.py, the vendor-agnostic
│   │                           #   "bring your own XDR/EDR/SIEM" webhook adapter
│   ├── enrichment/              # live CISA KEV + EPSS client (verified against the
│   │                           #   real public endpoints - see its module docstring)
│   │                           #   + scan_type_mapping.py (SAST/DAST/SCA/Infra-VM/Cert-Mgmt)
│   ├── exceptions/             # vulnerability exception/waiver workflow (request,
│   │                           #   approve, auto-expire, revoke)
│   ├── inventory/               # asset inventory aggregation + editable ownership
│   └── output/                 # normalized findings + generated playbooks land here
├── vulnerable-demo-app/        # intentionally vulnerable Flask app for the /vulnhunt demo
│   ├── app.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── init_db.py
├── vulnerable-demo-multilang/   # intentionally vulnerable Java/JS/Go/PHP/Perl fixtures
│                                #   proving vuln-scanner.md's per-language coverage
├── docs/                        # USER_GUIDE, FAQ, AI_COMMANDS, INTEGRATIONS,
│                                #   REMEDIATION_WORKFLOWS, COMPLIANCE_MAPPING (non-
│                                #   certifying), SUPPORT - see docs/README.md
├── tests/                       # 597 tests (pipeline artifacts, CLI, dashboard, connectors,
│                                #   enrichment, priority engine, ATT&CK, ServiceNow,
│                                #   multi-language scanner patterns, AI-assist, reports,
│                                #   exceptions, asset inventory, generic ingestion,
│                                #   scan-type taxonomy, local auth, compensating controls,
│                                #   Jira/Splunk/CrowdStrike connectors, CMDB CSV import),
│                                #   see TEST_CASES.md
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
