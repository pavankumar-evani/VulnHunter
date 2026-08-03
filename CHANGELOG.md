# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project doesn't yet have a formal
release/versioning scheme (tracked in [KNOWLEDGE_TRANSFER.md §9 Roadmap](KNOWLEDGE_TRANSFER.md#9-roadmap)).

## [Unreleased]

### Added
- **AI Assist** (`/ai-assist`, `/api/ai-assist`, `dashboard/ai_assist.py`) — ask Claude to
  explain a finding, draft remediation steps, or write an executive summary, grounded in
  that finding's real data. Same dry-run-preview-by-default / explicit-confirm-to-spend
  pattern as `/run` and `/servicenow`: preview the exact prompt for free, confirm to
  actually call the real Claude API and spend usage/credits. A per-row "Ask AI" link on
  the Remediation Queue deep-links here with the finding preselected.
- **Reports** (`/reports`, `/api/reports/generate[.html]`, `dashboard/reports.py`) — a
  real, on-demand report generator (daily/weekly/monthly/quarterly/half-yearly/yearly
  framing) summarizing SLA, KEV/EPSS, risk-tier, and asset-coverage KPIs from the actual
  artifacts, downloadable as a standalone HTML snapshot. Honest caveat built into the
  report itself: without a persistence layer, every period currently renders the same
  real, current-moment snapshot rather than aggregating historical data.
- **Illustrative MSSP tenant-switcher demo** (`dashboard/static/js/tenant.js`) — a sidebar
  selector ("All Tenants" / "Acme Financial Corp (demo)" / "Northwind Bank (demo)") that
  partitions the same real findings by asset category on the Remediation Queue page, with
  a persistent on-page banner and FAQ entry making clear this is a UI-only illustration,
  not real per-tenant authentication or data isolation.
- **Categorization/filtering** on Code Scan (severity, CWE-derived category), Remediation
  Queue (priority, asset type, KEV-only), and Remediation Plan (risk tier, automation
  target) — all client-side over already-fetched data, with a live match count.
- **Live-refresh indicators** on Overview and the Remediation Queue — poll the same real
  API every 20s with a "Live · updated Xs ago" badge, so the dashboard reflects changes
  (e.g. a priority-rules edit) without a manual reload.
- **Visual/brand redesign** — a real SVG logo mark + favicon, a hand-drawn stroke-icon set
  replacing the earlier unicode-glyph nav icons, hover tooltips on every nav item and the
  tenant switcher explaining what each does, dark-mode-aware form inputs.
- **Support and FAQ pages** (`/support`, `/faq`) plus a full `docs/` folder (`USER_GUIDE.md`,
  `FAQ.md`, `AI_COMMANDS.md`, `INTEGRATIONS.md`, `REMEDIATION_WORKFLOWS.md`,
  `COMPLIANCE_MAPPING.md`, `SUPPORT.md`) covering usage, every AI-facing entry point,
  integrations, the remediation lifecycle, and an explicitly non-certifying
  control-mapping reference (NIST CSF / SOC2 categories - not a compliance claim).
- 37 new tests (`test_ai_assist.py`, `test_reports.py`, plus new `dashboard` API test
  classes) — full suite now 219/219 across 11 files.

### Changed
- **Dashboard: Flask + Jinja2 → FastAPI + a hand-rolled vanilla-JS single-page app.**
  Reframed from a hackathon entry toward a commercial-grade product, the ask included
  "modern JS interface" and using whichever of Java/JavaScript/Go/Python/Perl/PHP fit
  best. This machine has Python and Perl available but no Node/npm, Java, Go, or PHP
  runtime, and Docker's daemon was unreachable - so anything written in those other
  languages couldn't be compiled, run, or verified here. Rather than ship unverified
  code, the platform itself stayed on what's genuinely buildable-and-testable
  (`dashboard/app.py` is now FastAPI serving a JSON API at `/api/*`; the frontend is a
  real SPA - client-side routing, `fetch()`-based rendering, dynamic `import()` per
  page, live client-side table sorting - with zero build step). Every page was verified
  live in a browser during development, not just unit-tested. Full reasoning in
  [KNOWLEDGE_TRANSFER.md §11.1](KNOWLEDGE_TRANSFER.md#111-the-commercial-grade-polyglot-ask--what-actually-happened).
  `tests/test_dashboard.py` now uses `fastapi.testclient.TestClient` against the JSON
  API (31 tests, up from 25) rather than grepping rendered HTML, since there's no
  server-side HTML left to grep.

### Added
- **Multi-language code-scanning coverage.** `.claude/agents/vuln-scanner.md`'s
  detection guidance now explicitly covers JavaScript/TypeScript, Java, Go, PHP, and
  Perl (previously Python-only patterns plus generic/Docker/dependency checks) - real
  commercial scanners (Semgrep, Snyk, CodeQL) differentiate on breadth of *target*
  languages, not implementation language. New `vulnerable-demo-multilang/` fixtures (one
  small, realistic, intentionally-vulnerable file per language) and 31 new tests in
  `tests/test_multilang_scanner_patterns.py` verify the fixtures and the scanner's
  documented patterns stay consistent with each other via static text inspection - no
  Java/Go/PHP/Node runtime was available to actually execute the fixtures or run a live
  scan against them, so that's exactly what these tests do and don't claim.
- **Dashboard: SLA/priority engine, MITRE ATT&CK tagging, ServiceNow adapter, modern
  sidebar nav.** In response to a broader ask for a more "industry tool"-grade
  experience — built the realistic subset, deferred the rest with reasons (see
  [KNOWLEDGE_TRANSFER.md §11](KNOWLEDGE_TRANSFER.md#11-the-enterprisemssp-platform-ask--scope-reality-check)):
  - `remediation/config/priority_engine.py` + `priority_rules.yaml` — a configurable,
    form-editable (`/priority-rules`) scoring engine computing priority + SLA due
    dates/breach status per finding, independent of `remediation-planner`'s own static
    snapshot. Edits take effect immediately on `/queue` and the Overview KPIs.
  - `remediation/enrichment/attack_mapping.py` — MITRE ATT&CK technique tagging via
    keyword heuristic (explicitly documented as non-authoritative), surfaced on `/queue`.
  - `remediation/connectors/servicenow_connector.py` — creates ServiceNow Incidents per
    finding via the Table API, idempotent, with a no-credentials-needed preview mode at
    `/servicenow`. Same "built against docs, unverified against a live instance" caveat
    as the Tenable/Armis connectors.
  - New `/queue` (live, re-scored) page, distinct from `/remediate`'s static snapshot;
    sidebar navigation replacing the top bar.
  - 49 new tests at the time (`test_priority_engine.py`, `test_attack_mapping.py`,
    `test_servicenow_connector.py`, plus dashboard route tests) — full suite was
    145/145 across 8 files before the dashboard/scanner-coverage work above landed on
    top of it (now 182/182 across 9 files - see the entries above).
- **Live CISA KEV + EPSS threat-intel enrichment** (`remediation/enrichment/`,
  `threat-intel-enricher` subagent) — real, free, public, no-auth APIs, verified against
  the live endpoints during development (unlike the Tenable/Armis connectors). Moves
  `/remediate`'s prioritization beyond raw CVSS: `remediation-planner` now escalates a
  finding's priority when it's confirmed KEV-listed (actively exploited) or has EPSS ≥
  50% (high near-term exploitation probability) — never overriding `risk_tier`, which
  still gates what's safe to auto-apply. 13 new tests, including one deliberate live
  smoke test against the real APIs.
- **`application` and `certificate` asset classes** — `/remediate` now explicitly covers
  more than OS/infra findings: a Log4Shell (CVE-2021-44228) sample finding demonstrates
  application-layer library CVEs, and two new certificate/TLS sample findings (SSL
  expiry, deprecated TLSv1.0/1.1) demonstrate findings with no CVE at all. Both route to
  `manual-only` today, same honest-gap treatment as network/IoT.
- Dashboard now shows KEV-listed / high-EPSS KPI counts and an asset-class coverage
  table on the Overview page, and KEV/EPSS columns on the remediation queue.
- Sample data grew to 14 findings (was 11); full test suite now 96/96 across 5 files.

### Fixed
- A hand-counting error in `REMEDIATION_PLAN.md`'s summary (claimed 7 KEV-listed
  findings; the real, live-verified count is 6) — caught by cross-checking against the
  dashboard's programmatically-computed KPI rather than trusting the hand count.

## Tier 2 (headless CLI, dashboard, connectors)

### Added
- `cli/vulnhunter.py` — headless CLI wrapping `claude -p` so either pipeline runs from a
  script/CI/cron without an interactive session. Spend-capped, dry-run by default in
  spirit, with a JSON audit log per real invocation. 13 tests, no real API calls made in
  any test.
- `dashboard/` — MVP Flask web UI: overview KPIs, code scan findings, remediation queue
  linked to generated playbooks, playbook detail view, and a run-trigger page wrapping
  the CLI (dry-run by default). 14 tests via Flask's test client, no real server or API
  calls in any test.
- `remediation/connectors/` — live Tenable.io and Armis API clients implementing each
  vendor's publicly documented contract, writing output in the same file shapes as the
  sample data so the normalizer needs no changes. 18 tests against mocked HTTP
  responses. **Not yet verified against a real Tenable/Armis tenant** — no credentials
  were available while building this; see `remediation/connectors/README.md`.
- Full test suite now 78/78 passing across 4 files (pipeline artifacts, CLI, dashboard,
  connectors).

### Fixed
- A real UTF-8 mojibake bug: `subprocess.run(text=True)` without an explicit
  `encoding="utf-8"` decoded git's UTF-8 output with the platform default codec (cp1252
  on Windows), corrupting em-dashes and other non-ASCII characters. Fixed across every
  affected `subprocess.run` call; caught by manually verifying the dashboard's rendered
  pages, not by a pre-written test.
- An actual infinite loop in `TenableConnector.poll_export_status`'s timeout logic
  (an elapsed-time accumulator that a zero step size could never advance past). Fixed by
  switching to a wall-clock deadline. Caught by the test suite itself hanging.

## Tier 1 repo hygiene

### Added
- `LICENSE` (proprietary/all-rights-reserved), `SECURITY.md`, GitHub Actions CI running
  the test suite on every push/PR, `CODEOWNERS`, issue/PR templates, this changelog.

## 2026-08-03

### Added
- `TEST_CASES.md` — formal test case log (33 cases, TC-ID per test method, steps,
  expected vs. actual results, plus a "notable findings" section).
- `KNOWLEDGE_TRANSFER.md` — full KT doc: executive summary, problem statement, design
  rationale, product details, step-by-step operating instructions, repo map, test
  evidence, roadmap, and a troubleshooting log.
- `deliverables/` — Deloitte-branded hackathon pitch deck (`.pptx`) and full project/test
  report (`.docx`).
- `tests/test_pipeline_artifacts.py` — 33 automated tests (stdlib-only `unittest`)
  validating both pipelines' real output artifacts via git history and generated files.
- **Remediation engine (`/remediate`)**: ingests Tenable CSV, Armis JSON, and manual
  threat-intel JSON; normalizes into one Finding schema; plans remediation with risk
  tiers (`auto-approvable` / `needs-change-approval` / `manual-only`); generates
  reviewable Ansible playbooks for `windows-server` and `unix-server` findings via
  `remediation-fixer-windows`/`remediation-fixer-unix`. Network/firewall/IoT-OT asset
  classes are ingested and planned but not yet auto-remediated (documented gap, not a
  silent one).
- Validated `/remediate` end-to-end against realistic mock data: 11 findings normalized,
  7 Ansible playbooks generated, `REMEDIATION_PLAN.md` produced.

### Changed
- Corrected README's stated `/vulnhunt` demo numbers (9 findings / 6 auto-fixed) to match
  the actual validated scan, after the original estimate (~6 findings / 3-4 auto-fixed)
  was found not to match reality.
- `vuln-fixer` reworked to stop at `git push` instead of calling `gh pr create` — no
  `gh` CLI dependency; the PR-creation URL GitHub prints on push is the actual mechanism
  to open the PR.
- Safety story reworked from "run the scan in a Docker sandbox" to tool-scoping (no
  Edit/Write access for scanners, no Bash/network access for infra fixers) after Docker
  proved unreliable in the target environment — arguably a stronger safety model anyway.

### Fixed
- Reformatted a fake demo Stripe API key that was realistic enough to trip GitHub's
  secret-scanning push protection; rewrote the (not-yet-pushed) local git history to
  remove the flagged string from every commit.
- Two test assertions that produced false positives by matching comment prose instead of
  actual code (Dockerfile `USER` directive check, secret-removal check).

## 2026-08-03 (initial)

### Added
- Initial `/vulnhunt` pipeline scaffold: `vuln-scanner`, `vuln-triage-reporter`,
  `vuln-fixer` subagents, the `/vulnhunt` slash command, and the intentionally
  vulnerable `vulnerable-demo-app/` Flask app (6 planted vulnerabilities plus 3
  Dockerfile-level issues).
- Validated `/vulnhunt` end-to-end: 9 findings detected, 6 auto-fixed and pushed to
  `vulnhunter/auto-fixes-20260803`, `SECURITY_REPORT.md` generated.
