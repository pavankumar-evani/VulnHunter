# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project doesn't yet have a formal
release/versioning scheme (tracked in [KNOWLEDGE_TRANSFER.md §9 Roadmap](KNOWLEDGE_TRANSFER.md#9-roadmap)).

## [Unreleased]

### Added
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
