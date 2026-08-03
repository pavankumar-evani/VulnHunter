# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project doesn't yet have a formal
release/versioning scheme (tracked in [KNOWLEDGE_TRANSFER.md §9 Roadmap](KNOWLEDGE_TRANSFER.md#9-roadmap)).

## [Unreleased]

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
