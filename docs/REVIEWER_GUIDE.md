# Reviewer guide

For anyone assessing Quanta from outside the team: security engineers, architects, procurement, and AI models asked to review the repository. It tells you where things are, how to run them, which command proves which claim, and, just as important, what has **not** been verified. It is written to be checked, not believed.

## 1. What Quanta is, in four sentences

A self-hosted security operations platform. It reads findings and context from the tools an organisation already has (scanners, cloud posture, SIEM and XDR, directories, CI, API gateways, AI usage), keeps them in one store, ranks them with explainable, tunable rules, assigns owners, and drives each item to a fix that a person approves (a pull request, or a reviewable playbook), then checks the next scan to see whether it is really gone. It is not a scanner, SIEM, EDR agent, firewall, WAF or compliance certifier. Nothing it generates is executed by Quanta.

## 2. Run it in five minutes

```bash
git clone https://github.com/pavankumar-evani/VulnHunter.git && cd VulnHunter
pip install -r dashboard/requirements.txt
python dashboard/app.py                                  # https://127.0.0.1:5050 (self-signed certificate on first run)
python cli/quanta_admin.py seed-demo                     # simulated connectors: see section 5
python -m unittest discover -s tests -p "test_*.py"      # the whole suite, ten to twenty minutes
```

Python 3.12 (what CI runs). No Node.js is needed to run the application; Node is used only by a few tests of browser modules and is skipped if absent. Demo accounts `admin@quanta.local` and `analyst@quanta.local` (`ChangeMe123!`) are published on purpose; production mode refuses to start with them.

## 3. Map of the repository

| Where | What |
|---|---|
| `dashboard/app.py`, `dashboard/appsec_api.py`, `dashboard/simulation_api.py` | the FastAPI backend (one process serves the API and the single-page app) |
| `dashboard/static/js/` | the vanilla-JavaScript front end: no bundler, no framework, no `node_modules` |
| `dashboard/auth/` | local accounts (PBKDF2), HMAC-signed session cookie, optional OIDC, role and team scoping |
| `remediation/` | the engine: `ingest/`, `enrichment/`, `connectors/`, `connections/`, `gitops/`, `appsec/`, `soc/`, `soar/`, `hunting/`, `grc/`, `posture/`, `graphs/`, `simulation/`, `licensing/`, `utils/`, `config/` (every editable policy as YAML) |
| `.claude/agents/`, `.claude/commands/` | the twelve subagents and two slash commands; each agent's `tools:` list is a deliberate boundary (the scanner cannot write, fixers cannot run commands) |
| `cli/` | `quanta.py` (pipelines), `quanta_admin.py` (operations), `quanta_license.py`, `quanta_release.py` (release preflight and rollback plan) |
| `deploy/`, `Dockerfile`, `docker-compose*.yml`, `.github/workflows/` | containers, the Helm chart and per-environment overlays, CI, the release and rollback workflows |
| `tests/` | one `unittest` file per module; hand-rolled fakes, never a real vendor, never a real spend |
| `docs/`, `docs/enterprise-suite/` | operational guides and sixteen technical references |
| `CLAUDE.md` | the most current description of how everything fits together |

## 4. Claims and where to check them

| Claim | How to verify |
|---|---|
| Nothing Quanta generates is executed by it | the fixer agents' `tools:` are `Read, Write` only (`.claude/agents/remediation-fixer-*.md`); the pull request code path is the only repository write (`remediation/gitops/proposals.py` `open_pr`: dry run unless `confirm`, new branch only, never merged) |
| Dangerous actions are confirm-gated and dry-run by default | `python cli/quanta.py --dry-run scan vulnerable-demo-app --fix` prints and spends nothing; routes that spend or write return `preview_only` without `confirm` (see the tests named in `CLAUDE.md` "Testing") |
| Unknown is never counted as a pass | `python -m unittest tests.test_posture_engine` and each `tests/test_posture_*.py`: an empty estate gives only `unknown`/`not applicable`, and a framework is not scored below 30% observable weight |
| Scores are explainable | every finding's score shows its factors (`remediation/appsec/scoring.py`, weights in `remediation/config/appsec_scoring.yaml`); posture scores come from checks you can open on `/posture` |
| Access control | `dashboard/auth/rbac.py`; route-level checks are in `dashboard/app.py` (`require_admin`, `require_login`, team scoping `_scope_to_team`); `tests/test_dashboard.py`, `tests/test_auth.py`, `tests/test_self_scan_fixes.py` |
| Hardening | `tests/test_hardening.py` (XML entity guard, failed-login throttle, Secure cookie, CSP, self-hosted font), `tests/test_ssrf_hardening.py` (redirect and mapped-IPv6 SSRF), `tests/test_file_lock.py` and `tests/test_lock_wait_and_schema_cache.py` (concurrent writers) |
| No secret in output | tests assert secret values never appear in posture results, graph data or connection listings |
| Demo data travels the real path | section 5 and `tests/test_simulation*.py` |
| Same build in every environment | `docs/ENVIRONMENTS.md`, `docs/RELEASE_PROCESS.md`, `tests/test_environments_deploy.py`, `tests/test_migration_policy.py` |
| Licence verification | `remediation/licensing/license.py` (Ed25519 over the exact signed bytes, no algorithm field to confuse), `tests/test_licensing.py` |

## 5. Demonstration data versus live data

A fresh clone ships a small committed sample so the pages are not empty. A production deployment does not use it: `python cli/quanta_admin.py clear-sample-data --yes` sets it aside and `quanta_admin check` fails a production deployment that still holds it.

For demonstrations, Quanta has **simulated connectors** (`remediation/simulation/`). A fictional, deterministic estate is rendered into each vendor's real response format and replayed through the connector's own code: request building, paging, parsing, classification, merge and enrichment all run for real; only the network is replaced. Every record is stamped `source_mode: simulation`, a simulated record never overwrites a live one, the Connections page and finding detail show a "Simulated" tag, and simulation is refused when `QUANTA_ENV=prod` unless an operator sets `QUANTA_ALLOW_SIMULATION=true`. Connecting a real account means editing the connection from `simulation` to `live` with real credentials; nothing downstream changes. Remove the simulated data with `python cli/quanta_admin.py seed-demo --remove`.

## 6. What has NOT been verified (read this section first if you are sceptical)

- **No connector has been run against a live vendor account.** Each is built against the vendor's public documentation and tested against recorded or hand-written responses. The simulation proves the parsing and workflow, not that a vendor's real service behaves the same today.
- **The Git host integration (GitHub, GitLab), OSV and the signed webhooks have not been run against live services.** The hourly pull-request follow-up and the webhook receivers are unit-tested with fakes.
- **The release and rollback workflows and the Helm overlays are checked statically only.** They have not been run against a cluster; `helm` and `docker` were not available where they were written. The "prod" approval gate is a GitHub Environment setting that must be configured in the repository (it cannot live in a file).
- **PostgreSQL** is supported through SQLAlchemy and checked by the chart's tests and an end-to-end script that runs real processes, but the day-to-day suite runs on SQLite. A SQLAlchemy major bump (2.1) is held back for that reason.
- **The Claude Code subagents** (the AI fixers) need the Claude Code CLI and are validated by deterministic layers (playbook lint, diff validation), not by the model's own say-so.
- **No advisory database ships.** Vulnerabilities in an SBOM come from scanner findings or the OSV check, so "no vulnerable components" can mean "none known to the connected sources".
- **Scale:** findings are stored as one file (tens of thousands, not millions).
- **Session revocation** is not server-side: a stateless cookie is valid for its 12 hours after logout or role change. Documented, not yet fixed.
- **Compliance:** Quanta supplies evidence and workflow. It does not certify anything; the framework mappings are its reading of each standard. Posture scores and stages are Quanta's own summary (no standard publishes a score) and the thresholds are editable.
- **Performance** has been measured only on a developer machine (an idle approval write: 18 ms).

## 7. How the code was checked

The test suite (2,600+ tests at the last full run) passes on CI (GitHub Actions, Linux) and on the developer's Windows machine. Beyond unit tests: a static-analysis pass (`bandit`) and a dependency audit (`pip-audit`, no known vulnerable dependency); Quanta's own `vuln-scanner` agent was run against Quanta (25 findings, each read and confirmed before fixing; the full list is in the changelog); a concurrency defect that only appeared on Linux CI was reproduced under artificial CPU pressure, fixed, and the reproduction is a regression test. Browser behaviour was driven in headless Chrome against a seeded server (interaction scripts, console errors, desktop and phone width). These are checks by the people who wrote the code, helped by automated tools; they are not an independent audit. A good use of your review is to find what they missed.

## 8. Where to push hardest

1. The access-control surface in `dashboard/app.py`: which routes need `require_admin`, which rely on team scoping, and anything that trusts an identity from a request body instead of the session.
2. Every place Quanta fetches a URL it was given (connectors, the API-spec fetch): `remediation/connectors/url_safety.py` resolves DNS once and blocks cloud-metadata, loopback and link-local ranges, but does not pin the resolved address.
3. The pull request path (`remediation/gitops/`): path canonicalisation, denied-path matching, branch protection.
4. The simulation boundary: can simulated data ever be presented as live, or survive into production?
5. The honesty of the posture checks: a check that claims `pass` without evidence is a bug.
6. Anything in section 6 that you believe is worse than described.
