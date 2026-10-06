# Enterprise Documentation Suite — Manifest

Sixteen HTML documents, version-controlled here so they survive alongside the code they
document. Each is also published as a Claude Artifact (a hosted, shareable page) at the
URL below. **The files in this directory are the source of truth** — the published
Artifact is a mirror, kept in sync by republishing from these exact files (see "Keeping
this in sync" below).

| File | Published URL | Audience |
|---|---|---|
| `hub.html` | https://claude.ai/artifact/Aw2XoPpCrAbGekPUjzdrCA | Landing page — links to all 15 below |
| `executive-brief.html` | https://claude.ai/artifact/GfPjPuQLEEg3TGFs7Zrgb4 | Enterprise evaluators |
| `whitepaper.html` | https://claude.ai/artifact/6bjsozJYehi9kecgTT18Mw | Enterprise evaluators — deep research/POV companion to `executive-brief.html`: why-now, vs. ServiceNow USEM, FAQs, patent/publication feasibility |
| `architecture.html` | https://claude.ai/artifact/TYwmnQLD96mY8iqGcTcgyL | Technical |
| `vuln-engine.html` | https://claude.ai/artifact/7rd9dp3xbpMLbkrLkyD5PY | Technical |
| `remediation-engine.html` | https://claude.ai/artifact/HM4xPo3cWiDrAtb53eiWKf | Technical |
| `connectors.html` | https://claude.ai/artifact/KjThFCZZFQx5p84rL7aUcj | Technical |
| `rbac-governance.html` | https://claude.ai/artifact/5TLSKiAErPCxdC4oQ1aiu9 | Technical |
| `ai-capabilities.html` | https://claude.ai/artifact/5CHkYU17mET2mLXpjTxySK | Technical — every AI surface in the app, what powers it, and its guardrails |
| `reporting.html` | https://claude.ai/artifact/GkZ6EcabxquNLLyYyGXePj | Technical — report fields, on-demand generation, scheduled email delivery |
| `soc-operations.html` | https://claude.ai/artifact/8uRxdBAihsmEnGukLGSN2F | Technical — SOC, SOAR, hunting reports, threat intelligence, AI/ML-guided playbooks, detection use cases, SOC metrics and the models used |
| `pages.html` | https://claude.ai/artifact/1cdCtX7fNB3xwTV99xR6V4 | Technical |
| `developer-guide.html` | https://claude.ai/artifact/KyRcNyctxD9jXCBpK98sqd | Developers |
| `poc-methodology.html` | https://claude.ai/artifact/Y81CxD9usZnY3Bjhh4bK1Z | Business |
| `pricing.html` | https://claude.ai/artifact/EoeA8VCKW94gK21efoXJyn | Business |
| `user-guide.html` | https://claude.ai/artifact/TeWQ7PY8BWq4JU7RLXJcKH | Everyday users |

## Keeping this in sync with the application — read this when you change anything

**Whenever a change to the application would make a claim in one of these documents —
or in the repository's own `CLAUDE.md` — wrong, stale, or incomplete, update the affected
document(s) in the same change** — don't let the docs drift. Concretely:

| If you change... | Update... |
|---|---|
| A connector (`remediation/connectors/*.py`), or add/remove one | `connectors.html`, `vuln-engine.html` §8, `pages.html` §4, and `CLAUDE.md`'s "The connector pattern" section |
| The Finding schema (`remediation/schema/normalized-finding-schema.md`) | `architecture.html` §4 and `CLAUDE.md`'s "The Finding schema" section (it names the current asset-type count) |
| The remediation workflow, approval states, or policy engine | `remediation-engine.html` |
| Add/remove a subagent, or change a pipeline's step sequence (`.claude/agents/*.md`, `.claude/commands/*.md`) | `vuln-engine.html` (for `/quanta-scan`), `remediation-engine.html` (for `/remediate`), and `CLAUDE.md`'s two "Architecture: ..." sections — this exact gap (a subagent added but never reflected in any of the three) is why this row was added |
| SOC cases, queues, metrics, log analysis, TTP classifier, threat-intelligence scoring, hunt/investigation report sections, SOAR recommender, use-case generators (`remediation/soc/`, `remediation/hunting/`, `remediation/soar/`) | `soc-operations.html` (the method sections and the models table), `pages.html` (/soc, /hunting, /soar), `ai-capabilities.html` and `CLAUDE.md` |
| Dark Web Watch sources, matching or ingest (`remediation/darkweb/`, `darkweb_connector.py`) | `soc-operations.html` §15, `pages.html` (/dark-web-watch), `docs/INTEGRATION_API.md`, `CLAUDE.md` |
| RBAC, session/auth model, or the tenant-switcher's real scope | `rbac-governance.html` and `CLAUDE.md`'s "Authentication & RBAC" section |
| A new connector accepting a host/URL, or any other AI/security guardrail | `rbac-governance.html` §06 ("AI & security guardrails") - and route it through `remediation/connectors/url_safety.py`'s `assert_safe_target()`/`assert_safe_instance_label()` before construction, the same guardrail every existing connector uses |
| The API Security area (`remediation/apisec/`, `remediation/config/api_security.yaml`, `/api/api-security/*`, the `api:write` key scope, the `api-policy-endpoint` connection) | `docs/API_SECURITY.md` (source of truth), `docs/INTEGRATION_API.md`, `pages.html`, `rbac-governance.html`, `architecture.html`, `developer-guide.html`, `connectors.html`, `user-guide.html`, `docs/FAQ.md` + `faq.js`, and `CLAUDE.md` |
| The module layout (a page added, moved or removed in `dashboard/static/js/nav.js` or `remediation/config/capabilities.yaml`, or a connector added to a module) | `CLAUDE.md` ("Module layout"), `dashboard/README.md` ("How the app is organised"), `pages.html`, `user-guide.html` and `docs/USER_GUIDE.md` §3 |
| Licensing (`remediation/licensing/`, `remediation/config/licensing.yaml`, `cli/quanta_license.py`, the route-to-module map) | `docs/LICENSING.md` (source of truth), `rbac-governance.html`, `architecture.html`, `developer-guide.html`, `CLAUDE.md`; commercial terms stay in `docs/PRICING.md` |
| Any dashboard page/route (`dashboard/static/js/pages/`, `app.js` routes) | `pages.html` (the affected row) |
| A new end-user workflow, form, or button (anything answering a real "how do I...?") | `user-guide.html`, plus a matching `### ` entry in `docs/FAQ.md` (Ask Quanta's `search_faq()` reads that file live - no code change needed for it to become searchable) and its condensed twin in `dashboard/static/js/pages/faq.js`'s hardcoded `FAQS` array (the in-app FAQ page does NOT read `docs/FAQ.md` directly - the two must be kept in sync by hand) |
| Repo structure, subagent conventions, or the connector-writing pattern | `developer-guide.html` and `CLAUDE.md` |
| **Pricing, tiers, SLA terms, or a vertical module (OT/IoT, AppSec)** | `docs/PRICING.md` (source of truth) **first**, then `pricing.html` and `executive-brief.html`'s pricing-referencing sections, then check `docs/VR_PLATFORM_COMPARISON.md` for stale competitive-cost language |
| Anything affecting the honest competitive/problem-solution framing | `executive-brief.html`, and check `whitepaper.html` §02 (vs. ServiceNow USEM) for stale claims |
| Any AI-facing page or feature (AI Assist, AI Trend Analysis, Ask Quanta, ML Insights) or a subagent's tool-scoping/budget cap | `ai-capabilities.html` |
| The Reports page, `dashboard/reports.py`, or the report-scheduler (`remediation/notifications/report_scheduler.py`, `report_schedule_rules.yaml`) | `reporting.html` — keep the "real today vs. roadmap" split accurate; this is the doc most likely to drift into overclaiming, be careful |
| A new competitor fact, research citation, or patent/publication development worth tracking | `whitepaper.html` §01/§02/§04 |
| Environments, releases and simulated connectors: `remediation/utils/environment.py`, `cli/quanta_release.py`, `features.yaml`, `deploy/helm/quanta/values-*.yaml`, `.github/workflows/release.yml`, `remediation/simulation/` | `docs/ENVIRONMENTS.md`, `docs/RELEASE_PROCESS.md`, `docs/SIMULATION.md` (sources of truth), `developer-guide.html`, `architecture.html`, `connectors.html` (the simulation note), `user-guide.html` with matching `docs/FAQ.md` / `faq.js` entries, `docs/REVIEWER_GUIDE.md`, and `CLAUDE.md`'s "Environments, releases and simulated data" paragraph |
| Relationship graphs: `remediation/graphs/`, `GET /api/graphs/<module>`, `graphView.js` / `graphTheory.js` / `graphLayout.js`, the `Relationship graph` menu entries | `pages.html` (the `/graphs` row), `developer-guide.html` (adding a graph builder), `architecture.html`, `user-guide.html` with matching `docs/FAQ.md` / `faq.js` entries, and `CLAUDE.md`'s "Relationship graphs" paragraph |
| Application security: `remediation/appsec/`, `remediation/gitops/`, `devsecops/gates.py` / `design.py`, `connectors/git_host_connector.py` / `osv_connector.py`, `gitops_policy.yaml`, `pipeline_gates.yaml`, `appsec_scoring.yaml`, the PR guards (never merges, denied paths, confirm-gated open) | `remediation-engine.html` §13, `vuln-engine.html` §14, `connectors.html` (GitHub/GitLab/OSV), `rbac-governance.html` §06-07, `developer-guide.html` §12, `architecture.html` §10, `pages.html` (applications, fix-prs, pipeline-gates, secure-design, devsecops), `user-guide.html` §09 with matching `docs/FAQ.md` / `faq.js` entries, `docs/INTEGRATION_API.md`, and `CLAUDE.md`'s "Application security" section |
| Threat-intel sources or industry/sector correlation (`remediation/enrichment/threat_actor_groups.py`) | `vuln-engine.html` §04 |

**To republish a document after editing its local file**: use the Artifact tool's
`publish` action with `file_path` set to the file here and `url` set to its Published
URL above (this updates the existing page in place rather than creating a new one) —
see the Artifact tool's own instructions for the exact call shape. Read the current
live version first if this conversation didn't just publish it, to avoid a version
conflict.

This convention is also recorded in the project's `CLAUDE.md` so it surfaces
automatically in every session working in this repo.
