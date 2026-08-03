# VulnHunter Dashboard (MVP)

A read-only-by-default web UI over both pipelines' real generated artifacts, plus a form
to trigger a run via the [headless CLI](../cli/README.md). A FastAPI JSON API
(`dashboard/app.py`) behind a hand-rolled vanilla-JS single-page frontend
(`dashboard/static/`) — no Node/npm/build step. See "Why FastAPI + vanilla JS" below for
the reasoning.

## Running it

```bash
pip install -r dashboard/requirements.txt
python dashboard/app.py
# open http://127.0.0.1:5050
```

It reads directly from the repo it's run in: git history (for `/vulnhunt`'s
`SECURITY_REPORT.md`, via the `vulnhunter/auto-fixes-*` branch) and files under
`remediation/` (for `/remediate`'s `normalized-findings.json`, `REMEDIATION_PLAN.md`, and
generated playbooks). If those artifacts don't exist yet, the relevant pages show an
empty state with instructions instead of erroring.

## Architecture

- **`dashboard/app.py`** — a FastAPI app with two kinds of routes:
  - `/api/*` — the JSON API. This is the only thing the frontend talks to, and the only
    thing worth testing from Python (see Testing below).
  - Everything else (`/`, `/vulnhunt`, `/remediate`, `/queue`, `/priority-rules`,
    `/servicenow`, `/run`, `/playbooks/{filename}`, and any unrecognized path) serves the
    exact same file: `dashboard/static/index.html`. This is what makes it a single-page
    app — there's no server-side templating left at all.
- **`dashboard/static/js/app.js`** — the client-side router. It reads
  `window.location.pathname`, dynamically `import()`s the matching page module from
  `static/js/pages/`, and re-renders `#app` in place (no full page reload). Clicking any
  in-app link uses `history.pushState` instead of a real navigation; the browser's
  back/forward buttons still work via `popstate`.
- **`dashboard/static/js/pages/*.js`** — one module per page. Each calls the JSON API
  (via `static/js/api.js`), builds HTML from the response, and wires up any forms
  (priority-rules editor, ServiceNow send, run-pipeline trigger). All dynamic text goes
  through `escapeHtml()` in `static/js/dom.js` before hitting `innerHTML`.
- **`dashboard/data.py`** — unchanged by the rewrite. It has no Flask/FastAPI-specific
  code at all; it just parses real artifacts into plain dicts, and both the old Flask
  routes and the new FastAPI routes called it the same way.
- **`dashboard/ai_assist.py`** — pure prompt-construction for the AI-assist feature
  (`build_ai_assist_prompt(finding, action)`); no subprocess/network code of its own.
- **`dashboard/reports.py`** — real, live-computed report generation
  (`generate_report_data`, `render_report_html`) for the Reports page and
  `/api/reports/*`; no fabricated numbers, and honest about what "period" does and
  doesn't mean without a persistence layer (see its module docstring).
- **`dashboard/static/js/tenant.js`** — the illustrative MSSP tenant-switcher demo
  (client-side only, partitions findings by asset category - not real per-tenant
  auth/data isolation, see the FAQ page).

## Pages

| Route | Shows |
|---|---|
| `/` | KPI overview across both pipelines, SLA/KEV/EPSS summary, risk-tier + asset-class breakdown, live-refreshed every 20s |
| `/vulnhunt` | Code scan findings table (from `SECURITY_REPORT.md`), filterable by severity and CWE-derived category |
| `/queue` | The *live*, re-scored remediation queue (priority/SLA/KEV/EPSS/ATT&CK), sortable and filterable client-side (priority, asset type, KEV-only), the (demo) tenant switcher applies here, live-refreshed every 20s, per-row "Ask AI" link |
| `/remediate` | The *static* remediation plan snapshot (from `REMEDIATION_PLAN.md`), linked to generated playbooks, filterable by risk tier and automation target |
| `/playbooks/<filename>` | Full content of one generated Ansible playbook |
| `/priority-rules` | Live YAML editor for `remediation/config/priority_rules.yaml` |
| `/servicenow` | ServiceNow Incident preview (no credentials needed) and send form |
| `/run` | Form to trigger a pipeline run (dry-run by default), plus recent-run audit log |
| `/ai-assist` | Ask Claude to explain/remediate/summarize a finding - dry-run preview by default, explicit confirm to spend real API usage |
| `/reports` | Generate a real, downloadable KPI/SLA/coverage snapshot report (daily through yearly framing) |
| `/support` | How to get help, known limitations, before-you-file-a-bug checklist |
| `/faq` | Direct answers about what this product does and doesn't do |
| `/api/status` | JSON health/status endpoint |

## The `/run` and `/servicenow` safety design

Both forms **default to a dry-run/preview** — `/run` shows the exact command that would
execute and spends nothing; `/servicenow`'s send form shows exactly what payload would be
posted to each finding's Incident, with zero network calls. Actually executing either
requires explicitly checking a confirm box. This mirrors the CLI's own default posture
(see [cli/README.md](../cli/README.md)) rather than adding a different, looser rule just
because there's now a button instead of a terminal command.

## Why FastAPI + vanilla JS, not Node/React (or staying on Flask/Jinja2)

The ask behind this rewrite was a genuinely modern, commercial-grade interface. A
from-scratch React/TypeScript build was the obvious first thought — but this machine has
no Node.js/npm installed, so a React build couldn't be *written and verified running*
here; shipping an untested frontend isn't "modern," it's just unverified. Two real
options remained:

1. **Stay on Flask + server-rendered Jinja2** (the original MVP's choice) — safe, but not
   what "modern JS interface" actually means, and doesn't showcase real client-side
   interactivity (sorting, live re-render, no full-page reloads).
2. **FastAPI (JSON API) + a hand-rolled vanilla-JS SPA** — real client-side routing,
   `fetch()`-based data loading, dynamic `import()` per page, live in-browser table
   sorting - everything a React app would give you for this scope, using only what
   ships in every modern browser. No bundler, no `node_modules`, no build step to get
   wrong. Every page was clicked through and verified live in a browser during
   development (not just unit-tested) - see KNOWLEDGE_TRANSFER.md §11.1.

That's what this dashboard now is. If Node.js becomes available in the target
environment, `/api/*`'s JSON contract is the exact seam a React (or any other) frontend
would build against - `dashboard/data.py`'s parsing logic underneath doesn't change
either way, and neither would the FastAPI routes, which are already framework-appropriate
JSON endpoints rather than Flask's `render_template` calls.

## What this is NOT (yet)

This is a single-process, no-auth, no-persistence MVP:

- **No authentication or RBAC** — anyone who can reach the port can view findings and
  trigger a real (paid) pipeline run. Do not expose this beyond localhost/a trusted
  network as-is.
- **No database** — findings/plans are re-read from disk on every request; there's no
  historical trend view across multiple runs.
- **Synchronous pipeline execution** — a real (non-dry-run) `/api/run` submission blocks
  the request until the pipeline finishes, which can be slow. A production version needs
  a job queue.
- **Single-tenant** — one repo's worth of findings, not a multi-customer SaaS view. The
  sidebar's tenant switcher is a UI-only demo (partitions the same dataset by asset
  category) - not real per-tenant auth or data isolation.
- **No report history** — `/reports`' period selector (daily/weekly/monthly/...) labels
  the report's intended cadence, but every period currently renders the same real,
  current-moment snapshot; there's no historical data to aggregate yet.

These are exactly the gaps [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md)'s
commercialization roadmap (Tier 2b/3) already names — this MVP is meant to prove the
data layer and interaction model, not to be deployed as-is.

## Testing

`tests/test_dashboard.py` uses `fastapi.testclient.TestClient` (in-process ASGI calls, no
real HTTP server or network) to verify the JSON API's contract precisely and that every
route serves the SPA shell correctly. Because the frontend renders client-side, these
tests validate JSON payloads rather than rendered HTML - the actual DOM rendering was
verified live in a browser during development (see KNOWLEDGE_TRANSFER.md). The one test
touching `/api/run`'s POST handler only ever omits `confirm`, so it can never trigger a
real, paid API call; same rule for `/api/servicenow/send`.

```bash
python -m unittest tests.test_dashboard -v
```
