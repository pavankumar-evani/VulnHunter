# VulnHunter Dashboard (MVP)

A read-only-by-default web UI over both pipelines' real generated artifacts, plus a form
to trigger a run via the [headless CLI](../cli/README.md). Server-rendered Flask +
Jinja2, not a React single-page app — see "Why Flask, not React" below.

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

## Pages

| Route | Shows |
|---|---|
| `/` | KPI overview across both pipelines, risk-tier breakdown |
| `/vulnhunt` | Code scan findings table (from `SECURITY_REPORT.md`) |
| `/remediate` | Remediation queue (from `REMEDIATION_PLAN.md`), linked to generated playbooks |
| `/playbooks/<filename>` | Full content of one generated Ansible playbook |
| `/run` | Form to trigger a pipeline run (dry-run by default), plus recent-run audit log |
| `/api/status` | JSON health/status endpoint |

## The `/run` page's safety design

Submitting the form **defaults to a dry-run preview** — it shows the exact command that
would execute and spends nothing. Actually executing requires explicitly checking "I
understand this spends real API usage/credits." This mirrors the CLI's own default
posture (see [cli/README.md](../cli/README.md)) rather than adding a different, looser
rule just because there's now a button instead of a terminal command.

## Why Flask, not React

A modern dashboard would typically be a React/TypeScript SPA talking to a JSON API. This
machine didn't have Node.js/npm available when this was built, so a from-scratch
frontend build wasn't something that could be written *and verified running* here.
Flask + server-rendered Jinja2 templates:

- needed no new tooling beyond `pip install flask` (already proven available in this repo)
- could be started and its actual rendered output verified page-by-page in this same
  environment (see the commit history / KNOWLEDGE_TRANSFER.md for that verification)
- is a legitimate, if less flashy, architecture for an internal security tool — plenty of
  real products ship exactly this

If Node.js becomes available in the target environment, `/api/status`-style JSON
endpoints are the natural seam to build a React frontend against later, without
throwing away `dashboard/data.py`'s parsing logic (which the frontend framework choice
shouldn't affect either way).

## What this is NOT (yet)

This is a single-process, no-auth, no-persistence MVP:

- **No authentication or RBAC** — anyone who can reach the port can view findings and
  trigger a real (paid) pipeline run. Do not expose this beyond localhost/a trusted
  network as-is.
- **No database** — findings/plans are re-read from disk on every request; there's no
  historical trend view across multiple runs.
- **Synchronous pipeline execution** — a real (non-dry-run) `/run` submission blocks the
  request until the pipeline finishes, which can be slow. A production version needs a
  job queue.
- **Single-tenant** — one repo's worth of findings, not a multi-customer SaaS view.

These are exactly the gaps [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md)'s
commercialization roadmap (Tier 2b/3) already names — this MVP is meant to prove the
data layer and interaction model, not to be deployed as-is.

## Testing

`tests/test_dashboard.py` uses Flask's test client (in-process WSGI calls, no real HTTP
server or network) to verify every route renders and that the data layer's numbers match
the pipeline test suite's own expectations. The one test touching `/run`'s POST handler
only ever omits the `confirm` field, so it can never trigger a real, paid API call.

```bash
python -m unittest tests.test_dashboard -v
```
