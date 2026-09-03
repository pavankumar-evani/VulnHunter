# Getting Started (from GitHub, in 5 minutes)

This is the short path from "I have a link to the repo" to "the dashboard is open in my
browser." For the full picture (problem statement, both pipelines, test evidence,
troubleshooting log), see [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md). For the deep
enterprise documentation suite (architecture, pricing, RBAC, connectors, AI, and more),
see [docs/enterprise-suite/hub.html](enterprise-suite/hub.html).

## 1. Clone the repo

```bash
git clone https://github.com/pavankumar-evani/VulnHunter.git
cd VulnHunter
git checkout feature/remediation-engine
```

`feature/remediation-engine` is the branch with the current, actively-developed
dashboard and remediation engine described in this repo's docs. `main`/`master` may lag
behind it.

## 2. Install dependencies

Only the dashboard's dependencies are needed to see the product running:

```bash
pip install -r dashboard/requirements.txt
```

(No Node.js/npm needed — the frontend is hand-rolled vanilla JS, no build step. If you
also want to run the `/vulnhunt` or `/remediate` pipelines directly through Claude Code
rather than just browsing the dashboard, see the root [README.md](../README.md) instead.)

## 3. Run it

```bash
python dashboard/app.py
```

Open **http://127.0.0.1:5050** in a browser.

## 4. Log in

Two demo accounts ship with the repo so you can see role-based access without setting
anything up first:

| Email | Password | Role |
|---|---|---|
| `admin@vulnhunter.local` | `ChangeMe123!` | Admin |
| `analyst@vulnhunter.local` | `ChangeMe123!` | User |

These are intentionally public demo credentials, not real secrets — change or remove
them (`dashboard/auth/users.json`) before pointing this at anything real. See
[dashboard/README.md](../dashboard/README.md#authentication) for the full auth model,
including how to require login for every page and set a stable session secret.

## 5. What you'll see

The repo ships with real sample data already in place — you're not looking at an empty
shell. The Overview page shows live KPIs over a bundled remediation plan and code-scan
report (see `remediation/sample-data/` and `SECURITY_REPORT.md`). From there:

- **Queue** (`/queue`) — the live, re-scored remediation queue.
- **AI Assist** (`/ai-assist`) — ask Claude to explain or draft a fix for a finding.
- **Connectors/Adaptors** (sidebar) — where you'd plug in a real Tenable, Armis,
  OpenVAS, Qualys, or other live source instead of the sample data.
- **Reports** (`/reports`) — generate a downloadable KPI/SLA/coverage snapshot.

## 6. Where to go deeper

| Topic | Read this |
|---|---|
| Full product story, both pipelines, roadmap | [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) |
| Dashboard architecture, auth, production hardening | [dashboard/README.md](../dashboard/README.md) |
| Running `/vulnhunt` and `/remediate` via Claude Code | [README.md](../README.md) |
| Enterprise architecture, pricing, RBAC, connectors, AI, research | [docs/enterprise-suite/hub.html](enterprise-suite/hub.html) |
| Task-oriented "how do I...?" guide | [docs/USER_GUIDE.md](USER_GUIDE.md) |
| FAQ | [docs/FAQ.md](FAQ.md) |

If something breaks, check [dashboard/README.md](../dashboard/README.md#what-this-is-not-yet)
first — several current limitations (single-tenant with no per-tenant data boundary, no
historical trend storage across pipeline runs, reads open by default, local-only
binding) are already known and documented, not bugs.
