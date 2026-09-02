# Enterprise Documentation Suite — Manifest

Eleven HTML documents, version-controlled here so they survive alongside the code they
document. Each is also published as a Claude Artifact (a hosted, shareable page) at the
URL below. **The files in this directory are the source of truth** — the published
Artifact is a mirror, kept in sync by republishing from these exact files (see "Keeping
this in sync" below).

| File | Published URL | Audience |
|---|---|---|
| `hub.html` | https://claude.ai/code/artifact/506d5ae4-b369-4fe4-83b2-e645a843c19b | Landing page — links to all 10 below |
| `executive-brief.html` | https://claude.ai/code/artifact/7ed55a02-ab8b-4ebd-9451-281b035cfc1b | Enterprise evaluators |
| `architecture.html` | https://claude.ai/code/artifact/d7036aa2-c68f-45fd-a6ce-132dad8309f7 | Technical |
| `vuln-engine.html` | https://claude.ai/code/artifact/37848de1-aed0-4e71-b903-0cf2780dc52b | Technical |
| `remediation-engine.html` | https://claude.ai/code/artifact/845f8806-5bdf-47b3-ba02-d55fe8a34f46 | Technical |
| `connectors.html` | https://claude.ai/code/artifact/97b22f55-f70e-4f0a-9d5c-d99af5c12a0c | Technical |
| `rbac-governance.html` | https://claude.ai/code/artifact/2411def2-8368-47b2-82e4-e4068ba3dd1c | Technical |
| `pages.html` | https://claude.ai/code/artifact/04f95814-0635-4949-9046-4221d0e0513f | Technical |
| `developer-guide.html` | https://claude.ai/code/artifact/99a5503d-91d9-45cf-a83d-29ac14960ea4 | Developers |
| `poc-methodology.html` | https://claude.ai/code/artifact/fc05a1c0-7664-4ce1-88a2-86bec7eae328 | Business |
| `pricing.html` | https://claude.ai/code/artifact/6fc9ea41-5cc3-4934-8e2a-236a252b1bd1 | Business |

## Keeping this in sync with the application — read this when you change anything

**Whenever a change to the application would make a claim in one of these documents
wrong, stale, or incomplete, update the affected document(s) in the same change** —
don't let the docs drift. Concretely:

| If you change... | Update... |
|---|---|
| A connector (`remediation/connectors/*.py`), or add/remove one | `connectors.html`, `vuln-engine.html` §8, `pages.html` §4 |
| The Finding schema (`remediation/schema/normalized-finding-schema.md`) | `architecture.html` §4 |
| The remediation workflow, approval states, or policy engine | `remediation-engine.html` |
| RBAC, session/auth model, or the tenant-switcher's real scope | `rbac-governance.html` |
| Any dashboard page/route (`dashboard/static/js/pages/`, `app.js` routes) | `pages.html` (the affected row) |
| Repo structure, subagent conventions, or the connector-writing pattern | `developer-guide.html` |
| **Pricing, tiers, or SLA terms** | `docs/PRICING.md` (source of truth) **first**, then `pricing.html` and `executive-brief.html`'s pricing-referencing sections, then check `docs/VR_PLATFORM_COMPARISON.md` for stale competitive-cost language |
| Anything affecting the honest competitive/problem-solution framing | `executive-brief.html` |

**To republish a document after editing its local file**: use the Artifact tool's
`publish` action with `file_path` set to the file here and `url` set to its Published
URL above (this updates the existing page in place rather than creating a new one) —
see the Artifact tool's own instructions for the exact call shape. Read the current
live version first if this conversation didn't just publish it, to avoid a version
conflict.

This convention is also recorded in the project's `CLAUDE.md` so it surfaces
automatically in every session working in this repo.
