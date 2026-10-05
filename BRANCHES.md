# Branches

A quick-scan registry of what each active branch owns, so a new session (or a different
Claude account) knows what's already claimed without needing to check out or read
another branch's actual code. See [SESSION_SNAPSHOT.md](SESSION_SNAPSHOT.md) for why
this project runs parallel sessions at all, and the safety rules each one follows.

**How this file works**: every clone gets every branch's full history automatically —
that's just how git works, and it's harmless (small, and it's what lets `git fetch`/
`git merge origin/master` work at all). This file isn't about *access*, it's about
*scope*: which folders each branch is allowed to touch, so two sessions working at once
don't collide. Update the relevant entry's Status/Last-synced lines whenever you create,
finish, or abandon a branch — a stale registry is worse than none.

## master

The one always-working, deployable branch. Nothing lands here except through a
reviewed, merged pull request from one of the branches below — with one narrow
exception, see "Keeping this current" at the bottom.

## claude/dashboard

- **Owns**: `dashboard/` (the FastAPI app, all page modules, static JS/CSS) and, in practice, the product features built on top of it that ship together with their pages:
  the application-security stack (`remediation/appsec/`, `remediation/gitops/`, `remediation/devsecops/`, the Git host and OSV connectors), plus the SOC, hunting,
  SOAR, risk, firewall, AI-security and identity modules that were developed on this branch.
- **Scope boundary**: still does not edit `.claude/agents/vuln-*.md` or the `/quanta-scan` command. Changes to `remediation/utils/db.py` are additive (new tables) and
  must be merged quickly, see "Not a good fit for a long-lived parallel branch" below.
- **Status**: active. Carries a large body of work that `master` does not have yet; open a reviewed pull request into `master` rather than pushing there.
- **Last synced with master**: 2026-10-03 (merged into this branch, full suite green, 2,302 tests at that point).

## claude/api-security

- **Owns**: `remediation/apisec/` (API inventory, OWASP API Top 10 rules, caller activity, data classes, protection policies, CI gate, rollout), `remediation/config/api_security.yaml`,
  `dashboard/static/js/pages/apiSecurity.js`, `tests/test_api_security.py`, `docs/API_SECURITY.md`, and the `/api/api-security/*` block in `dashboard/app.py`.
- **Scope boundary**: touches shared files only additively (new tables in `remediation/utils/db.py`, one connection type in `remediation/connections/registry.py`, a `PolicyWebhook` class in
  `webhook_connector.py`, a `rule_ids` match in the guidance engine, an `api:write` key scope, new guidance entries, one DevSecOps control, one capabilities group).
- **Status**: complete and pushed; full suite green when last merged with `claude/dashboard`. Open a reviewed pull request into `claude/dashboard` (or `master`).
- **Last synced with `claude/dashboard`**: 2026-10-05.

## claude/vuln-scan-engine

- **Owns**: `.claude/agents/vuln-*.md`, `.claude/commands/quanta-scan.md` — the `/quanta-scan`
  pipeline (scanner, triage-reporter, fixer, verifier).
- **Scope boundary**: does not touch `remediation/` or `dashboard/`.
- **Status**: scaffolded 2026-09-04, not yet started.
- **Last synced with master**: 2026-09-04.

## claude/remediation-engine

- **Owns**: `remediation/enrichment/`, `remediation/schema/`,
  `.claude/agents/remediation-*.md`, `.claude/commands/remediate.md` — the `/remediate`
  pipeline's planning/enrichment side.
- **Scope boundary**: does not touch `remediation/connectors/` (see `claude/connectors`
  below) or `dashboard/`.
- **Status**: scaffolded 2026-09-04, not yet started.
- **Last synced with master**: 2026-09-04.

## claude/connectors

- **Owns**: `remediation/connectors/` — every pull/push connector.
- **Scope boundary**: does not touch `remediation/enrichment/` or `dashboard/`.
- **Status**: scaffolded 2026-09-04, not yet started.
- **Last synced with master**: 2026-09-04.

## Not a good fit for a long-lived parallel branch

**The database layer** (`remediation/utils/db.py`, migration scripts, and
`remediation/quanta.db`'s schema) is cross-cutting — the dashboard, every connector,
and the remediation engine all read and write through it. A long-running parallel branch
here is *more* likely to collide with the others, not less, precisely because almost
everything else touches it indirectly. If it needs a change, do it as a small, fast,
sequential PR — one session, merged quickly — rather than a parallel branch that sits
open for days while the others drift away from it. The same logic applies to shared auth
(`dashboard/auth/`) and anything under `remediation/utils/` generally.

## Other branches that exist and are not part of this scheme

`git branch -a` will also show a few auto-named branches (`claude/epic-driscoll-...`,
`claude/heuristic-heyrovsky-...`, `claude/loving-germain-...`), an old
`quanta/auto-fixes-20260803` branch from a prior `/quanta-scan --fix` run, and a couple
of dependabot branches. These predate this registry and weren't created under the
scoped-parallel-work scheme above — don't assume anything about what they contain, and
don't delete any of them without actually checking first.

## Keeping this current

- **Starting work on a branch**: update its Status line (e.g. "active — started
  2026-09-10") in the same commit as your first real change.
- **Finishing a branch**: after its PR merges, update its Status line to "merged into
  master, [date]" rather than deleting the entry outright — the history of what existed
  here is useful on its own.
- **The one narrow exception to "nothing lands on master except via PR"**: a commit that
  touches *only* this file is low-risk enough to push directly to master without a full
  PR cycle, specifically because it's bookkeeping with near-zero chance of conflicting
  with anyone's real code. Still run `git fetch origin master` immediately before doing
  so, in case another session updated this same file moments earlier.
