# VulnHunter — Session Snapshot

**Written 2026-09-04.** This is a portability document, not architecture reference —
[CLAUDE.md](CLAUDE.md) is the timeless "what this repo is" file and stays the primary
source for that. This file exists so that starting Claude Code in a **brand-new
account**, possibly on a **different machine**, and pointing it at
`git clone https://github.com/pavankumar-evani/VulnHunter.git` reproduces full continuity
with this project — including decisions and conventions that live only in a prior
session's own memory files, not in the code itself, and would otherwise have to be
re-discovered (some of them the hard way — see the pipeline gotchas below).

**If you're a Claude session reading this cold: read this whole file before touching
anything.** It's short. Skipping it costs more time than reading it does.

## 1. Who owns this, and the one fact that must never regress

VulnHunter is an **independent commercial product**, owned solely by the user
(pavankumar-evani on GitHub), operating as **"VulnHunter Development LLC."** It has no
current affiliation with Deloitte. An earlier phase of this project *did* originate
inside Deloitte (a hackathon), and a large, deliberate cleanup pass already stripped
Deloitte branding, placeholder domains (`corp.deloitte.local`), CODEOWNERS references,
README provenance lines, and Deloitte-branded deliverables from the repo (see the git log
around commit `da89124` and earlier — search `git log --grep=Deloitte` if you want the
full list). **Never reintroduce Deloitte branding, the Deloitte PPTX template/skill, or
Deloitte's color palette into anything produced for this project** — including new slide
decks, PDFs, or docs. If asked to build a presentation, use the plain `pptx` skill, not
`deloitte-pptx`.

Separately: a much earlier planning conversation for this project's feature set (the
compensating-control-coverage, network-reachability, attack-chain, and SBOM-remediation
capabilities — see `remediation/enrichment/`) was inspired by a **confidential internal
transcript** describing a different, real commercial platform, a real client engagement,
and real people. None of that — names, client, product — has ever been written into this
repo, and it must stay that way: describe any future capability by what it does for
VulnHunter, never by where the idea traces back to.

## 2. Repo, environment, and what's already durable

- **Repo**: `https://github.com/pavankumar-evani/VulnHunter`, branch `master`.
- **This session's working copy**: `C:\Users\pavane\OneDrive - Deloitte (O365D)\Desktop\Claud workspace\vulnhunter-project`
  on Windows. The `OneDrive - Deloitte (O365D)` folder name is just this user's personal
  OneDrive path from their employer-issued laptop — it is **not** a sign of any project
  affiliation with Deloitte (see §1); don't read anything into it, and don't be surprised
  that paths under this repo contain spaces and parentheses (see the pipeline gotcha in
  §4 below — that alone has caused a real, reproducible bug once already).
- **Everything committed to git is already fully portable** — a fresh `git clone`
  reproduces the code, `CLAUDE.md`, this file, and `scripts/doc-pdf-pipeline/` (see §4)
  with zero loss, on any machine, under any account. The two things that do **not**
  travel with git are covered in §5 (the `deliverables/` folder) and §6 (memory files).
- As of this writing: working tree clean except for one already-intended
  `.gitignore` change (adding `deliverables/`); no divergence from `origin/master`.
  Multiple Claude Code sessions have pushed to this repo concurrently in the past — always
  `git fetch origin master` and check for divergence before pushing, same as any other
  session working here would.

## 3. Standing preferences a fresh session won't otherwise know

These came from explicit user corrections/confirmations across this and earlier
sessions, distilled from that session's own memory files
(`~/.claude/projects/.../memory/*.md`, tied to the machine, not the account — see §6).
Treat these as decided, not open questions:

- **Dark navy theme, everywhere, by default.** `--paper:#0a0e1a; --ink:#eef1fb;
  --surface:#10172a; --surface-2:#151d35; --line:#263153; --muted:#97a2c2;
  --accent:#6d97f7; --accent-deep:#a9c2fb; --accent-soft:#16204a` (from
  `docs/enterprise-suite/executive-brief.html`'s own `:root[data-theme="dark"]` block —
  copy from there, don't reinvent). This was a real correction mid-session: a first pass
  at generating PDFs defaulted to a light theme reasoning it'd be more printable/practical
  — the user explicitly overrode that twice, once for new documents and once asking for
  already-delivered ones to be redone. Don't re-litigate this; it's settled.
- **Chakra Petch is the one app-wide and document-wide display/body font**, not just the
  login page's. Loaded via Google Fonts in the live app/docs; the real `.ttf` files (OFL
  1.1, free to embed/redistribute) are committed at `scripts/doc-pdf-pipeline/fonts/` for
  anything that needs to render fully offline with no network access.
- **Commit message convention**: a code+tests commit, then a *separate* docs-sync commit
  — don't bundle a functional change and its documentation update into one commit.
- **OneDrive-backed working directory**: avoid per-item file I/O in hot loops here
  specifically — OneDrive's sync layer makes many small sequential file operations
  noticeably slower than on a plain local disk. Load data once, pass it down, rather than
  re-reading/re-writing per iteration.
- **SSO/OIDC stays deferred** — real, working OIDC client code exists
  (`dashboard/auth/oidc.py`) but there's no real identity provider configured, and that's
  a deliberate, already-made decision, not a gap to keep flagging. Local HTTPS (a
  self-signed cert auto-generated into `dashboard/certs/` on first run) is the real,
  enabled default — don't propose "should we add HTTPS" either, it's already there.

## 4. What this session actually built (2026-09-03 → 2026-09-04)

In rough order, for context on *why* things look the way they do:

1. **Visual refresh**: swapped the app's old shield-and-magnifying-glass mark for a
   hexagon-and-reticle logo (app + all 15 `docs/enterprise-suite/` pages), replaced emoji
   lifecycle icons on the Overview page with real SVG icons, redesigned the login page's
   typography, and made Chakra Petch the whole app's font (not just login's).
2. **Business-facing document set** (all initially built light-themed via a `docx`
   Node script → Word COM → PDF pipeline, then later rebuilt dark — see #4 below):
   Developer & Contributor Guide, a US-market Commercial Brochure, a from-scratch-
   researched Cloud Hosting & Commercial Launch Guide (AWS/Azure/OCI/DigitalOcean cost
   tables, sourced from each vendor's real pricing pages/APIs, with explicit "could not
   verify" flags rather than invented numbers — most notably OCI's database price), and a
   commercial demo PPTX (built with the plain `pptx` skill, never `deloitte-pptx`).
3. **The 15-chapter enterprise documentation suite as PDFs + a combined PDF + an offline
   HTML hub.** `docs/enterprise-suite/*.html` are real, already-existing Claude Artifact
   pages (light-themed by default, with a dark override via `data-theme="dark"`) — this
   session built a pipeline (now committed at `scripts/doc-pdf-pipeline/`, see below) that
   renders all 15 to individual dark-themed PDFs, merges them into one bookmarked PDF, and
   builds a single self-contained offline HTML file (fonts embedded as base64, so it needs
   zero network access) with a sidebar that switches between all 15 via `<iframe srcdoc>`.
4. **Two rounds of real bugs found and fixed post-delivery** — worth knowing about
   because they're the kind of thing that looks fine in isolated testing and only shows up
   once a real reader complains:
   - **The dark-theme "no-op" bug**: the first attempt to force `docs/enterprise-suite/`
     pages into dark mode for PDF rendering did nothing at all, silently — because those
     source files are bare fragments (no literal `<html>` tag; the Claude Artifact
     publisher adds that wrapper only at publish time), so a regex that tried to *edit* an
     existing `<html ...>` tag matched zero times and the whole "fix" was a no-op. The
     real fix is to *prepend* `<html data-theme="dark">` rather than search-and-replace.
   - **Page breaks splitting code blocks/tables/callouts mid-element, and the dark
     background not reaching the page edges (white margins).** Both traced to one root
     cause: Chrome's `--print-to-pdf` reserves a page margin ("gutter") that no element's
     own `background` can paint into, and these pages had zero print-pagination CSS to
     begin with (they were authored as scrolling web pages). Fixed with
     `@page { margin: 0; }` plus `break-inside: avoid` (plain `avoid`, not the more
     specific `avoid-page` value, which Chrome's `--print-to-pdf` honors less reliably in
     practice) on every code block/table-row/callout/card. Full writeup in
     `scripts/doc-pdf-pipeline/README.md`.
   - **A path-with-spaces bug specific to this repo's real location**: the pipeline was
     first built and tested inside a scratchpad temp directory whose name happens to have
     no spaces at all — so a `--print-to-pdf=$path` argument built without embedding
     literal quotes around `$path` worked *there* by accident, then broke the moment the
     same scripts ran from this repo's real path (which contains `OneDrive - Deloitte
     (O365D)`, real spaces and parens). Chrome's own command-line parser splits an
     unquoted `--flag=value with spaces` at the spaces and then refuses with `Multiple
     targets are not supported in headless mode.` Fixed, and now tested from this repo's
     actual path, not just the scratchpad.
5. **`scripts/doc-pdf-pipeline/` itself** — this is new, permanent, committed
   infrastructure (not a one-off session artifact): the 5 Python/PowerShell scripts that
   do everything in point 3 above, the 3 standalone documents' dark-themed HTML sources
   from point 2, and the Chakra Petch font files. Read its own `README.md` before
   touching any of it — it documents two non-obvious, hard-won facts: Puppeteer/Playwright
   cannot drive Chrome at all on this machine (a real Chrome Enterprise policy disallows
   the DevTools remote-debugging protocol they depend on — this surfaces as a confusing
   "browser already running" error, not an obvious permissions error), and the
   `@page{margin:0}` fix from point 4 above.

## 5. `deliverables/` — real output, deliberately not in git

Every PDF, the offline HTML hub, and the font-file bundle this session produced for the
user live in a local, **gitignored** `deliverables/` folder at the repo root — matching an
earlier, deliberate decision in this same project to keep generated binaries out of git
history (some Deloitte-branded ones were removed from git for exactly this reason
earlier). **This folder will not travel with `git clone`.** If continuing in a new
account/machine and the actual delivered files (not just the ability to regenerate them)
matter, copy `deliverables/` there manually — Claude cannot move files between machines
or accounts on its own.

If the files themselves are gone but the repo is present, everything in `deliverables/`
is fully reproducible from source via `scripts/doc-pdf-pipeline/` (see §4.5) — that's the
whole reason that pipeline was committed rather than left as a scratchpad one-off.

## 6. About memory, and what this document is standing in for

Claude Code's memory system stores files locally
(`~/.claude/projects/<hash-of-this-project-path>/memory/`), keyed by machine + project
path, not by Claude account. A brand-new account on the **same machine**, pointed at this
**same working-directory path**, may well still find those memory files. A new account on
a **different machine**, or a fresh clone into a **different path**, will not — and this
document is written assuming the worse case, so it doesn't matter either way. If you *do*
have access to that session's memory files, `MEMORY.md` there is the index; this document
deliberately overlaps with it (§3 above) rather than assuming you have it.

## 7. Open items

- **Task #19** (in progress, not blocked): Admin page needs real health checks, connector
  health, and AI cost/billing surfaced — started, not finished.
- **Task #43** (pending, blocked on the user): live-verifying one real pull connector
  against an actual vendor account. Every connector in this repo is honestly disclosed as
  "built against public docs, unit-tested against mocked responses, never exercised
  against a real account" — this task is what would change that for one connector, and it
  needs the user to actually provide/authorize a real vendor credential to proceed.
- Nothing else is mid-flight. Run `python -m unittest discover -s tests -p "test_*.py"`
  to confirm the suite is still green (1,458 tests as of the last full run this session
  knows about) before assuming any of the above.
