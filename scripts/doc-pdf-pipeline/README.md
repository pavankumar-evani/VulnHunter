# Documentation PDF pipeline

Regenerates every dark-navy PDF and the offline HTML hub described in the
enterprise documentation suite, from source, on any machine. Built 2026-09
after the enterprise-suite docs (`docs/enterprise-suite/*.html`) were themed
dark to match the app and print-hardened to stop content splitting across
page breaks.

## What this produces

| Command | Produces |
|---|---|
| `patch_dark.py` → `render_docs.ps1` → `finalize_pdfs.py` | 15 individual chapter PDFs in `_build/final_out_dark/` |
| ...then `combine_pdfs.py` | One combined 100+ page PDF with a bookmark outline, `_build/VulnHunter_Documentation_Complete.pdf` |
| `patch_dark.py` → `build_offline_hub.py` | One self-contained offline HTML file, `_build/VulnHunter_Documentation_Offline.html` |
| `render_standalone_docs.ps1` | The 3 standalone docs (Developer Guide, Commercial Brochure, Cloud Hosting Guide) as PDFs in `_build/` |

None of these outputs are committed (`_build/` is gitignored) - only the
generators are. Copy whatever you need out of `_build/` into `deliverables/`
(itself gitignored - see the repo root) or hand it to the user directly.

## Prerequisites

- **Chrome or Edge installed** (the scripts auto-detect either, in the usual
  install locations - edit `$chromeCandidates` in the `.ps1` files if yours
  lives somewhere else).
- **Python** with `pypdf` installed (`pip install pypdf`).
- **PowerShell** (Windows PowerShell 5.1 or later).

## Running it

```powershell
# 1. The 15 individual chapter PDFs + the combined PDF
python patch_dark.py
powershell -File render_docs.ps1
python finalize_pdfs.py
python combine_pdfs.py

# 2. The offline HTML hub (only needs patch_dark.py's dark_offline_src/ output,
#    already produced by step 1 above if you ran it - otherwise run patch_dark.py alone first)
python build_offline_hub.py

# 3. The 3 standalone docs
powershell -File render_standalone_docs.ps1
```

## Two things worth understanding before you touch this

**Puppeteer/Playwright will not work here, and won't on any machine with the
same Chrome Enterprise policy.** Every render step uses Chrome's plain
`--headless=new --print-to-pdf=<path>` CLI flag directly via
`Start-Process`, not a DevTools-Protocol library. That's a deliberate,
hard-won choice: on this machine (and likely any other with the same
`DevTools remote debugging is disallowed by the system admin.` enterprise
policy), Puppeteer/Playwright's launch always fails - the error surfaces as
a confusing "browser is already running" even against a brand-new
`--user-data-dir`, because their whole architecture requires the
DevTools-remote-debugging port that policy blocks. The bare `--print-to-pdf`
CLI flag does not need that port and is unaffected. If you're on a machine
without that policy and want the finer control Puppeteer offers
(`page.evaluate`, `emulateMediaFeatures`, etc.), it should work fine there -
just don't assume it will work everywhere this pipeline needs to.

**`@page { margin: 0; }` is load-bearing, not cosmetic.** Chrome's
`--print-to-pdf` reserves a page margin ("gutter") around the printable
area that no element's own CSS `background` can paint into, regardless of
what `body { background }` says - this is what caused the dark-theme PDFs to
render with white margins on every side before this pipeline existed. Zeroing
the `@page` margin fixes that, and as a side effect also removes the room
Chrome needs to draw its own injected header/footer (date + title at the
top, file:// URL + page number at the bottom) - which is why
`finalize_pdfs.py`'s crop step is a documented no-op (`CROP_TOP`/
`CROP_BOTTOM = 0`) rather than deleted outright: it used to crop 34pt off
every page specifically to remove that header/footer band, before this fix
made it unnecessary. If a future Chrome version changes this behavior,
that's the first place to look.

**Paths with spaces will break Chrome's own command-line parser if you pass
them unquoted.** If this repo lives under a path containing a space (an
`OneDrive - Foo (Bar)` parent folder is a common real-world case), a plain
`--print-to-pdf=$outPath` PowerShell string fails with `Multiple targets are
not supported in headless mode.` - Chrome's parser splits the flag at the
unquoted space and treats the fragments as extra URL targets. Both `.ps1`
scripts here embed literal quotes in the value itself
(`'--print-to-pdf="{0}"' -f $outPath`) rather than relying on PowerShell's
own array-element quoting, which does not reliably survive into how Chrome
re-parses its own argv. If you add a new call site, copy that pattern.

Relatedly: `break-inside: avoid` (plain, not `avoid-page`) is what stops
code blocks/tables/callouts from splitting mid-element across a page break.
Chrome's `--print-to-pdf` has historically honored the more specific
`avoid-page` value less reliably than plain `avoid` - if page-break
regressions show up again, check which value is in use before assuming the
property isn't working at all.

## Fonts

`fonts/*.ttf` are the real Chakra Petch (Google Fonts, SIL Open Font License
1.1 - free to embed, redistribute, and bundle in generated documents; see
the licensing section of the Cloud Hosting Guide for the full citation)
weight files, committed here specifically so `build_offline_hub.py` can
embed them as base64 `@font-face` data URIs without a network fetch at
build time. Only 3 of the 6 available weights (Regular/SemiBold/Bold) are
actually embedded in the offline hub, to keep its file size reasonable -
see `FONT_FILES` in `build_offline_hub.py` if you want to change that.

## Standing conventions this pipeline follows

- Dark navy palette everywhere (`--paper:#0a0e1a`, `--ink:#eef1fb`,
  `--accent:#6d97f7`, etc.) - matches the enterprise-suite docs' own
  `:root[data-theme="dark"]` tokens. See `SESSION_SNAPSHOT.md` at the repo
  root for why this is the standing default, not a one-off choice.
- `<details>` elements are force-opened for the PDFs (nothing collapsed on a
  page nobody can click) but left naturally collapsed/clickable for the
  offline HTML hub, since that one is genuinely interactive.
