"""
Stage 1 of the 15-chapter pipeline: read the real docs/enterprise-suite/*.html
files (untouched) and produce two dark-themed variants of each into
scripts/doc-pdf-pipeline/_build/:

  dark_offline_src/  - dark theme only, <details> left naturally collapsed.
                        Feeds build_offline_hub.py (the interactive HTML hub).
  dark_print_src/    - dark theme + <details> force-opened + print-pagination
                        CSS fixes. Feeds render_docs.ps1 (the per-chapter PDFs).

Run this before render_docs.ps1. See README.md for the full pipeline order.
"""
import re, os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
SRC_DIR = os.path.join(REPO_ROOT, "docs", "enterprise-suite")
BUILD_DIR = os.path.join(SCRIPT_DIR, "_build")
PRINT_DIR = os.path.join(BUILD_DIR, "dark_print_src")
OFFLINE_DIR = os.path.join(BUILD_DIR, "dark_offline_src")

# Order matches docs/enterprise-suite/MANIFEST.md.
FILES = [
    "hub.html", "executive-brief.html", "whitepaper.html", "architecture.html",
    "vuln-engine.html", "remediation-engine.html", "connectors.html",
    "rbac-governance.html", "ai-capabilities.html", "reporting.html",
    "pages.html", "developer-guide.html", "poc-methodology.html",
    "pricing.html", "user-guide.html",
]

HTML_TAG_RE = re.compile(r"<html\b([^>]*)>")
DETAILS_RE = re.compile(r"<details\b(?![^>]*\bopen\b)([^>]*)>")
HEAD_CLOSE_RE = re.compile(r"</head>", re.IGNORECASE)

# Chrome's headless --print-to-pdf reserves a page margin ("gutter") that no
# element's own background can paint into, regardless of body{background} -
# only @page{margin:0} removes it (and, as a side effect, removes the room
# Chrome needs to draw its own injected header/footer, so no post-render crop
# is needed either - see finalize_pdfs.py). These 15 pages were authored as
# scrolling web pages with zero print-pagination CSS of their own, so
# break-inside protection is added here rather than in the source - plain
# "avoid" (not "avoid-page", which Chrome's print-to-pdf honors less
# reliably in practice).
PRINT_FIX_CSS = """<style>
  @page { margin: 0; }
  html, body { margin: 0; }
  * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
  pre, blockquote, figure, table,
  .callout, .codeblock, .card, .doccard, .disclaimer, .facet, .stat, .sg,
  .box, .panel, .tile, .tl-phase, .quote, .kpi, .metric {
    break-inside: avoid; page-break-inside: avoid;
  }
  tr { break-inside: avoid; page-break-inside: avoid; }
  h1, h2, h3, h4 { break-after: avoid; page-break-after: avoid; }
</style>
"""


def add_print_fixes(html):
    if HEAD_CLOSE_RE.search(html):
        return HEAD_CLOSE_RE.sub(PRINT_FIX_CSS + "</head>", html, count=1)
    return html + PRINT_FIX_CSS


def force_dark(html):
    # These artifact source files are bare fragments (no <html>/<head>/<body> -
    # the Artifact publisher adds that wrapper at publish time), so there is
    # normally no existing <html> tag to edit. Prepend an explicit opening
    # tag; the browser's own HTML parser folds the rest of the fragment into
    # it as the real document root, and :root[data-theme="dark"] then wins
    # over both the light default and any prefers-color-scheme match.
    if HTML_TAG_RE.search(html):
        return HTML_TAG_RE.sub(lambda m: f'<html{m.group(1)} data-theme="dark">', html, count=1)
    return '<html data-theme="dark">\n' + html


def force_open(html):
    return DETAILS_RE.sub(lambda m: "<details open" + m.group(1) + ">", html)


def main():
    os.makedirs(PRINT_DIR, exist_ok=True)
    os.makedirs(OFFLINE_DIR, exist_ok=True)

    for fname in FILES:
        with open(os.path.join(SRC_DIR, fname), encoding="utf-8") as f:
            html = f.read()
        dark = force_dark(html)

        with open(os.path.join(OFFLINE_DIR, fname), "w", encoding="utf-8") as f:
            f.write(dark)

        print_html = add_print_fixes(force_open(dark))
        with open(os.path.join(PRINT_DIR, fname), "w", encoding="utf-8") as f:
            f.write(print_html)

        n_details = html.count("<details")
        print(f"{fname}: dark forced, {n_details} <details> tag(s) force-opened for print")


if __name__ == "__main__":
    main()
