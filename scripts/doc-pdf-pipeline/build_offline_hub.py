"""
Builds VulnHunter_Documentation_Offline.html: a single, self-contained,
network-independent HTML file with a sidebar that switches between all 15
enterprise-suite chapters (loaded into an <iframe> per chapter via srcdoc),
Chakra Petch embedded as base64 data-URI fonts so it renders correctly with
no internet access at all. Run patch_dark.py first (this reads its
dark_offline_src/ output, not dark_print_src/ - <details> stays naturally
collapsed here, since this is meant to be clicked through, unlike the PDFs).
"""
import os, re, json, base64

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OFFLINE_SRC = os.path.join(SCRIPT_DIR, "_build", "dark_offline_src")
FONTS_DIR = os.path.join(SCRIPT_DIR, "fonts")
OUT_PATH = os.path.join(SCRIPT_DIR, "_build", "VulnHunter_Documentation_Offline.html")

# (filename, sidebar title, sidebar icon, sidebar group - None for no group label)
CHAPTERS = [
    ("hub.html", "VulnHunter Documentation", "🧭", None),
    ("executive-brief.html", "Solution Brief", "🎯", "For enterprise evaluators"),
    ("whitepaper.html", "The Governed Remediation Thesis", "🔬", "For enterprise evaluators"),
    ("architecture.html", "Architecture & Schema Reference", "🏗️", "Technical reference"),
    ("vuln-engine.html", "Vulnerability Finding Engine", "🔍", "Technical reference"),
    ("remediation-engine.html", "Remediation Engine & Workflows", "🛠️", "Technical reference"),
    ("connectors.html", "Connectors & Adaptors Catalog", "🔌", "Technical reference"),
    ("rbac-governance.html", "RBAC, Multi-Tenancy & Governance", "🔐", "Technical reference"),
    ("ai-capabilities.html", "AI Capabilities & Guardrails", "🤖", "Technical reference"),
    ("reporting.html", "Reporting & Scheduled Delivery", "📊", "Technical reference"),
    ("pages.html", "Page-by-Page Reference", "🗺️", "Technical reference"),
    ("developer-guide.html", "Developer Guide", "🧩", "Technical reference"),
    ("poc-methodology.html", "Proof-of-Concept Methodology", "🧪", "Business planning"),
    ("pricing.html", "VulnHunter Pricing", "💠", "Business planning"),
    ("user-guide.html", "User & Operations Guide", "📖", "For everyday users"),
]

# Only 3 weights embedded (not all 6 available in fonts/) to keep the file
# size reasonable - each weight gets duplicated once per chapter iframe plus
# once in the shell, since CSS @font-face never crosses a document/iframe
# boundary even for a same-origin srcdoc frame.
FONT_FILES = {
    "400": "ChakraPetch-Regular.ttf",
    "600": "ChakraPetch-SemiBold.ttf",
    "700": "ChakraPetch-Bold.ttf",
}


def font_face_css():
    faces = []
    for weight, fname in FONT_FILES.items():
        with open(os.path.join(FONTS_DIR, fname), "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        faces.append(
            f"@font-face{{font-family:'Chakra Petch';font-weight:{weight};"
            f"src:url(data:font/ttf;base64,{b64}) format('truetype');font-display:swap;}}"
        )
    return "<style>" + "".join(faces) + "</style>"


GFONT_IMPORT_RE = re.compile(r"<style>\s*@import url\('https://fonts\.googleapis\.com[^']*'\);")


def main():
    font_css = font_face_css()
    print(f"Font CSS block: {len(font_css)/1024:.0f} KB")

    chapters_data = {}
    for fname, title, icon, group in CHAPTERS:
        with open(os.path.join(OFFLINE_SRC, fname), encoding="utf-8") as f:
            html = f.read()
        # Swap the network Google-Fonts @import for the embedded offline
        # font-face block, so each iframe document is independently
        # offline-capable.
        if GFONT_IMPORT_RE.search(html):
            html = GFONT_IMPORT_RE.sub("<style>", html, count=1)
        html = font_css + html
        chapters_data[fname] = html
        print(f"{fname}: {len(html)/1024:.0f} KB embedded")

    chapters_json = json.dumps(chapters_data)
    # A literal "</script" inside the JSON string data would make the HTML
    # parser close THIS <script> tag early (it doesn't know the text is
    # inside a JS string) - escape it so the tag boundary can't be found
    # inside the payload. "<\/script" is still valid JSON (an
    # unnecessary-but-legal backslash-escape of "/") and decodes back to the
    # exact original text.
    chapters_json = re.sub(r"</script", "<\\/script", chapters_json, flags=re.IGNORECASE)
    print(f"\nTotal chapters payload: {len(chapters_json)/1024/1024:.2f} MB")

    nav_groups = []
    current_group = None
    group_items = []
    for fname, title, icon, group in CHAPTERS:
        if group != current_group:
            if current_group is not None or group_items:
                nav_groups.append((current_group, group_items))
            current_group = group
            group_items = []
        group_items.append((fname, title, icon))
    nav_groups.append((current_group, group_items))

    nav_html_parts = []
    for group, items in nav_groups:
        if group:
            nav_html_parts.append(f'<div class="navgroup-label">{group}</div>')
        for fname, title, icon in items:
            nav_html_parts.append(
                f'<button class="navitem" data-doc="{fname}" onclick="selectChapter(\'{fname}\')">'
                f'<span class="navicon">{icon}</span><span>{title}</span></button>'
            )
    nav_html = "\n".join(nav_html_parts)

    shell = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnHunter Documentation - Offline</title>
{font_css}
<style>
  :root {{
    --ink: #eef1fb; --paper: #0a0e1a; --surface: #10172a; --surface-2: #151d35;
    --line: #263153; --muted: #97a2c2; --accent: #6d97f7; --accent-deep: #a9c2fb;
    --accent-soft: #16204a;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; height: 100%; background: var(--paper); color: var(--ink);
    font-family: 'Chakra Petch', ui-sans-serif, system-ui, sans-serif; }}
  #shell {{ display: flex; height: 100vh; }}
  #sidebar {{ width: 300px; flex: 0 0 auto; background: #060a16; border-right: 1px solid var(--line);
    display: flex; flex-direction: column; overflow-y: auto; }}
  #sidebar-header {{ padding: 20px 18px 14px; border-bottom: 1px solid var(--line); }}
  #sidebar-header .mark {{ display: flex; align-items: center; gap: 8px; font-weight: 700;
    color: #fff; font-size: 1.05rem; letter-spacing: 0.01em; }}
  #sidebar-header .hexicon {{ width: 20px; height: 20px; flex: none; }}
  #sidebar-header .tagline {{ color: var(--muted); font-size: 0.75rem; margin-top: 6px; }}
  #offline-badge {{ display: inline-block; margin-top: 10px; font-size: 0.68rem; font-weight: 600;
    letter-spacing: 0.05em; text-transform: uppercase; color: #34d399; background: rgba(52,211,153,0.12);
    border: 1px solid rgba(52,211,153,0.35); border-radius: 20px; padding: 3px 10px; }}
  nav {{ flex: 1; padding: 10px 10px 20px; }}
  .navgroup-label {{ font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--muted); margin: 18px 10px 6px; }}
  .navitem {{ display: flex; align-items: center; gap: 10px; width: 100%; text-align: left;
    background: transparent; border: none; color: var(--ink); font-family: inherit; font-size: 0.88rem;
    padding: 9px 10px; border-radius: 8px; cursor: pointer; }}
  .navitem:hover {{ background: var(--surface); }}
  .navitem.active {{ background: var(--accent-soft); color: var(--accent-deep); font-weight: 600; }}
  .navicon {{ font-size: 1rem; width: 20px; text-align: center; flex: none; }}
  #main {{ flex: 1; display: flex; flex-direction: column; min-width: 0; }}
  #topbar {{ display: flex; align-items: center; gap: 10px; padding: 10px 20px; border-bottom: 1px solid var(--line);
    color: var(--muted); font-size: 0.82rem; flex: none; }}
  #topbar .doctitle {{ color: var(--ink); font-weight: 600; }}
  #viewer {{ flex: 1; border: none; width: 100%; background: var(--paper); }}
  #sidebar::-webkit-scrollbar {{ width: 8px; }}
  #sidebar::-webkit-scrollbar-thumb {{ background: var(--line); border-radius: 4px; }}
</style>
</head>
<body>
<div id="shell">
  <div id="sidebar">
    <div id="sidebar-header">
      <div class="mark">
        <svg class="hexicon" viewBox="0 0 24 24" fill="none"><path d="M12 2l8.66 5v10L12 22l-8.66-5V7z" stroke="#6d97f7" stroke-width="1.6"/><circle cx="12" cy="12" r="3" fill="#6d97f7"/></svg>
        VulnHunter
      </div>
      <div class="tagline">Enterprise Documentation Suite</div>
      <span id="offline-badge">Offline copy - no network needed</span>
    </div>
    <nav>
      {nav_html}
    </nav>
  </div>
  <div id="main">
    <div id="topbar">
      <span>Viewing:</span> <span class="doctitle" id="doctitle">VulnHunter Documentation</span>
    </div>
    <iframe id="viewer" title="Document viewer"></iframe>
  </div>
</div>
<script id="chapters-data" type="application/json">{chapters_json}</script>
<script>
  const CHAPTERS = JSON.parse(document.getElementById('chapters-data').textContent);
  const TITLES = {json.dumps({fname: title for fname, title, icon, group in CHAPTERS})};

  function selectChapter(fname) {{
    document.getElementById('viewer').srcdoc = CHAPTERS[fname];
    document.getElementById('doctitle').textContent = TITLES[fname];
    document.querySelectorAll('.navitem').forEach(el => {{
      el.classList.toggle('active', el.getAttribute('data-doc') === fname);
    }});
    try {{ localStorage.setItem('vh-doc-last', fname); }} catch (e) {{}}
  }}

  let start = 'hub.html';
  try {{
    const saved = localStorage.getItem('vh-doc-last');
    if (saved && CHAPTERS[saved]) start = saved;
  }} catch (e) {{}}
  selectChapter(start);
</script>
</body>
</html>
"""

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write(shell)

    size_mb = os.path.getsize(OUT_PATH) / 1024 / 1024
    print(f"\nWritten: {OUT_PATH} ({size_mb:.2f} MB)")


if __name__ == "__main__":
    main()
