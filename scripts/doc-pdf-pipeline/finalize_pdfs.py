"""
Stage 3 of the 15-chapter pipeline: rename each raw rendered PDF to a
readable, numbered filename. Run render_docs.ps1 first.

Historically this step also cropped 34pt off the top/bottom of every page to
remove Chrome's injected print header/footer (date+title, url+page-number).
That's no longer necessary - render_docs.ps1's source HTML now sets
@page{margin:0} (see patch_dark.py), which removes the header/footer as a
side effect (there's no margin gutter left for Chrome to draw them in).
CROP_TOP/CROP_BOTTOM are left in place at 0, not deleted, in case a future
Chrome version regresses this and the crop needs reviving.
"""
import os, re
import pypdf

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(SCRIPT_DIR, "_build")
RAW_DIR = os.path.join(BUILD_DIR, "raw_out_dark")
FINAL_DIR = os.path.join(BUILD_DIR, "final_out_dark")

CROP_TOP = 0
CROP_BOTTOM = 0

# (raw filename from render_docs.ps1, human-readable title used for the final filename)
ORDERED = [
    ("01_hub.pdf", "VulnHunter Documentation"),
    ("02_executive-brief.pdf", "VulnHunter Solution Brief"),
    ("03_whitepaper.pdf", "The Governed Remediation Thesis"),
    ("04_architecture.pdf", "Architecture and Schema Reference"),
    ("05_vuln-engine.pdf", "Vulnerability Finding Engine"),
    ("06_remediation-engine.pdf", "Remediation Engine and Workflows"),
    ("07_connectors.pdf", "Connectors and Adaptors Catalog"),
    ("08_rbac-governance.pdf", "RBAC Multi-Tenancy and Governance"),
    ("09_ai-capabilities.pdf", "AI Capabilities and Guardrails"),
    ("10_reporting.pdf", "Reporting and Scheduled Delivery"),
    ("11_pages.pdf", "Page-by-Page Reference"),
    ("12_developer-guide.pdf", "Developer Guide"),
    ("13_poc-methodology.pdf", "Proof-of-Concept Methodology"),
    ("14_pricing.pdf", "VulnHunter Pricing"),
    ("15_user-guide.pdf", "User and Operations Guide"),
]


def slug(title):
    return re.sub(r"\s+", "_", title.strip())


def main():
    os.makedirs(FINAL_DIR, exist_ok=True)
    for i, (raw_name, title) in enumerate(ORDERED, start=1):
        raw_path = os.path.join(RAW_DIR, raw_name)
        reader = pypdf.PdfReader(raw_path)
        writer = pypdf.PdfWriter()
        for page in reader.pages:
            if CROP_TOP or CROP_BOTTOM:
                left, bottom, right, top = [float(v) for v in page.mediabox]
                page.mediabox.lower_left = (left, bottom + CROP_BOTTOM)
                page.mediabox.upper_right = (right, top - CROP_TOP)
                page.cropbox.lower_left = (left, bottom + CROP_BOTTOM)
                page.cropbox.upper_right = (right, top - CROP_TOP)
            writer.add_page(page)
        out_name = f"{i:02d}_{slug(title)}.pdf"
        out_path = os.path.join(FINAL_DIR, out_name)
        with open(out_path, "wb") as f:
            writer.write(f)
        print(f"{raw_name} ({len(reader.pages)} pages) -> {out_name}")


if __name__ == "__main__":
    main()
