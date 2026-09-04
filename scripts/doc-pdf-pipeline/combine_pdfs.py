"""
Stage 4 of the 15-chapter pipeline: merge every finalized chapter PDF into
one combined PDF with a real bookmark outline (grouped by audience, matching
docs/enterprise-suite/hub.html's own grouping). Run finalize_pdfs.py first.
"""
import os
import pypdf

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FINAL_DIR = os.path.join(SCRIPT_DIR, "_build", "final_out_dark")
OUT_PATH = os.path.join(SCRIPT_DIR, "_build", "VulnHunter_Documentation_Complete.pdf")

# (filename in final_out_dark, bookmark title, bookmark group - None for no parent)
ORDERED = [
    ("01_VulnHunter_Documentation.pdf", "VulnHunter Documentation (start here)", None),
    ("02_VulnHunter_Solution_Brief.pdf", "Solution Brief", "For enterprise evaluators"),
    ("03_The_Governed_Remediation_Thesis.pdf", "The Governed Remediation Thesis", "For enterprise evaluators"),
    ("04_Architecture_and_Schema_Reference.pdf", "Architecture & Schema Reference", "Technical reference"),
    ("05_Vulnerability_Finding_Engine.pdf", "Vulnerability Finding Engine", "Technical reference"),
    ("06_Remediation_Engine_and_Workflows.pdf", "Remediation Engine & Workflows", "Technical reference"),
    ("07_Connectors_and_Adaptors_Catalog.pdf", "Connectors & Adaptors Catalog", "Technical reference"),
    ("08_RBAC_Multi-Tenancy_and_Governance.pdf", "RBAC, Multi-Tenancy & Governance", "Technical reference"),
    ("09_AI_Capabilities_and_Guardrails.pdf", "AI Capabilities & Guardrails", "Technical reference"),
    ("10_Reporting_and_Scheduled_Delivery.pdf", "Reporting & Scheduled Delivery", "Technical reference"),
    ("11_Page-by-Page_Reference.pdf", "Page-by-Page Reference", "Technical reference"),
    ("12_Developer_Guide.pdf", "Developer Guide", "Technical reference"),
    ("13_Proof-of-Concept_Methodology.pdf", "Proof-of-Concept Methodology", "Business planning"),
    ("14_VulnHunter_Pricing.pdf", "VulnHunter Pricing", "Business planning"),
    ("15_User_and_Operations_Guide.pdf", "User & Operations Guide", "For everyday users"),
]


def main():
    writer = pypdf.PdfWriter()
    group_bookmarks = {}
    page_cursor = 0

    for fname, title, group in ORDERED:
        reader = pypdf.PdfReader(os.path.join(FINAL_DIR, fname))
        writer.append(reader)

        parent = None
        if group:
            if group not in group_bookmarks:
                group_bookmarks[group] = writer.add_outline_item(group, page_cursor)
            parent = group_bookmarks[group]
        writer.add_outline_item(title, page_cursor, parent=parent)

        page_cursor += len(reader.pages)
        print(f"+ {fname} ({len(reader.pages)} pages) -> '{title}' at page {page_cursor - len(reader.pages) + 1}")

    writer.add_metadata({
        "/Title": "VulnHunter Enterprise Documentation - Complete",
        "/Author": "VulnHunter Development LLC",
    })

    with open(OUT_PATH, "wb") as f:
        writer.write(f)

    print(f"\nTotal pages: {page_cursor}")
    print(f"Written: {OUT_PATH}")


if __name__ == "__main__":
    main()
