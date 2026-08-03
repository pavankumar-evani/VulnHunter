"""
Finding-category taxonomy: classifies each /remediate-pipeline finding by the
vulnerability-management methodology that actually produced it, not just its raw
asset type - Infrastructure Vulnerability Management (Tenable/Armis-style asset
scanning), Software Composition Analysis (a vulnerable bundled/third-party library),
or Certificate/TLS Lifecycle Management.

Static Application Security Testing (SAST) is /vulnhunt's own category by definition -
those findings live in a fully separate data path (see dashboard/data.py's
load_vulnhunt_data(), which reads SECURITY_REPORT.md via git history, not
normalized-findings.json) and are already implicitly SAST; this module doesn't
re-tag them.

Dynamic Application Security Testing (DAST) is a real, supported category in this
taxonomy (SCAN_TYPES below) but has **no sample finding in this repo's demo data
yet** - a DAST scanner (OWASP ZAP, Burp Suite Enterprise, etc.) would feed findings
through the same connector pattern Tenable/Armis already use, once one is wired up.
Listed here for completeness, not faked with a fabricated finding just to fill the
category.

"Code coverage" (a test-suite quality metric - % of code exercised by tests) is a
different kind of measurement entirely, not a vulnerability category, and isn't
represented here or anywhere in this taxonomy.

Classification is intentionally simple and honest: it's a lookup against
`asset.type`, not a claim that Tenable/Armis/etc. themselves report a scan
methodology - they don't. VulnHunter infers it from what kind of asset the finding is
against.
"""

SCAN_TYPES = ("infra-vm", "sca", "cert-mgmt", "sast", "dast")

SCAN_TYPE_LABELS = {
    "infra-vm": "Infrastructure Vulnerability Management",
    "sca": "Software Composition Analysis (SCA)",
    "cert-mgmt": "Certificate & TLS Lifecycle Management",
    "sast": "Static Application Security Testing (SAST)",
    "dast": "Dynamic Application Security Testing (DAST)",
}

_ASSET_TYPE_TO_SCAN_TYPE = {
    "certificate": "cert-mgmt",
    "application": "sca",
}
_DEFAULT_SCAN_TYPE = "infra-vm"


def classify_finding(finding):
    """Returns one of SCAN_TYPES for a single /remediate-pipeline finding, based on
    asset.type. A finding against an `application` asset is treated as SCA (a
    vulnerable bundled library, e.g. Log4Shell) rather than SAST, since /remediate
    ingests third-party scan/asset data, not VulnHunter's own source-code analysis -
    that's the fully separate /vulnhunt pipeline."""
    asset_type = (finding.get("asset") or {}).get("type", "")
    return _ASSET_TYPE_TO_SCAN_TYPE.get(asset_type, _DEFAULT_SCAN_TYPE)


def tag_scan_types(findings):
    """Returns a new list (doesn't mutate input) with `scan_type` and
    `scan_type_label` fields added to every finding - same immutable-tagging pattern
    as attack_mapping.tag_findings."""
    tagged = []
    for f in findings:
        f = dict(f)
        scan_type = classify_finding(f)
        f["scan_type"] = scan_type
        f["scan_type_label"] = SCAN_TYPE_LABELS[scan_type]
        tagged.append(f)
    return tagged
