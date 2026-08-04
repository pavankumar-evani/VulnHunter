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
taxonomy (SCAN_TYPES below). A finding against an `application` asset is classified as
DAST rather than SCA when it has no `cve` - a genuinely real, industry-standard
distinguishing signal: SCA findings say "this specific CVE-numbered vulnerable
dependency version is present" (there's a CVE because it's about a versioned,
publicly-tracked component), while DAST findings say "this class of vulnerability was
found by actively probing the running application" (an app-specific reflected-XSS or
IDOR bug has no CVE - it's not a versioned, shared component anyone else could look up).
A DAST scanner (OWASP ZAP, Burp Suite Enterprise, etc.) would feed findings through the
same connector pattern Tenable/Armis already use.

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
}
_DEFAULT_SCAN_TYPE = "infra-vm"


def classify_finding(finding):
    """Returns one of SCAN_TYPES for a single /remediate-pipeline finding, based on
    asset.type (and, for `application` assets only, whether it has a CVE - see this
    module's docstring for why that's the SCA/DAST split). A finding against an
    `application` asset is SCA or DAST rather than SAST, since /remediate ingests
    third-party scan/asset data, not VulnHunter's own source-code analysis - that's the
    fully separate /vulnhunt pipeline."""
    asset_type = (finding.get("asset") or {}).get("type", "")
    if asset_type == "application":
        return "sca" if finding.get("cve") else "dast"
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
