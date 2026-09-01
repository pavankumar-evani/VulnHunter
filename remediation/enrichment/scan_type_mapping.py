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

Three more real methodologies, added alongside the IaC/GitHub-GitLab/runtime finding
categories: `iac` (Infrastructure-as-Code static analysis - Checkov/tfsec-style config-
template scanning, no CVE), `secrets` (repository secret-scanning alerts - CWE-798
hardcoded-credential findings, no CVE), and `runtime` (Falco-style container/host
runtime detection, no CVE). Each is a genuinely distinct methodology from agent-based
infra-vm scanning, same reasoning DAST already got its own bucket for.
"""

SCAN_TYPES = ("infra-vm", "sca", "cert-mgmt", "sast", "dast", "iac", "secrets", "runtime", "ai-ml")

SCAN_TYPE_LABELS = {
    "infra-vm": "Infrastructure Vulnerability Management",
    "sca": "Software Composition Analysis (SCA)",
    "cert-mgmt": "Certificate & TLS Lifecycle Management",
    "sast": "Static Application Security Testing (SAST)",
    "dast": "Dynamic Application Security Testing (DAST)",
    "iac": "Infrastructure-as-Code Security Scanning",
    "secrets": "Secret Scanning (Repository)",
    "runtime": "Runtime / Container Security",
    "ai-ml": "AI/ML Security",
}

_ASSET_TYPE_TO_SCAN_TYPE = {
    "certificate": "cert-mgmt",
    "iac-resource": "iac",
    "container-runtime": "runtime",
    "ai-ml-system": "ai-ml",
}
_DEFAULT_SCAN_TYPE = "infra-vm"


def classify_finding(finding):
    """Returns one of SCAN_TYPES for a single /remediate-pipeline finding, based on
    asset.type (and, for `application`/`code-repository` assets, whether it has a CVE
    - see this module's docstring for why that's the SCA/DAST split for `application`).
    A `code-repository` finding (GitHub/GitLab-style alert) follows the identical
    logic: a Dependabot-style dependency alert has a real CVE (classified `sca`, same
    methodology bucket as any other vulnerable-dependency finding), while a
    secret-scanning alert has none (classified `secrets` - deliberately a distinct
    label from `application`'s DAST bucket, and from /appsec's own SAST-CWE-based
    "Secrets Management" card, which is a fully separate data path - see
    scan_type_mapping's callers in appsec.js)."""
    asset_type = (finding.get("asset") or {}).get("type", "")
    if asset_type == "application":
        return "sca" if finding.get("cve") else "dast"
    if asset_type == "code-repository":
        return "sca" if finding.get("cve") else "secrets"
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
