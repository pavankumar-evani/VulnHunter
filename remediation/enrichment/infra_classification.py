"""
Infrastructure Vulnerability Management sub-classification: splits the single
"infra-vm" scan-type bucket (see scan_type_mapping.py) into the asset-type groupings
a real infra/security team would actually organize around - server OS patching,
end-user device management, network hardware, network security appliances, OT/IoT
devices, virtualization/hypervisor platforms, printers, and cloud infrastructure -
rather than one flat "Infrastructure Vulnerabilities" list.

Classification is a lookup against `asset.type` (see
remediation/schema/normalized-finding-schema.md for the full vocabulary), the same
simple, honest, non-guessing design as scan_type_mapping.py - not a claim that
Tenable/Armis/etc. themselves report this grouping.

"cloud" is a real, supported category (cloud security posture findings are a
standard part of real vulnerability management - Tenable and Armis both cover
AWS/Azure/GCP asset scanning) and has real, NVD-sourced sample findings covering
Kubernetes/Docker/container-runtime CVEs plus AWS/Azure/GCP provider-specific service
CVEs (Amazon S3/Lambda/IAM/RDS, Azure AD/Storage, Google Cloud Storage/SDK, etc.) - see
remediation/sample-data/generate_bulk_findings.py's "cloud" category.

"endpoint" (added alongside "os" so `windows-endpoint` moves OUT of the server
bucket) is real, well-established vulnerability-management territory: laptops/
desktops patched via SCCM (Microsoft Configuration Manager) and mobile devices
patched via an MDM platform (e.g. Microsoft Intune) are managed on a genuinely
different patch cycle/tooling than server OS patching - see bulk_normalize.py's
_REMEDIATION_MECHANISM for the honest disclosure that this app has no working
SCCM/Intune API integration, only this informational field naming the real-world
tool that would normally handle it.

"printer" and "virtualization" are likewise real, standard vulnerability-management
categories (networked printer firmware, and hypervisor/VM-platform CVEs - VMware
ESXi/vCenter, Microsoft Hyper-V, Proxmox VE, Citrix Hypervisor all have real,
well-documented CVE histories) that simply didn't have their own bucket before.
"""

INFRA_CATEGORIES = ("os", "endpoint", "network", "network-security", "ot", "virtualization", "cloud", "apps", "printer", "iac", "runtime")

INFRA_CATEGORY_LABELS = {
    "os": "Server Vulnerabilities (Windows, Linux/Unix)",
    "endpoint": "End-User Devices (SCCM/MDM-managed)",
    "network": "Network",
    "network-security": "Network Security",
    "ot": "OT / IoT",
    "virtualization": "Virtualization (Hypervisor/VM Platform)",
    "cloud": "Cloud Infrastructure",
    "apps": "OS Applications",
    "printer": "Printers",
    "iac": "Infrastructure-as-Code",
    "runtime": "Container/Host Runtime Security",
}

_ASSET_TYPE_TO_INFRA_CATEGORY = {
    "windows-server": "os",
    "unix-server": "os",
    "windows-endpoint": "endpoint",
    "mobile-device": "endpoint",
    "network-routing-switching": "network",
    "network-security-device": "network-security",
    "iot-ot-device": "ot",
    "virtualization-host": "virtualization",
    "cloud-infrastructure": "cloud",
    "client-application": "apps",
    "printer": "printer",
    "iac-resource": "iac",
    "container-runtime": "runtime",
}


def classify_infra_finding(finding):
    """Returns one of INFRA_CATEGORIES for a finding whose asset.type is an
    infrastructure type, or None for anything else (application/certificate findings,
    or a finding with no recognized asset.type at all) - this deliberately does NOT
    default to a catch-all bucket the way scan_type_mapping.classify_finding does,
    since "not an infra finding" is a meaningful, real answer here, not a gap to
    paper over."""
    asset_type = (finding.get("asset") or {}).get("type", "")
    return _ASSET_TYPE_TO_INFRA_CATEGORY.get(asset_type)


def tag_infra_categories(findings):
    """Returns a new list (doesn't mutate input) with `infra_category` and
    `infra_category_label` fields added to every finding - `None`/`None` for
    non-infra findings. Same immutable-tagging pattern as scan_type_mapping.tag_scan_types."""
    tagged = []
    for f in findings:
        f = dict(f)
        category = classify_infra_finding(f)
        f["infra_category"] = category
        f["infra_category_label"] = INFRA_CATEGORY_LABELS.get(category)
        tagged.append(f)
    return tagged


def build_infra_category_counts(findings):
    """Returns one row per known INFRA_CATEGORIES entry - including zero-count rows,
    same "show the whole known taxonomy" design as attack_mapping.build_attack_heatmap
    - so the Infrastructure Vulnerabilities hub page can show a Cloud Infrastructure
    card even before any cloud finding exists. `findings` must already carry an
    `infra_category` field (see tag_infra_categories)."""
    counts = {}
    for f in findings:
        category = f.get("infra_category")
        if category:
            counts[category] = counts.get(category, 0) + 1

    return [
        {"id": category, "label": INFRA_CATEGORY_LABELS[category], "count": counts.get(category, 0)}
        for category in INFRA_CATEGORIES
    ]
