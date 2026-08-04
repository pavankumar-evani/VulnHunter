"""
Infrastructure Vulnerability Management sub-classification: splits the single
"infra-vm" scan-type bucket (see scan_type_mapping.py) into the asset-type groupings
a real infra/security team would actually organize around - OS-level patching,
network hardware, network security appliances, OT/IoT devices, and cloud
infrastructure - rather than one flat "Infrastructure Vulnerabilities" list.

Classification is a lookup against `asset.type` (see
remediation/schema/normalized-finding-schema.md for the full vocabulary), the same
simple, honest, non-guessing design as scan_type_mapping.py - not a claim that
Tenable/Armis/etc. themselves report this grouping.

"cloud" is a real, supported category (cloud security posture findings are a
standard part of real vulnerability management - Tenable and Armis both cover
AWS/Azure/GCP asset scanning) but has **no sample finding in this repo's demo data
yet**, same "listed for completeness, not faked" treatment scan_type_mapping.py
already gives DAST.
"""

INFRA_CATEGORIES = ("os", "network", "network-security", "ot", "cloud")

INFRA_CATEGORY_LABELS = {
    "os": "OS Vulnerabilities",
    "network": "Network",
    "network-security": "Network Security",
    "ot": "OT / IoT",
    "cloud": "Cloud Infrastructure",
}

_ASSET_TYPE_TO_INFRA_CATEGORY = {
    "windows-server": "os",
    "windows-endpoint": "os",
    "unix-server": "os",
    "network-routing-switching": "network",
    "network-security-device": "network-security",
    "iot-ot-device": "ot",
    "cloud-infrastructure": "cloud",
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
