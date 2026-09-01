"""
Cloud provider attribution - which major cloud (AWS / Azure / GCP / OCI / Alibaba Cloud)
a `cloud-infrastructure` finding's asset actually runs on, derived from the asset's own
real `os` field (e.g. "Amazon EKS worker node (Amazon Linux 2)", "Azure Kubernetes
Service node", "Oracle Container Engine for Kubernetes (OKE) node").

WHAT THIS IS NOT: a live CSPM (Cloud Security Posture Management) integration - this
app has no real AWS/Azure/GCP/OCI/Alibaba API credentials and doesn't call any cloud
provider's API. The underlying findings are real, NVD-sourced CVEs (see
remediation/sample-data/generate_bulk_findings.py) already present in this app's normal
ingest path; this module only classifies which provider's managed service each one's
asset description names, the same "real-content keyword classification, not an
authoritative source-of-truth" honesty tier as quantum_readiness.py and
attack_mapping.py - this app's schema carries no separate structured `cloud_provider`
field to join against.

Deliberately returns None (not a guess) for a `cloud-infrastructure` asset whose `os`
names a genuinely multi-cloud tool with no single provider - "Terraform-provisioned
cloud resource" or "Kubernetes 1.2x (self-managed cluster node)"/"Docker Engine 24.x"
are real, honestly-unattributed cases, not a gap in this module's keyword list.
"""
import re

_PROVIDER_PATTERNS = [
    ("AWS", re.compile(r"\bAWS\b|\bAmazon\b|\bEKS\b", re.IGNORECASE)),
    ("Azure", re.compile(r"\bAzure\b", re.IGNORECASE)),
    ("GCP", re.compile(r"\bGCP\b|\bGoogle\b|\bGKE\b", re.IGNORECASE)),
    ("OCI", re.compile(r"\bOracle\b|\bOCI\b|\bOKE\b", re.IGNORECASE)),
    ("Alibaba Cloud", re.compile(r"\bAlibaba\b", re.IGNORECASE)),
]


def classify_cloud_provider(finding):
    """Returns one of "AWS"/"Azure"/"GCP"/"OCI"/"Alibaba Cloud", or None when the
    asset isn't `cloud-infrastructure` or its `os` doesn't name a specific provider."""
    asset = finding.get("asset") or {}
    if asset.get("type") != "cloud-infrastructure":
        return None
    os_str = asset.get("os") or ""
    for provider, pattern in _PROVIDER_PATTERNS:
        if pattern.search(os_str):
            return provider
    return None


def tag_cloud_provider(findings):
    """Adds `cloud_provider` to every finding - None when not a cloud-infrastructure
    asset or its provider can't be honestly determined from real content. Returns a
    new list (doesn't mutate the input), same convention as every other tag_*()
    enrichment pass in this package."""
    tagged = []
    for f in findings:
        f = dict(f)
        f["cloud_provider"] = classify_cloud_provider(f)
        tagged.append(f)
    return tagged
