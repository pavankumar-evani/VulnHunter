"""
Validation and normalisation of findings pushed to Quanta over the ingest API
(`POST /api/ingest/findings`), by a scanner, SOAR playbook, CI job or custom collector.

The contract is deliberately small: the five fields below are required or strongly
recommended, everything else is optional, and anything Quanta can derive (asset type,
remediation domain, dates) it derives. Unknown extra fields are ignored rather than rejected,
so a sender can add its own metadata without breaking.

Required: `title`, `severity` (Critical | High | Medium | Low, any case), `asset.name`.
Useful:   `cve`, `cvss`, `asset.ip`, `asset.os`, `source_ref` (the sender's own id for the
          finding, which is what makes a re-send update the same finding instead of adding a
          duplicate), `description`, `recommended_fix`, `first_seen`, `last_seen`.
"""
import datetime
import re

from remediation.ingest.classify import classify

SEVERITIES = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium", "low": "Low"}
KNOWN_TYPES = {
    "windows-server", "windows-endpoint", "unix-server", "unix-endpoint", "network-routing-switching", "network-security-device",
    "iot-ot-device", "virtualization-host", "cloud-infrastructure", "application", "certificate", "client-application",
    "mobile-device", "printer", "iac-resource", "code-repository", "container-runtime", "ai-ml-system", "unknown",
}
FIXER_DOMAINS = {"windows-server", "unix-server", "iot-ot-device", "application"}
SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,39}$")
MAX_BATCH = 5000
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def check_source(source):
    if not SOURCE_RE.match(source or ""):
        raise ValueError("source must be 2 to 40 characters: lowercase letters, digits and hyphens")
    return source


SCAN_TYPES = ("sast", "dast", "sca", "secrets", "iac", "container", "cicd", "coverage", "infra-vm", "runtime", "cert-mgmt", "ai-ml")


def _optional_fields(item):
    """Optional fields a scanner-aware sender may add: scan_type, location, cwe, rule_id, tool, suggested_patch, dependency."""
    out = {}
    st = item.get("scan_type")
    if st not in (None, ""):
        if st not in SCAN_TYPES:
            raise ValueError(f"scan_type must be one of {', '.join(SCAN_TYPES)}")
        out["scan_type"] = st
    loc = item.get("location")
    if isinstance(loc, dict):
        out["location"] = {"file": str(loc.get("file") or "")[:500] or None, "line": loc.get("line") if isinstance(loc.get("line"), int) else None,
                           "end_line": loc.get("end_line") if isinstance(loc.get("end_line"), int) else None,
                           "url": str(loc.get("url") or "")[:500] or None, "snippet": str(loc.get("snippet") or "")[:500] or None}
    cwe = item.get("cwe")
    if cwe:
        out["cwe"] = [c for c in (cwe if isinstance(cwe, list) else [cwe]) if re.match(r"^CWE-\d+$", str(c), re.I)][:6]
        out["cwe"] = [str(c).upper() for c in out["cwe"]]
    for k in ("rule_id", "tool"):
        if item.get(k):
            out[k] = str(item[k])[:200]
    if item.get("suggested_patch"):
        out["suggested_patch"] = str(item["suggested_patch"])[:6000]
    if isinstance(item.get("dependency"), dict):
        out["dependency"] = {k: item["dependency"].get(k) for k in ("package", "ecosystem", "version", "fixed_version", "direct")}
    return out


def normalise(item, today=None):
    """One incoming finding (a dict) -> a Finding-schema dict without an id. Raises ValueError
    with a message naming the problem."""
    today = today or datetime.date.today().isoformat()
    title = str(item.get("title") or "").strip()
    if not title:
        raise ValueError("title is required")
    if len(title) > 300:
        raise ValueError("title must be at most 300 characters")
    severity = SEVERITIES.get(str(item.get("severity") or "").strip().lower())
    if not severity:
        raise ValueError("severity must be Critical, High, Medium or Low")
    asset = item.get("asset") or {}
    name = str(asset.get("name") or "").strip()
    if not name:
        raise ValueError("asset.name is required")
    if len(name) > 255:
        raise ValueError("asset.name must be at most 255 characters")
    cve = str(item.get("cve") or "").strip().upper() or None
    if cve and not _CVE.match(cve):
        raise ValueError(f"cve {cve!r} is not a valid CVE id")
    cvss = item.get("cvss")
    if cvss is not None:
        try:
            cvss = round(float(cvss), 1)
        except (TypeError, ValueError):
            raise ValueError("cvss must be a number") from None
        if not 0 <= cvss <= 10:
            raise ValueError("cvss must be between 0 and 10")
    os_name = str(asset.get("os") or "").strip() or None
    declared = str(asset.get("type") or "").strip().lower()
    if declared in KNOWN_TYPES and declared != "unknown":
        asset_type = declared
    else:
        asset_type, _ = classify(os_name or "", name, title)
    for field in ("first_seen", "last_seen"):
        v = item.get(field)
        if v and not _DATE.match(str(v)):
            raise ValueError(f"{field} must start with a date like 2026-09-01")
    extra = _optional_fields(item)
    return {
        **extra,
        "source_ref": str(item.get("source_ref")).strip() if item.get("source_ref") not in (None, "") else None,
        "asset": {"name": name, "ip": str(asset.get("ip") or "").strip() or None, "type": asset_type, "os": os_name},
        "title": title, "cve": cve, "cvss": cvss, "severity": severity,
        "description": str(item.get("description") or "").strip(),
        "recommended_fix": str(item.get("recommended_fix") or "").strip(),
        "remediation_domain": asset_type if asset_type in FIXER_DOMAINS else None,
        "first_seen": str(item.get("first_seen"))[:10] if item.get("first_seen") else today,
        "last_seen": str(item.get("last_seen"))[:10] if item.get("last_seen") else today,
        "kev": None, "epss": None,
    }


def normalise_batch(items, today=None):
    """Returns (findings, errors) where errors is [{index, error}] - one bad record never
    rejects the whole batch."""
    if len(items) > MAX_BATCH:
        raise ValueError(f"At most {MAX_BATCH} findings per request")
    good, errors = [], []
    for i, item in enumerate(items):
        try:
            good.append(normalise(item, today))
        except ValueError as exc:
            errors.append({"index": i, "error": str(exc)})
    return good, errors
