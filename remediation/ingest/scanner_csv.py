"""
Deterministic conversion of the scanner-export CSV (Tenable's column set, which the Qualys
and OpenVAS connectors flatten into) into the common Finding schema - the same job
`vuln-ingest-normalizer` does with model judgment, done with explicit rules so a scheduled
sync needs no interactive agent. See remediation/schema/normalized-finding-schema.md.

Informational rows (risk None/Info) are skipped by default: they are not vulnerabilities
and would bury the queue. Rows without a host are skipped and counted, never guessed.
"""
import csv
import datetime
import re
from pathlib import Path

from remediation.ingest.classify import classify

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium", "low": "Low"}
_DATE_FORMATS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%b %d, %Y %H:%M:%S %Z", "%b %d, %Y %H:%M:%S",
                 "%m/%d/%Y", "%m/%d/%Y %H:%M:%S", "%d/%m/%Y")


def _date(value, default):
    value = (value or "").strip()
    if not value:
        return default
    for fmt in _DATE_FORMATS:
        try:
            return datetime.datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            continue
    m = re.match(r"(\d{4}-\d{2}-\d{2})", value)
    return m.group(1) if m else default


def _float(value):
    try:
        return round(float(str(value).strip()), 1)
    except (TypeError, ValueError):
        return None


def _severity(risk, cvss):
    s = _SEVERITY.get((risk or "").strip().lower())
    if s:
        return s
    if cvss is None:
        return None
    return "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low" if cvss > 0 else None


def row_to_finding(row, source, today):
    """One CSV row -> Finding dict (no id yet), or (None, reason) when it is skipped."""
    host = (row.get("Host") or row.get("FQDN") or row.get("IP Address") or "").strip()
    if not host:
        return None, "no-host"
    cvss = _float(row.get("CVSS v3.0 Base Score"))
    severity = _severity(row.get("Risk"), cvss)
    if not severity:
        return None, "informational"
    title = (row.get("Name") or "").strip() or "Untitled finding"
    os_name = (row.get("OS") or "").strip()
    asset_type, domain = classify(os_name, host, title)
    cves = _CVE.findall(row.get("CVE") or "")
    description = (row.get("Synopsis") or "").strip()
    if len(cves) > 1:
        description = (description + f" Also affects: {', '.join(c.upper() for c in cves[1:])}.").strip()
    finding = {
        "source": source,
        "source_ref": (row.get("Plugin ID") or "").strip() or None,
        "asset": {"name": host, "ip": (row.get("IP Address") or "").strip() or None, "type": asset_type, "os": os_name or None},
        "title": title,
        "cve": cves[0].upper() if cves else None,
        "cvss": cvss,
        "severity": severity,
        "description": description,
        "recommended_fix": (row.get("Solution") or "").strip(),
        "remediation_domain": domain,
        "first_seen": _date(row.get("First Discovered"), today),
        "last_seen": _date(row.get("Last Observed"), today),
        "kev": None,
        "epss": None,
    }
    return finding, None


def parse_csv(path, source, today=None, include_informational=False):
    """Returns (findings, skipped) where skipped is {reason: count}."""
    today = today or datetime.date.today().isoformat()
    findings, skipped = [], {}
    with Path(path).open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            finding, reason = row_to_finding(row, source, today)
            if finding is None and reason == "informational" and include_informational:
                continue
            if finding is None:
                skipped[reason] = skipped.get(reason, 0) + 1
            else:
                findings.append(finding)
    return findings, skipped
