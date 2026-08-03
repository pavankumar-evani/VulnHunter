"""
Generic, vendor-agnostic ingestion adapter - the "bring your own XDR/EDR/SIEM" path.

Tenable/Armis/ServiceNow each get a bespoke connector because each has a real,
documented, vendor-specific API contract to build against (auth flow, pagination,
field names - see tenable_connector.py / armis_connector.py). Building one more bespoke
connector per additional named product (Qualys, Splunk, Microsoft Sentinel, CrowdStrike,
Defender, ...) without real API access to any of them would mean shipping code that
looks plausible but was never verified against anything real - the opposite of what this
project tries to do everywhere else (see remediation/connectors/README.md's "built vs.
verified" distinction).

Instead: almost every modern SIEM/XDR/EDR/SOAR tool supports sending a **custom outbound
webhook** with a JSON body you control the shape of. This module is the receiving side
of that: validate an inbound JSON payload against a documented minimal shape, and
normalize it into the same Finding schema every other source uses (see
remediation/schema/normalized-finding-schema.md). One real, generic, testable adapter
that any tool can plug into today, instead of N fabricated vendor-specific ones.

This is genuinely one-directional and push-based (the outside tool sends data in),
unlike Tenable/Armis (VulnHunter pulls, using that vendor's auth). That's a deliberate,
honest design choice, not a limitation of what could be built - see the module-level
note in dashboard/app.py's /api/ingest/generic route for how this gets exposed.
"""
import datetime
import re

REQUIRED_FIELDS = ("title", "severity", "asset_name", "asset_type")
VALID_SEVERITIES = ("Critical", "High", "Medium", "Low")
VALID_ASSET_TYPES = (
    "windows-server", "windows-endpoint", "unix-server", "network-routing-switching",
    "network-security-device", "iot-ot-device", "application", "certificate",
)
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def validate_generic_payload(payload):
    """Returns a list of human-readable error strings (empty list means valid). Never
    raises - callers (the API route) decide how to surface these."""
    errors = []
    if not isinstance(payload, dict):
        return ["payload must be a JSON object"]

    for field in REQUIRED_FIELDS:
        if not payload.get(field):
            errors.append(f"'{field}' is required")

    severity = payload.get("severity")
    if severity and severity not in VALID_SEVERITIES:
        errors.append(f"'severity' must be one of {VALID_SEVERITIES}, got {severity!r}")

    asset_type = payload.get("asset_type")
    if asset_type and asset_type not in VALID_ASSET_TYPES:
        errors.append(f"'asset_type' must be one of {VALID_ASSET_TYPES}, got {asset_type!r}")

    cve = payload.get("cve")
    if cve is not None and not _CVE_PATTERN.match(cve):
        errors.append(f"'cve', if provided, must look like CVE-YYYY-NNNN, got {cve!r}")

    return errors


def _next_finding_id(existing_findings):
    existing = [int(f["id"].split("-")[1]) for f in existing_findings if f.get("id", "").startswith("FIND-")]
    return f"FIND-{max(existing, default=0) + 1}"


def normalize_generic_finding(payload, existing_findings, source_name="generic", as_of=None):
    """Maps a validated generic payload into VulnHunter's normalized Finding schema.
    Caller must run validate_generic_payload() first - this does not re-validate.
    Assigns the next stable/incremental FIND-N id the same way
    vuln-ingest-normalizer.md documents (never renumbers existing findings)."""
    as_of = as_of or datetime.date.today()
    today = as_of.isoformat()

    return {
        "id": _next_finding_id(existing_findings),
        "source": source_name,
        "source_ref": payload.get("source_ref", ""),
        "asset": {
            "name": payload["asset_name"],
            "ip": payload.get("asset_ip"),
            "type": payload["asset_type"],
            "os": payload.get("asset_os"),
        },
        "title": payload["title"],
        "cve": payload.get("cve"),
        "cvss": payload.get("cvss"),
        "severity": payload["severity"],
        "description": payload.get("description", ""),
        "recommended_fix": payload.get("recommended_fix", ""),
        "remediation_domain": None,
        "first_seen": payload.get("first_seen", today),
        "last_seen": payload.get("last_seen", today),
        "kev": None,
        "epss": None,
    }
