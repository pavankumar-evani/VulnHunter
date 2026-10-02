"""
The catalogue of pull connectors that can be stored and synced on a schedule: what each one
needs, how to build it, and how to turn a pull into data for the dashboard.

Every `pull` returns one of:
  {"kind": "findings", "findings": [...], "reconcile": bool, "skipped": {...}}
  {"kind": "assets",   "assets": [...]}
`reconcile` is True only when the pull is a COMPLETE export (see remediation/ingest/merge.py).
Hosts and URLs are checked with the SSRF guard (remediation/connectors/url_safety.py) before a
connector is ever built, at save time and again at run time.

OpenVAS/GVM is not listed: it launches a scan and polls for minutes to hours, so it keeps its
own start / status / import page rather than a scheduled one-shot pull.
"""
import os
import tempfile
from pathlib import Path

from remediation.connectors import url_safety
from remediation.connectors.active_directory_connector import ActiveDirectoryConnector
from remediation.connectors.axonius_connector import AxoniusConnector
from remediation.connectors.cortex_xsiam_connector import CortexXsiamConnector
from remediation.connectors.infoblox_connector import InfobloxConnector
from remediation.connectors.prismacloud_connector import PrismaCloudConnector
from remediation.connectors.qualys_connector import QualysConnector
from remediation.connectors.tenable_connector import TenableConnector
from remediation.ingest import scanner_csv


def _f(name, label, secret=False, required=True, kind="text", placeholder="", help=""):
    return {"name": name, "label": label, "secret": secret, "required": required, "type": kind, "placeholder": placeholder, "help": help}


def _csv_pull(connector, source, reconcile):
    fd, tmp = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    try:
        connector.fetch_and_write_csv(Path(tmp))
        findings, skipped = scanner_csv.parse_csv(tmp, source)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return {"kind": "findings", "findings": findings, "reconcile": reconcile, "skipped": skipped}


def _tenable(c):
    return TenableConnector(c["access_key"], c["secret_key"])


def _qualys(c):
    return QualysConnector(c["username"], c["password"], platform_url=c["platform_url"])


SPECS = {
    "tenable": {
        "label": "Tenable.io", "category": "Vulnerability scanner", "output": "findings",
        "fields": [_f("access_key", "Access key", secret=True), _f("secret_key", "Secret key", secret=True)],
        "docs": "Tenable.io > Settings > My Account > API Keys.",
        "build": _tenable, "pull": lambda c: _csv_pull(_tenable(c), "tenable", reconcile=True),
        "test": lambda c: _tenable(c).test_connection(),
        "note": "A full export: vulnerabilities no longer reported are removed from the queue on each sync.",
    },
    "qualys": {
        "label": "Qualys VMDR", "category": "Vulnerability scanner", "output": "findings",
        "fields": [_f("platform_url", "Platform URL", placeholder="https://qualysapi.qualys.com"), _f("username", "Username"),
                   _f("password", "Password", secret=True)],
        "safe_targets": ["platform_url"], "docs": "Use the API base URL for your Qualys platform/region.",
        "build": _qualys, "pull": lambda c: _csv_pull(_qualys(c), "qualys", reconcile=False),
        "test": lambda c: _qualys(c).test_connection(),
        "note": "Host detections can be truncated for very large tenants, so findings are added and refreshed but never auto-removed.",
    },
    "prismacloud": {
        "label": "Prisma Cloud", "category": "Cloud posture", "output": "findings",
        "fields": [_f("base_url", "API base URL", placeholder="https://api.prismacloud.io"), _f("access_key_id", "Access key ID", secret=True),
                   _f("secret_key", "Secret key", secret=True)],
        "safe_targets": ["base_url"],
        "build": lambda c: PrismaCloudConnector(c["access_key_id"], c["secret_key"], base_url=c["base_url"]),
        "pull": lambda c: {"kind": "findings", "findings": PrismaCloudConnector(c["access_key_id"], c["secret_key"], base_url=c["base_url"]).fetch_and_normalize_alerts(),
                           "reconcile": False, "skipped": {}},
        "test": lambda c: PrismaCloudConnector(c["access_key_id"], c["secret_key"], base_url=c["base_url"]).test_connection(),
    },
    "cortex-xsiam": {
        "label": "Cortex XSIAM", "category": "Detection and response", "output": "findings",
        "fields": [_f("base_url", "API base URL"), _f("api_key_id", "API key ID", secret=True), _f("api_key", "API key", secret=True)],
        "safe_targets": ["base_url"],
        "build": lambda c: CortexXsiamConnector(c["api_key"], c["api_key_id"], base_url=c["base_url"]),
        "pull": lambda c: {"kind": "findings", "findings": CortexXsiamConnector(c["api_key"], c["api_key_id"], base_url=c["base_url"]).fetch_and_normalize_incidents(),
                           "reconcile": False, "skipped": {}},
        "test": lambda c: CortexXsiamConnector(c["api_key"], c["api_key_id"], base_url=c["base_url"]).test_connection(),
    },
    "infoblox": {
        "label": "Infoblox", "category": "Asset discovery", "output": "assets",
        "fields": [_f("grid_master", "Grid master host"), _f("username", "Username"), _f("password", "Password", secret=True)],
        "safe_targets": ["grid_master"],
        "build": lambda c: InfobloxConnector(c["grid_master"], c["username"], c["password"]),
        "pull": lambda c: {"kind": "assets", "assets": InfobloxConnector(c["grid_master"], c["username"], c["password"]).fetch_and_normalize_hosts()},
        "test": lambda c: InfobloxConnector(c["grid_master"], c["username"], c["password"]).test_connection(),
    },
    "axonius": {
        "label": "Axonius", "category": "Asset discovery", "output": "assets",
        "fields": [_f("base_url", "Base URL"), _f("api_key", "API key", secret=True), _f("api_secret", "API secret", secret=True)],
        "safe_targets": ["base_url"],
        "build": lambda c: AxoniusConnector(c["base_url"], c["api_key"], c["api_secret"]),
        "pull": lambda c: {"kind": "assets", "assets": AxoniusConnector(c["base_url"], c["api_key"], c["api_secret"]).fetch_and_normalize_devices()},
        "test": lambda c: AxoniusConnector(c["base_url"], c["api_key"], c["api_secret"]).test_connection(),
    },
    "active-directory": {
        "label": "Active Directory", "category": "Asset discovery", "output": "assets",
        "fields": [_f("server", "Server"), _f("base_dn", "Base DN"), _f("bind_dn", "Bind DN", required=False),
                   _f("bind_password", "Bind password", secret=True, required=False), _f("use_ssl", "Use LDAPS", required=False, kind="checkbox")],
        "safe_targets": ["server"],
        "build": lambda c: ActiveDirectoryConnector(c["server"], c["base_dn"], bind_dn=c.get("bind_dn") or None,
                                                    bind_password=c.get("bind_password") or None, use_ssl=bool(c.get("use_ssl"))),
        "pull": lambda c: {"kind": "assets", "assets": ActiveDirectoryConnector(c["server"], c["base_dn"], bind_dn=c.get("bind_dn") or None,
                                                                                bind_password=c.get("bind_password") or None, use_ssl=bool(c.get("use_ssl"))).fetch_and_normalize_computers()},
        "test": lambda c: ActiveDirectoryConnector(c["server"], c["base_dn"], bind_dn=c.get("bind_dn") or None,
                                                   bind_password=c.get("bind_password") or None, use_ssl=bool(c.get("use_ssl"))).test_connection(),
    },
}


def public_catalog():
    """What the UI needs: the types and their fields, never the callables."""
    return [{"type": t, **{k: v for k, v in s.items() if k in ("label", "category", "output", "fields", "docs", "note")}} for t, s in SPECS.items()]


def split_values(conn_type, values):
    """Splits submitted field values into (config, secrets) per the spec; validates required
    fields and the SSRF guard. Raises ValueError with a readable message."""
    spec = SPECS.get(conn_type)
    if not spec:
        raise ValueError(f"Unknown connector type {conn_type!r}")
    config, secrets = {}, {}
    for f in spec["fields"]:
        v = values.get(f["name"])
        if f["type"] == "checkbox":
            v = bool(v)
        elif isinstance(v, str):
            v = v.strip()
        if f["required"] and (v is None or v == ""):
            raise ValueError(f"{f['label']} is required")
        if v in (None, ""):
            continue
        (secrets if f["secret"] else config)[f["name"]] = v
    for name in spec.get("safe_targets", []):
        target = config.get(name)
        if target:
            try:
                url_safety.assert_safe_target(target)
            except url_safety.UnsafeTargetError as exc:
                raise ValueError(f"{name}: {exc}") from exc
    return config, secrets
