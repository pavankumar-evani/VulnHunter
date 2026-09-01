"""
Asset inventory: aggregates the asset data already scattered across individual
findings (remediation/output/normalized-findings.json) into one row per unique asset -
finding count, highest severity, KEV exposure - plus an editable owner/team, since
"who owns this asset" is real operational metadata no vendor scan ever reports.

Ownership is a single local JSON file (remediation/inventory/asset_ownership.json),
committed and seeded with a couple of realistic examples - the same real-editable-config
pattern as remediation/config/priority_rules.yaml and remediation/exceptions/
exceptions.json, not a database or a real CMDB integration. A production version would
sync ownership from a real CMDB/asset-management system rather than a flat file edited
by hand; this is the honest MVP version of that idea (see KNOWLEDGE_TRANSFER.md).
"""
import json
from pathlib import Path

from remediation.audit.activity_log import record_activity
from remediation.enrichment.eol_lookup import classify_eol
from remediation.inventory import pattern_recognition

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OWNERSHIP_PATH = Path(__file__).resolve().parent / "asset_ownership.json"

_SEVERITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}

# An asset's internet/internal-facing exposure is real operational knowledge no vendor
# scan reliably reports on its own - this is a manually-set, editable classification
# (same file/pattern as owner/team), NOT derived from any network scan or auto-detection.
# "unknown" is the honest default until someone actually sets it - never guessed.
VALID_FACING_VALUES = ("external", "internal", "unknown")
DEFAULT_FACING = "unknown"

# Same manually-set, never-guessed convention as facing above - lets the remediation
# policy engine (remediation/config/remediation_policy_engine.py) apply a distinct
# auto-remediate/no-approval-needed policy to non-production assets. "unknown" (not
# "prod") is the honest default until someone actually tags an asset - this app has no
# way to infer environment from a hostname or scan result reliably.
VALID_ENVIRONMENT_VALUES = ("prod", "staging", "dev", "unknown")
DEFAULT_ENVIRONMENT = "unknown"

# Same string-enum convention remediation_policy.yaml's own per-domain `cadence` field
# already uses (see that file's header comment) - an asset-level override is meant to be
# directly interchangeable with a domain's default, not a second, incompatible
# representation ("every N days") of the same real concept.
VALID_CADENCE_VALUES = ("weekly", "monthly", "quarterly", "half-yearly", "yearly", "on-demand")


def load_ownership(path=None):
    # Resolved inside the body (not as a bound default parameter) so that patching
    # DEFAULT_OWNERSHIP_PATH in tests actually takes effect for every caller that omits
    # `path` - a bound default is captured once at function-definition time and is
    # immune to patching afterwards (same gotcha as remediation/exceptions/store.py).
    path = Path(path) if path is not None else DEFAULT_OWNERSHIP_PATH
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def save_ownership(ownership, path=None):
    path = Path(path) if path is not None else DEFAULT_OWNERSHIP_PATH
    path.write_text(json.dumps(ownership, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def set_owner(asset_name, owner, team, actor=None, path=None):
    if not asset_name:
        raise ValueError("asset_name is required")
    ownership = load_ownership(path)
    # setdefault (not a fresh dict) so this doesn't wipe out a facing classification
    # already set on this asset - owner/team and facing are edited independently.
    entry = ownership.setdefault(asset_name, {})
    entry["owner"] = owner or ""
    entry["team"] = team or ""
    save_ownership(ownership, path)
    record_activity(actor, "asset.set_owner", asset_name, {"owner": entry["owner"], "team": entry["team"]})
    return entry


def set_facing(asset_name, facing, actor=None, path=None):
    if not asset_name:
        raise ValueError("asset_name is required")
    if facing not in VALID_FACING_VALUES:
        raise ValueError(f"facing must be one of {VALID_FACING_VALUES}, got {facing!r}")
    ownership = load_ownership(path)
    entry = ownership.setdefault(asset_name, {})
    entry["facing"] = facing
    save_ownership(ownership, path)
    record_activity(actor, "asset.set_facing", asset_name, {"facing": facing})
    return entry


def set_environment(asset_name, environment, actor=None, path=None):
    if not asset_name:
        raise ValueError("asset_name is required")
    if environment not in VALID_ENVIRONMENT_VALUES:
        raise ValueError(f"environment must be one of {VALID_ENVIRONMENT_VALUES}, got {environment!r}")
    ownership = load_ownership(path)
    entry = ownership.setdefault(asset_name, {})
    entry["environment"] = environment
    save_ownership(ownership, path)
    record_activity(actor, "asset.set_environment", asset_name, {"environment": environment})
    return entry


def set_remediation_schedule(asset_name, cadence=None, maintenance_window=None, actor=None, path=None):
    """Per-asset remediation-schedule override - checked by
    remediation/config/remediation_policy_engine.py's policy_for_finding() before it
    falls back to the finding's remediation_domain's own default cadence/maintenance
    window (same override-precedence pattern already proven for environment=='dev').
    `cadence` uses the same string enum as a domain's own cadence field (see
    VALID_CADENCE_VALUES) - never a second, incompatible representation of the same
    concept. Pass cadence=None and maintenance_window=None to clear an existing
    override and revert the asset to its domain's default schedule."""
    if not asset_name:
        raise ValueError("asset_name is required")
    if cadence is not None and cadence not in VALID_CADENCE_VALUES:
        raise ValueError(f"cadence must be one of {VALID_CADENCE_VALUES} or None, got {cadence!r}")
    ownership = load_ownership(path)
    entry = ownership.setdefault(asset_name, {})
    if cadence is None and maintenance_window is None:
        entry.pop("remediation_schedule", None)
    else:
        entry["remediation_schedule"] = {"cadence": cadence, "maintenance_window": maintenance_window}
    save_ownership(ownership, path)
    record_activity(actor, "asset.set_remediation_schedule", asset_name, entry.get("remediation_schedule"))
    return entry


def set_network_info(asset_name, ip=None, mac=None, actor=None, path=None):
    """Real, editable IP/MAC override for one asset - same manually-set,
    validated-not-guessed pattern as set_facing/set_environment above. A vendor scan
    finding sometimes already carries an ip/mac (see build_asset_inventory()'s
    per-finding extraction), but often doesn't (e.g. a scanner that only reports a
    hostname) or reports a stale one after a DHCP lease change - this lets a human
    correct or fill that in, and it takes precedence over whatever a finding reported
    (see build_asset_inventory()'s merge below). Pass "" (or None) for either field to
    clear it back to whatever the finding data itself provides. Raises ValueError for
    a value that doesn't parse as a real IPv4/IPv6 address or a real 6-octet MAC."""
    if not asset_name:
        raise ValueError("asset_name is required")
    ip = (ip or "").strip()
    mac = (mac or "").strip()
    if ip and pattern_recognition.ip_version(ip) is None:
        raise ValueError(f"{ip!r} is not a valid IPv4 or IPv6 address")
    if mac and not pattern_recognition.is_valid_mac(mac):
        raise ValueError(f"{mac!r} is not a valid MAC address (expected e.g. aa:bb:cc:dd:ee:ff)")
    ownership = load_ownership(path)
    entry = ownership.setdefault(asset_name, {})
    entry["ip"] = ip or None
    entry["mac"] = mac or None
    save_ownership(ownership, path)
    record_activity(actor, "asset.set_network_info", asset_name, {"ip": entry["ip"], "mac": entry["mac"]})
    return entry


def reconcile_pulled_assets(pulled_assets, known_asset_names, actor=None, path=None):
    """Reconciles asset records pulled from a live connector (Infoblox/Axonius/Active
    Directory - see their fetch_and_normalize_*() output shape:
    {name, ip, mac, type, source, source_ref, extra}) against the real, finding-derived
    asset list, writing any real ip/mac ground truth into asset_ownership.json via
    set_network_info() - the same override-wins mechanism the single-asset "Edit owner"
    panel's IP/MAC fields already use. Same case-insensitive matched/unmatched split as
    cmdb_import.reconcile_rows(), and the same honest scope limit that module's docstring
    already states: an unmatched pulled asset's ip/mac is still stored (so it's already
    correct the moment a finding against it does show up), but it won't appear on the
    Asset Inventory table until then, since that table is built from findings, not a
    separate asset registry.

    A pulled record with neither ip nor mac (e.g. an Infoblox host record with no IPs,
    or an AD computer object - which never carries either) is skipped rather than
    calling set_network_info with nothing to actually set."""
    known_lower = {n.lower(): n for n in known_asset_names}
    matched, unmatched, skipped = [], [], []

    for pulled in pulled_assets:
        name = (pulled.get("name") or "").strip()
        if not name:
            skipped.append({"reason": "No name on this pulled record", "asset_name": None})
            continue
        if not pulled.get("ip") and not pulled.get("mac"):
            skipped.append({"reason": "No ip or mac to reconcile", "asset_name": name})
            continue

        real_name = known_lower.get(name.lower(), name)
        try:
            set_network_info(real_name, ip=pulled.get("ip"), mac=pulled.get("mac"), actor=actor, path=path)
        except ValueError as exc:
            skipped.append({"reason": str(exc), "asset_name": real_name})
            continue

        entry = {"asset_name": real_name, "ip": pulled.get("ip"), "mac": pulled.get("mac")}
        (matched if real_name.lower() in known_lower else unmatched).append(entry)

    return {"matched": matched, "unmatched": unmatched, "skipped": skipped}


def build_asset_inventory(findings, ownership=None):
    """Groups findings by asset.name into one inventory row each. Returns a list
    sorted by finding_count descending (busiest assets first), then name."""
    ownership = ownership if ownership is not None else load_ownership()

    by_name = {}
    for f in findings:
        asset = f.get("asset") or {}
        name = asset.get("name")
        if not name:
            continue
        row = by_name.setdefault(name, {
            "name": name,
            "type": asset.get("type", "unknown"),
            "ip": asset.get("ip"),
            "mac": asset.get("mac"),
            "os": asset.get("os"),
            "finding_count": 0,
            "critical_count": 0,
            "highest_severity": None,
            "kev_count": 0,
        })
        # A later finding for the same asset might carry an ip/mac/os the first one
        # didn't (findings are otherwise independent per-scan records) - backfill
        # rather than overwrite, so the first non-null value wins either way.
        if not row["ip"] and asset.get("ip"):
            row["ip"] = asset.get("ip")
        if not row["mac"] and asset.get("mac"):
            row["mac"] = asset.get("mac")
        if not row["os"] and asset.get("os"):
            row["os"] = asset.get("os")
        row["finding_count"] += 1
        severity = f.get("severity")
        if severity == "Critical":
            row["critical_count"] += 1
        if severity and (row["highest_severity"] is None
                          or _SEVERITY_RANK.get(severity, -1) > _SEVERITY_RANK.get(row["highest_severity"], -1)):
            row["highest_severity"] = severity
        if f.get("kev") and f["kev"].get("listed"):
            row["kev_count"] += 1

    rows = []
    for name, row in by_name.items():
        owner_info = ownership.get(name, {})
        row["owner"] = owner_info.get("owner") or None
        row["team"] = owner_info.get("team") or None
        row["facing"] = owner_info.get("facing") or DEFAULT_FACING
        row["environment"] = owner_info.get("environment") or DEFAULT_ENVIRONMENT
        row["remediation_schedule"] = owner_info.get("remediation_schedule")
        # A human-set ip/mac override (set_network_info) takes precedence over
        # whatever a scan finding reported - real operational ground truth (or a
        # correction for a stale/missing scanner-reported value) beats a possibly
        # stale or absent per-finding field, same override-wins convention as
        # owner/team/facing/environment above.
        row["ip"] = owner_info.get("ip") or row["ip"]
        row["mac"] = owner_info.get("mac") or row["mac"]
        row["ip_version"] = pattern_recognition.ip_version(row["ip"])
        # Whichever applies (an address is never both) - the /24 (IPv4) or /64 (IPv6)
        # grouping key used by the Asset Mapping page's "group by subnet" view, so it
        # never has to re-implement IP parsing itself.
        row["subnet"] = pattern_recognition.ip_subnet(row["ip"]) or pattern_recognition.ipv6_subnet(row["ip"])
        row["eol_status"] = classify_eol(row["os"])
        rows.append(row)

    rows.sort(key=lambda r: (-r["finding_count"], r["name"]))
    return rows
