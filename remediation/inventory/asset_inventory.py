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

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OWNERSHIP_PATH = Path(__file__).resolve().parent / "asset_ownership.json"

_SEVERITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}

# An asset's internet/internal-facing exposure is real operational knowledge no vendor
# scan reliably reports on its own - this is a manually-set, editable classification
# (same file/pattern as owner/team), NOT derived from any network scan or auto-detection.
# "unknown" is the honest default until someone actually sets it - never guessed.
VALID_FACING_VALUES = ("external", "internal", "unknown")
DEFAULT_FACING = "unknown"


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


def set_owner(asset_name, owner, team, path=None):
    if not asset_name:
        raise ValueError("asset_name is required")
    ownership = load_ownership(path)
    # setdefault (not a fresh dict) so this doesn't wipe out a facing classification
    # already set on this asset - owner/team and facing are edited independently.
    entry = ownership.setdefault(asset_name, {})
    entry["owner"] = owner or ""
    entry["team"] = team or ""
    save_ownership(ownership, path)
    return entry


def set_facing(asset_name, facing, path=None):
    if not asset_name:
        raise ValueError("asset_name is required")
    if facing not in VALID_FACING_VALUES:
        raise ValueError(f"facing must be one of {VALID_FACING_VALUES}, got {facing!r}")
    ownership = load_ownership(path)
    entry = ownership.setdefault(asset_name, {})
    entry["facing"] = facing
    save_ownership(ownership, path)
    return entry


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
            "finding_count": 0,
            "critical_count": 0,
            "highest_severity": None,
            "kev_count": 0,
        })
        # A later finding for the same asset might carry an ip/mac the first one
        # didn't (findings are otherwise independent per-scan records) - backfill
        # rather than overwrite, so the first non-null value wins either way.
        if not row["ip"] and asset.get("ip"):
            row["ip"] = asset.get("ip")
        if not row["mac"] and asset.get("mac"):
            row["mac"] = asset.get("mac")
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
        rows.append(row)

    rows.sort(key=lambda r: (-r["finding_count"], r["name"]))
    return rows
