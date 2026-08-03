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
    ownership[asset_name] = {"owner": owner or "", "team": team or ""}
    save_ownership(ownership, path)
    return ownership[asset_name]


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
            "finding_count": 0,
            "highest_severity": None,
            "kev_count": 0,
        })
        row["finding_count"] += 1
        severity = f.get("severity")
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
        rows.append(row)

    rows.sort(key=lambda r: (-r["finding_count"], r["name"]))
    return rows
