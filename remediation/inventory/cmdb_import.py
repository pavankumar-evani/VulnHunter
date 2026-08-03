"""
CMDB import: reconciles an uploaded asset-details export against VulnHunter's real,
finding-derived asset list, to help bulk-assign owner/team on the Asset Inventory page
instead of hand-editing each asset one at a time.

Accepts **CSV**, not a fabricated `.xlsx` binary parser - same reasoning as
dashboard/static/js/export.js's download side: real `.xlsx` parsing needs a new
dependency (`openpyxl`) this project doesn't otherwise use, and every spreadsheet tool
(Excel included) exports/opens CSV natively, so "export your CMDB sheet to CSV first" is
a normal, one-click step rather than a real limitation. If a project genuinely needs
native `.xlsx` upload, `openpyxl` is a reasonable, well-known dependency to add for it -
just not added here without being asked for specifically.

Column names in real-world CMDB exports vary a lot ("Owner" vs "Application Owner" vs
"Asset Owner", "Team" vs "Group" vs "Department"), so `suggest_column_mapping` guesses
via a keyword heuristic - same honesty pattern as attack_mapping.py/
compensating_controls.py: a starting point to confirm or correct in the UI, never
applied blind.

This is a real, working bulk-import - not a live CMDB sync/connector. An uploaded row
for an asset with no current findings against it is still stored (in
asset_ownership.json, same file/format the single-asset "Edit owner" form already
writes to) so its owner/team is already in place the moment a finding against it does
show up - it just won't appear on the Asset Inventory table until then, since that table
is built from findings, not from a separate asset registry.
"""
import csv
import io

_ASSET_NAME_KEYWORDS = ["asset name", "asset", "hostname", "host name", "host", "device name", "device", "name", "server"]
_OWNER_KEYWORDS = ["application owner", "app owner", "asset owner", "owner", "contact"]
_TEAM_KEYWORDS = ["team", "group", "department", "division", "squad"]


def parse_csv_text(csv_text):
    """Returns (headers, rows) - rows are list[dict] keyed by header, via the stdlib
    csv module (handles quoting/commas-in-fields correctly, unlike a naive .split(','))."""
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    return list(reader.fieldnames or []), rows


def _best_header_match(headers, keywords):
    """Longest-keyword-first, so e.g. "Application Owner" is preferred over the plainer
    "owner" keyword also matching an unrelated column that happens to contain "owner"."""
    for keyword in keywords:
        for header in headers:
            if keyword in header.lower():
                return header
    return None


def suggest_column_mapping(headers):
    """Best-effort guess at which uploaded column is the asset name/owner/team - a
    keyword heuristic against header text, not a guaranteed-correct mapping. Always
    confirm/adjust in the UI before applying - see the module docstring."""
    return {
        "asset_name": _best_header_match(headers, _ASSET_NAME_KEYWORDS),
        "owner": _best_header_match(headers, _OWNER_KEYWORDS),
        "team": _best_header_match(headers, _TEAM_KEYWORDS),
    }


def reconcile_rows(rows, column_mapping, known_asset_names):
    """Classifies each uploaded row against the real, finding-derived asset list
    (case-insensitive match):
    - matched: the asset already has findings against it (appears on /assets today)
    - unmatched: no findings against it yet - owner/team can still be stored, applying
      the moment one shows up
    - invalid: no asset name found in the mapped column at all
    """
    known_lower = {name.lower(): name for name in known_asset_names}
    asset_col = column_mapping.get("asset_name")
    owner_col = column_mapping.get("owner")
    team_col = column_mapping.get("team")

    matched, unmatched, invalid = [], [], []
    for i, row in enumerate(rows):
        raw_name = (row.get(asset_col) or "").strip() if asset_col else ""
        if not raw_name:
            invalid.append({"row": i, "reason": "No asset name found in the mapped column"})
            continue
        entry = {
            "row": i,
            "asset_name": raw_name,
            "owner": ((row.get(owner_col) or "").strip() if owner_col else ""),
            "team": ((row.get(team_col) or "").strip() if team_col else ""),
        }
        real_name = known_lower.get(raw_name.lower())
        if real_name:
            entry["asset_name"] = real_name  # normalize to the real casing
            matched.append(entry)
        else:
            unmatched.append(entry)
    return {"matched": matched, "unmatched": unmatched, "invalid": invalid}


def apply_import(entries, path=None):
    """entries: list of {asset_name, owner, team} - already reconciled (and possibly
    hand-edited in the UI) rows from reconcile_rows()'s matched+unmatched lists. Calls
    asset_inventory.set_owner for each real asset name - the exact same upsert the
    single-asset "Edit owner" form on /assets already uses, just applied in bulk.
    Entries with a blank asset_name are skipped (never silently invent one)."""
    from . import asset_inventory  # local import - avoids a circular import at module load time

    applied = 0
    for entry in entries:
        name = (entry.get("asset_name") or "").strip()
        if not name:
            continue
        asset_inventory.set_owner(name, entry.get("owner", ""), entry.get("team", ""), path=path)
        applied += 1
    return {"applied": applied, "skipped": len(entries) - applied}
