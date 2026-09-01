"""
Bulk, rule-based asset-metadata policy: instead of editing owner/team/environment/
facing/remediation-schedule one asset at a time on /assets, an admin declares
match-and-set rules in remediation/config/asset_policy_rules.yaml and applies them
across every real asset that matches, in one action.

Same real preview-then-apply flow already established elsewhere in this repo
(remediation/inventory/cmdb_import.py's CSV import preview/apply,
remediation/enrichment/exploit_criteria's rule preview): preview_matches() is read-only
and writes nothing; apply_rules() only ever writes through asset_inventory.py's own
real setters, so every bulk-applied change is validated and recorded in the real
activity log (remediation/audit/activity_log.py) exactly the same way a single-asset
edit already is - just with `"bulk-asset-policy"` noted as the source.

Deliberately does NOT let a rule set an asset's `type` - type reflects what the real
finding/scan data actually reports (windows-server, application, certificate, ...), and
letting an admin-authored rule override it would let the displayed type silently
disagree with reality. This boundary is enforced here in code (a `type` key under a
rule's `set` block is simply never read), not just documented in the YAML file.
"""
import re
from pathlib import Path

import yaml

from remediation.inventory import asset_inventory

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "asset_policy_rules.yaml"

# Fields a rule's `set` block is allowed to change - `type` is deliberately absent (see
# module docstring). Iterated in this fixed order so preview/apply behavior is stable
# regardless of key order in the parsed YAML.
SETTABLE_FIELDS = ("owner", "team", "environment", "facing", "remediation_schedule")


def load_rules(path=None):
    path = Path(path) if path is not None else DEFAULT_RULES_PATH
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {"rules": []}


def _asset_matches(asset_row, match):
    name = asset_row.get("name") or ""
    if "name_prefix" in match and not name.startswith(match["name_prefix"]):
        return False
    if "name_regex" in match and not re.search(match["name_regex"], name):
        return False
    if "type" in match and asset_row.get("type") != match["type"]:
        return False
    if "environment" in match and (asset_row.get("environment") or "unknown") != match["environment"]:
        return False
    if "facing" in match and (asset_row.get("facing") or "unknown") != match["facing"]:
        return False
    return True


def preview_matches(asset_rows, rules):
    """Read-only - returns [{rule_index, rule_name, set, matched_assets: [name, ...]}]
    for every rule in `rules` (the same {"rules": [...]} shape load_rules() returns, so
    a caller can preview an unsaved YAML edit before committing it). Writes nothing."""
    results = []
    for i, rule in enumerate(rules.get("rules", [])):
        match = rule.get("match", {})
        set_fields = {k: v for k, v in (rule.get("set") or {}).items() if k in SETTABLE_FIELDS}
        matched = [a["name"] for a in asset_rows if _asset_matches(a, match)]
        results.append({
            "rule_index": i,
            "rule_name": rule.get("name", f"Rule {i + 1}"),
            "set": set_fields,
            "matched_assets": matched,
        })
    return results


def apply_rules(asset_rows, rules, actor=None, path=None):
    """Real writes via asset_inventory.py's own setters, one call per matched asset per
    field group that changed - each recorded in the real activity log the same way a
    single-asset edit already is. Returns {rules_applied, assets_changed}."""
    preview = preview_matches(asset_rows, rules)
    assets_changed = set()
    for entry in preview:
        set_fields = entry["set"]
        for asset_name in entry["matched_assets"]:
            if "owner" in set_fields or "team" in set_fields:
                # Re-read current ownership fresh for every asset (not once for the
                # whole batch) - an earlier rule in this same apply_rules() call may
                # already have changed this asset's owner/team, and a stale in-memory
                # snapshot would silently clobber that with an out-of-date value.
                current = asset_inventory.load_ownership(path).get(asset_name, {})
                asset_inventory.set_owner(
                    asset_name,
                    set_fields.get("owner", current.get("owner", "")),
                    set_fields.get("team", current.get("team", "")),
                    actor=actor, path=path,
                )
            if "environment" in set_fields:
                asset_inventory.set_environment(asset_name, set_fields["environment"], actor=actor, path=path)
            if "facing" in set_fields:
                asset_inventory.set_facing(asset_name, set_fields["facing"], actor=actor, path=path)
            if "remediation_schedule" in set_fields:
                schedule = set_fields["remediation_schedule"] or {}
                asset_inventory.set_remediation_schedule(
                    asset_name, schedule.get("cadence"), schedule.get("maintenance_window"), actor=actor, path=path,
                )
            assets_changed.add(asset_name)
    return {"rules_applied": len(preview), "assets_changed": len(assets_changed)}
