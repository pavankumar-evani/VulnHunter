"""
Tests for remediation/inventory/asset_policy.py - the bulk, rule-based asset-metadata
policy engine. Uses in-memory asset rows/rules (not the real shipped
asset_policy_rules.yaml, which ships with zero active rules) plus a temporary
ownership file so this suite never mutates real data.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.audit import activity_log  # noqa: E402
from remediation.inventory import asset_inventory, asset_policy  # noqa: E402


def _asset(name, asset_type="unix-server", environment="unknown", facing="unknown"):
    return {"name": name, "type": asset_type, "environment": environment, "facing": facing}


class PreviewMatches(unittest.TestCase):
    def test_name_prefix_match(self):
        assets = [_asset("WEB-PORTAL01"), _asset("WEB-PORTAL02"), _asset("LNX-DB03")]
        rules = {"rules": [{"name": "Web portals", "match": {"name_prefix": "WEB-PORTAL"}, "set": {"facing": "external"}}]}
        preview = asset_policy.preview_matches(assets, rules)
        self.assertEqual(preview[0]["matched_assets"], ["WEB-PORTAL01", "WEB-PORTAL02"])

    def test_name_regex_match(self):
        assets = [_asset("NET-RTSW-0001"), _asset("NET-RTSW-0002"), _asset("FW-EDGE01")]
        rules = {"rules": [{"match": {"name_regex": r"^NET-RTSW-\d+$"}, "set": {}}]}
        preview = asset_policy.preview_matches(assets, rules)
        self.assertEqual(sorted(preview[0]["matched_assets"]), ["NET-RTSW-0001", "NET-RTSW-0002"])

    def test_type_match(self):
        assets = [_asset("A", asset_type="certificate"), _asset("B", asset_type="unix-server")]
        rules = {"rules": [{"match": {"type": "certificate"}, "set": {}}]}
        preview = asset_policy.preview_matches(assets, rules)
        self.assertEqual(preview[0]["matched_assets"], ["A"])

    def test_environment_and_facing_are_anded_together(self):
        assets = [
            _asset("A", environment="prod", facing="external"),
            _asset("B", environment="prod", facing="internal"),
            _asset("C", environment="dev", facing="external"),
        ]
        rules = {"rules": [{"match": {"environment": "prod", "facing": "external"}, "set": {}}]}
        preview = asset_policy.preview_matches(assets, rules)
        self.assertEqual(preview[0]["matched_assets"], ["A"])

    def test_type_is_never_a_settable_field_even_if_present_in_yaml(self):
        assets = [_asset("A")]
        rules = {"rules": [{"match": {"name_prefix": "A"}, "set": {"type": "application", "owner": "Someone"}}]}
        preview = asset_policy.preview_matches(assets, rules)
        self.assertNotIn("type", preview[0]["set"])
        self.assertIn("owner", preview[0]["set"])

    def test_no_rules_returns_empty_list(self):
        self.assertEqual(asset_policy.preview_matches([_asset("A")], {"rules": []}), [])

    def test_is_read_only(self):
        assets = [_asset("A")]
        assets_before = [dict(a) for a in assets]
        rules = {"rules": [{"match": {"name_prefix": "A"}, "set": {"owner": "X", "team": "Y"}}]}
        asset_policy.preview_matches(assets, rules)
        self.assertEqual(assets, assets_before)


class ApplyRules(unittest.TestCase):
    """apply_rules() writes real changes via asset_inventory.py's setters, which also
    write to the real, shared activity log (see remediation/audit/activity_log.py)
    unless redirected - patch its default path to a temp file too so this suite never
    pollutes the real, committed-empty log."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "asset_ownership.json"
        self.activity_log_path = Path(self.tmpdir.name) / "activity_log.json"
        self.activity_patcher = patch.object(activity_log, "DEFAULT_LOG_PATH", self.activity_log_path)
        self.activity_patcher.start()

    def tearDown(self):
        self.activity_patcher.stop()
        self.tmpdir.cleanup()

    def test_applies_owner_and_team_to_every_matched_asset(self):
        assets = [_asset("WEB-PORTAL01"), _asset("WEB-PORTAL02"), _asset("LNX-DB03")]
        rules = {"rules": [{"match": {"name_prefix": "WEB-PORTAL"}, "set": {"owner": "Web Ops", "team": "Platform"}}]}
        result = asset_policy.apply_rules(assets, rules, actor="admin@test.local", path=self.path)
        self.assertEqual(result, {"rules_applied": 1, "assets_changed": 2})
        loaded = asset_inventory.load_ownership(self.path)
        self.assertEqual(loaded["WEB-PORTAL01"]["owner"], "Web Ops")
        self.assertEqual(loaded["WEB-PORTAL02"]["team"], "Platform")
        self.assertNotIn("LNX-DB03", loaded)

    def test_setting_only_owner_preserves_an_assets_existing_team(self):
        asset_inventory.set_owner("WEB-PORTAL01", "Old Owner", "Existing Team", path=self.path)
        assets = [_asset("WEB-PORTAL01")]
        rules = {"rules": [{"match": {"name_prefix": "WEB-PORTAL"}, "set": {"owner": "New Owner"}}]}
        asset_policy.apply_rules(assets, rules, path=self.path)
        loaded = asset_inventory.load_ownership(self.path)
        self.assertEqual(loaded["WEB-PORTAL01"]["owner"], "New Owner")
        self.assertEqual(loaded["WEB-PORTAL01"]["team"], "Existing Team")

    def test_applies_remediation_schedule(self):
        assets = [_asset("NET-RTSW-01", asset_type="network-routing-switching")]
        rules = {"rules": [{"match": {"type": "network-routing-switching"}, "set": {"remediation_schedule": {"cadence": "weekly"}}}]}
        asset_policy.apply_rules(assets, rules, path=self.path)
        loaded = asset_inventory.load_ownership(self.path)
        self.assertEqual(loaded["NET-RTSW-01"]["remediation_schedule"]["cadence"], "weekly")

    def test_does_not_write_a_type_field_even_if_present_in_the_rule(self):
        assets = [_asset("A")]
        rules = {"rules": [{"match": {"name_prefix": "A"}, "set": {"type": "application"}}]}
        asset_policy.apply_rules(assets, rules, path=self.path)
        loaded = asset_inventory.load_ownership(self.path)
        # No settable field was actually present (type is stripped), so nothing about
        # this asset should have been written at all.
        self.assertNotIn("A", loaded)

    def test_multiple_rules_touching_the_same_asset_do_not_clobber_each_other(self):
        assets = [_asset("WEB-PORTAL01")]
        rules = {"rules": [
            {"match": {"name_prefix": "WEB-PORTAL"}, "set": {"owner": "Web Ops", "team": "Platform"}},
            {"match": {"name_prefix": "WEB-PORTAL"}, "set": {"facing": "external"}},
        ]}
        asset_policy.apply_rules(assets, rules, path=self.path)
        loaded = asset_inventory.load_ownership(self.path)
        self.assertEqual(loaded["WEB-PORTAL01"]["owner"], "Web Ops")
        self.assertEqual(loaded["WEB-PORTAL01"]["facing"], "external")

    def test_no_matching_assets_changes_nothing(self):
        assets = [_asset("LNX-DB03")]
        rules = {"rules": [{"match": {"name_prefix": "WEB-PORTAL"}, "set": {"owner": "X", "team": "Y"}}]}
        result = asset_policy.apply_rules(assets, rules, path=self.path)
        self.assertEqual(result["assets_changed"], 0)
        self.assertEqual(asset_inventory.load_ownership(self.path), {})


class RealRulesFileIsValid(unittest.TestCase):
    def test_real_shipped_file_loads_and_has_a_rules_key(self):
        rules = asset_policy.load_rules()
        self.assertIn("rules", rules)

    def test_real_shipped_file_ships_with_no_active_rules(self):
        # Nothing here should ever accidentally apply to the real seed asset data.
        rules = asset_policy.load_rules()
        self.assertEqual(rules["rules"], [])


if __name__ == "__main__":
    unittest.main()
