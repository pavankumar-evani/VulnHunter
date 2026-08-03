"""
Tests for remediation/inventory/asset_inventory.py - aggregating findings into a
per-asset inventory view, plus the editable ownership store. Ownership tests use a
temporary file (never the real, shipped asset_ownership.json).
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.inventory import asset_inventory  # noqa: E402


def _finding(id_, asset_name, asset_type, severity, kev_listed=False):
    return {
        "id": id_,
        "asset": {"name": asset_name, "type": asset_type},
        "severity": severity,
        "kev": {"listed": kev_listed} if kev_listed is not None else None,
    }


class BuildAssetInventory(unittest.TestCase):
    def test_groups_findings_by_asset_name(self):
        findings = [
            _finding("FIND-1", "WEB-PORTAL01", "certificate", "Medium"),
            _finding("FIND-2", "WEB-PORTAL01", "certificate", "Medium"),
            _finding("FIND-3", "WIN-DC01", "windows-server", "Critical"),
        ]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["WEB-PORTAL01"]["finding_count"], 2)
        self.assertEqual(by_name["WIN-DC01"]["finding_count"], 1)

    def test_highest_severity_picks_the_max_across_an_assets_findings(self):
        findings = [
            _finding("FIND-1", "LNX-DB03", "unix-server", "Medium"),
            _finding("FIND-2", "LNX-DB03", "unix-server", "Critical"),
            _finding("FIND-3", "LNX-DB03", "unix-server", "Low"),
        ]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertEqual(rows[0]["highest_severity"], "Critical")

    def test_kev_count_only_counts_actually_listed_findings(self):
        findings = [
            _finding("FIND-1", "WIN-FS02", "windows-server", "Critical", kev_listed=True),
            _finding("FIND-2", "WIN-FS02", "windows-server", "High", kev_listed=False),
            _finding("FIND-3", "WIN-FS02", "windows-server", "Low", kev_listed=None),
        ]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertEqual(rows[0]["kev_count"], 1)

    def test_findings_without_an_asset_name_are_skipped_not_crashed_on(self):
        findings = [{"id": "FIND-1", "asset": {}, "severity": "Low", "kev": None}]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertEqual(rows, [])

    def test_sorted_by_finding_count_descending_then_name(self):
        findings = [
            _finding("FIND-1", "A-HOST", "windows-server", "Low"),
            _finding("FIND-2", "B-HOST", "windows-server", "Low"),
            _finding("FIND-3", "B-HOST", "windows-server", "Low"),
        ]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertEqual([r["name"] for r in rows], ["B-HOST", "A-HOST"])

    def test_owner_and_team_are_attached_from_ownership_map(self):
        findings = [_finding("FIND-1", "WIN-DC01", "windows-server", "Critical")]
        ownership = {"WIN-DC01": {"owner": "Priya Nair", "team": "Identity"}}
        rows = asset_inventory.build_asset_inventory(findings, ownership=ownership)
        self.assertEqual(rows[0]["owner"], "Priya Nair")
        self.assertEqual(rows[0]["team"], "Identity")

    def test_unowned_asset_has_none_owner_and_team(self):
        findings = [_finding("FIND-1", "UNOWNED-01", "windows-server", "Low")]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertIsNone(rows[0]["owner"])
        self.assertIsNone(rows[0]["team"])


class OwnershipStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "asset_ownership.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_load_from_missing_file_returns_empty_dict(self):
        self.assertEqual(asset_inventory.load_ownership(self.path), {})

    def test_set_owner_persists_and_is_readable_back(self):
        asset_inventory.set_owner("WIN-DC01", "Priya Nair", "Identity", path=self.path)
        loaded = asset_inventory.load_ownership(self.path)
        self.assertEqual(loaded["WIN-DC01"], {"owner": "Priya Nair", "team": "Identity"})

    def test_set_owner_overwrites_a_previous_entry_for_the_same_asset(self):
        asset_inventory.set_owner("WIN-DC01", "First Owner", "Team A", path=self.path)
        asset_inventory.set_owner("WIN-DC01", "Second Owner", "Team B", path=self.path)
        loaded = asset_inventory.load_ownership(self.path)
        self.assertEqual(loaded["WIN-DC01"], {"owner": "Second Owner", "team": "Team B"})

    def test_set_owner_requires_an_asset_name(self):
        with self.assertRaises(ValueError):
            asset_inventory.set_owner("", "Someone", "Some Team", path=self.path)


class RealSeedFileIsValid(unittest.TestCase):
    def test_shipped_ownership_file_is_well_formed(self):
        ownership = asset_inventory.load_ownership()
        self.assertIsInstance(ownership, dict)
        for name, info in ownership.items():
            self.assertIsInstance(name, str)
            self.assertIn("owner", info)
            self.assertIn("team", info)


if __name__ == "__main__":
    unittest.main()
