"""
Tests for remediation/inventory/cmdb_import.py - CSV parsing, column-mapping
suggestion, reconciliation against the real asset list, and bulk apply. Apply tests use
a temporary ownership file (never the real, shipped asset_ownership.json).
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.inventory import asset_inventory, cmdb_import  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402


def _patch_db_engine(tmpdir_path):
    """See tests/test_dashboard.py's helper of the same name for the full rationale."""
    test_engine = create_engine(f"sqlite:///{Path(tmpdir_path) / 'test.db'}")
    patcher = patch.object(db_module, "get_engine", return_value=test_engine)
    patcher.engine = test_engine
    return patcher


class ParseCsvText(unittest.TestCase):
    def test_parses_headers_and_rows(self):
        csv_text = "Hostname,Application Owner,Team\nWEB-PORTAL01,Web Ops,Platform\n"
        headers, rows = cmdb_import.parse_csv_text(csv_text)
        self.assertEqual(headers, ["Hostname", "Application Owner", "Team"])
        self.assertEqual(rows, [{"Hostname": "WEB-PORTAL01", "Application Owner": "Web Ops", "Team": "Platform"}])

    def test_handles_quoted_fields_with_commas(self):
        csv_text = 'Hostname,Notes\nWIN-DC01,"Domain controller, primary site"\n'
        _, rows = cmdb_import.parse_csv_text(csv_text)
        self.assertEqual(rows[0]["Notes"], "Domain controller, primary site")

    def test_empty_text_returns_no_rows(self):
        headers, rows = cmdb_import.parse_csv_text("")
        self.assertEqual(rows, [])


class SuggestColumnMapping(unittest.TestCase):
    def test_matches_common_header_names(self):
        mapping = cmdb_import.suggest_column_mapping(["Hostname", "Application Owner", "Team"])
        self.assertEqual(mapping["asset_name"], "Hostname")
        self.assertEqual(mapping["owner"], "Application Owner")
        self.assertEqual(mapping["team"], "Team")

    def test_matches_alternate_header_names(self):
        mapping = cmdb_import.suggest_column_mapping(["Asset", "Contact", "Department"])
        self.assertEqual(mapping["asset_name"], "Asset")
        self.assertEqual(mapping["owner"], "Contact")
        self.assertEqual(mapping["team"], "Department")

    def test_no_match_returns_none_not_a_guess(self):
        mapping = cmdb_import.suggest_column_mapping(["Column A", "Column B"])
        self.assertIsNone(mapping["asset_name"])
        self.assertIsNone(mapping["owner"])
        self.assertIsNone(mapping["team"])


class ReconcileRows(unittest.TestCase):
    MAPPING = {"asset_name": "Hostname", "owner": "Owner", "team": "Team"}
    KNOWN = ["WEB-PORTAL01", "WIN-DC01"]

    def test_matches_a_known_asset_case_insensitively(self):
        rows = [{"Hostname": "web-portal01", "Owner": "Web Ops", "Team": "Platform"}]
        result = cmdb_import.reconcile_rows(rows, self.MAPPING, self.KNOWN)
        self.assertEqual(len(result["matched"]), 1)
        self.assertEqual(result["matched"][0]["asset_name"], "WEB-PORTAL01")  # normalized casing

    def test_unmatched_asset_is_not_dropped(self):
        rows = [{"Hostname": "NEW-SERVER-01", "Owner": "Someone", "Team": "SomeTeam"}]
        result = cmdb_import.reconcile_rows(rows, self.MAPPING, self.KNOWN)
        self.assertEqual(len(result["unmatched"]), 1)
        self.assertEqual(result["unmatched"][0]["asset_name"], "NEW-SERVER-01")

    def test_row_with_no_asset_name_is_invalid(self):
        rows = [{"Hostname": "", "Owner": "Someone", "Team": "SomeTeam"}]
        result = cmdb_import.reconcile_rows(rows, self.MAPPING, self.KNOWN)
        self.assertEqual(len(result["invalid"]), 1)
        self.assertEqual(result["matched"], [])
        self.assertEqual(result["unmatched"], [])

    def test_mixed_batch_classifies_each_row_independently(self):
        rows = [
            {"Hostname": "WIN-DC01", "Owner": "Priya", "Team": "Identity"},
            {"Hostname": "UNKNOWN-01", "Owner": "X", "Team": "Y"},
            {"Hostname": "", "Owner": "Z", "Team": "W"},
        ]
        result = cmdb_import.reconcile_rows(rows, self.MAPPING, self.KNOWN)
        self.assertEqual(len(result["matched"]), 1)
        self.assertEqual(len(result["unmatched"]), 1)
        self.assertEqual(len(result["invalid"]), 1)

    def test_no_asset_column_mapped_makes_every_row_invalid(self):
        rows = [{"Hostname": "WIN-DC01", "Owner": "Priya", "Team": "Identity"}]
        result = cmdb_import.reconcile_rows(rows, {"asset_name": None, "owner": "Owner", "team": "Team"}, self.KNOWN)
        self.assertEqual(len(result["invalid"]), 1)


class ApplyImport(unittest.TestCase):
    """apply_import() calls asset_inventory.set_owner(), which also writes to the real,
    shared activity log (see remediation/audit/activity_log.py) unless redirected -
    patch its default path to a temp file too so this suite never pollutes the real,
    committed-empty log."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "asset_ownership.json"
        self.activity_patcher = _patch_db_engine(self.tmpdir.name)
        self.activity_patcher.start()

    def tearDown(self):
        self.activity_patcher.engine.dispose()
        self.activity_patcher.stop()
        self.tmpdir.cleanup()

    def test_applies_owner_and_team_for_each_entry(self):
        entries = [
            {"asset_name": "WEB-PORTAL01", "owner": "Web Ops", "team": "Platform"},
            {"asset_name": "WIN-DC01", "owner": "Priya Nair", "team": "Identity"},
        ]
        result = cmdb_import.apply_import(entries, path=self.path)
        self.assertEqual(result["applied"], 2)
        loaded = asset_inventory.load_ownership(self.path)
        self.assertEqual(loaded["WEB-PORTAL01"], {"owner": "Web Ops", "team": "Platform"})
        self.assertEqual(loaded["WIN-DC01"], {"owner": "Priya Nair", "team": "Identity"})

    def test_skips_entries_with_no_asset_name(self):
        entries = [{"asset_name": "", "owner": "X", "team": "Y"}]
        result = cmdb_import.apply_import(entries, path=self.path)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(asset_inventory.load_ownership(self.path), {})

    def test_applying_for_an_unmatched_asset_still_stores_ownership(self):
        """An asset with no findings yet still gets its ownership stored - it just
        won't show up on /assets until a finding against it exists."""
        entries = [{"asset_name": "FUTURE-SERVER-01", "owner": "Someone", "team": "SomeTeam"}]
        cmdb_import.apply_import(entries, path=self.path)
        loaded = asset_inventory.load_ownership(self.path)
        self.assertEqual(loaded["FUTURE-SERVER-01"]["owner"], "Someone")


if __name__ == "__main__":
    unittest.main()
