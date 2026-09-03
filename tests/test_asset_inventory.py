"""
Tests for remediation/inventory/asset_inventory.py - aggregating findings into a
per-asset inventory view, plus the editable ownership store. Ownership tests use an
isolated temp DB (never the real, shared remediation/vulnhunter.db).
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.inventory import asset_inventory  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402


def _patch_db_engine(tmpdir_path):
    """See tests/test_dashboard.py's helper of the same name for the full rationale -
    record_activity() (called by set_owner/set_facing/etc below) resolves its DB
    access via db_module.get_engine() when no engine is passed explicitly, so
    patching that one function redirects it to an isolated on-disk file. Returned
    patcher carries the engine as `.engine` - callers must dispose it (Windows won't
    delete a tempdir while a pooled connection still has the file open) before
    `.stop()` and the tmpdir cleanup that follows."""
    test_engine = create_engine(f"sqlite:///{Path(tmpdir_path) / 'test.db'}")
    patcher = patch.object(db_module, "get_engine", return_value=test_engine)
    patcher.engine = test_engine
    return patcher


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

    def test_critical_count_only_counts_critical_severity(self):
        findings = [
            _finding("FIND-1", "WIN-DC01", "windows-server", "Critical"),
            _finding("FIND-2", "WIN-DC01", "windows-server", "Critical"),
            _finding("FIND-3", "WIN-DC01", "windows-server", "High"),
        ]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertEqual(rows[0]["critical_count"], 2)

    def test_facing_defaults_to_unknown_when_not_set(self):
        findings = [_finding("FIND-1", "UNCLASSIFIED-01", "windows-server", "Low")]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertEqual(rows[0]["facing"], "unknown")

    def test_facing_is_attached_from_ownership_map(self):
        findings = [_finding("FIND-1", "WEB-PORTAL01", "certificate", "Medium")]
        ownership = {"WEB-PORTAL01": {"facing": "external"}}
        rows = asset_inventory.build_asset_inventory(findings, ownership=ownership)
        self.assertEqual(rows[0]["facing"], "external")


class OwnershipStore(unittest.TestCase):
    """Every set_* call here also writes to the real, shared activity log (see
    remediation/audit/activity_log.py) unless redirected - patching db_module.get_engine
    for the whole class redirects both to the same isolated on-disk DB."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_patcher = _patch_db_engine(self.tmpdir.name)
        self.db_patcher.start()

    def tearDown(self):
        self.db_patcher.engine.dispose()
        self.db_patcher.stop()
        self.tmpdir.cleanup()

    def test_load_from_missing_file_returns_empty_dict(self):
        self.assertEqual(asset_inventory.load_ownership(), {})

    def test_set_owner_persists_and_is_readable_back(self):
        asset_inventory.set_owner("WIN-DC01", "Priya Nair", "Identity")
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"], {"owner": "Priya Nair", "team": "Identity"})

    def test_set_owner_overwrites_a_previous_entry_for_the_same_asset(self):
        asset_inventory.set_owner("WIN-DC01", "First Owner", "Team A")
        asset_inventory.set_owner("WIN-DC01", "Second Owner", "Team B")
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"], {"owner": "Second Owner", "team": "Team B"})

    def test_set_owner_requires_an_asset_name(self):
        with self.assertRaises(ValueError):
            asset_inventory.set_owner("", "Someone", "Some Team")

    def test_set_owner_does_not_clobber_an_existing_facing_classification(self):
        asset_inventory.set_facing("WIN-DC01", "external")
        asset_inventory.set_owner("WIN-DC01", "Priya Nair", "Identity")
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"]["facing"], "external")
        self.assertEqual(loaded["WIN-DC01"]["owner"], "Priya Nair")

    def test_set_facing_does_not_clobber_existing_owner_team(self):
        asset_inventory.set_owner("WIN-DC01", "Priya Nair", "Identity")
        asset_inventory.set_facing("WIN-DC01", "internal")
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"]["owner"], "Priya Nair")
        self.assertEqual(loaded["WIN-DC01"]["facing"], "internal")

    def test_set_facing_rejects_an_invalid_value(self):
        with self.assertRaises(ValueError):
            asset_inventory.set_facing("WIN-DC01", "space-station")

    def test_set_remediation_schedule_persists_cadence_and_window(self):
        window = {"day_of_week": "sunday", "start_time": "01:00", "end_time": "02:00", "timezone": "UTC"}
        asset_inventory.set_remediation_schedule("WIN-DC01", "weekly", window)
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"]["remediation_schedule"], {"cadence": "weekly", "maintenance_window": window})

    def test_set_remediation_schedule_rejects_an_invalid_cadence(self):
        with self.assertRaises(ValueError):
            asset_inventory.set_remediation_schedule("WIN-DC01", "biannually")

    def test_set_remediation_schedule_with_no_args_clears_an_existing_override(self):
        asset_inventory.set_remediation_schedule("WIN-DC01", "weekly")
        asset_inventory.set_remediation_schedule("WIN-DC01")
        loaded = asset_inventory.load_ownership()
        self.assertNotIn("remediation_schedule", loaded["WIN-DC01"])

    def test_set_remediation_schedule_does_not_clobber_owner(self):
        asset_inventory.set_owner("WIN-DC01", "Priya Nair", "Identity")
        asset_inventory.set_remediation_schedule("WIN-DC01", "monthly")
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"]["owner"], "Priya Nair")
        self.assertEqual(loaded["WIN-DC01"]["remediation_schedule"]["cadence"], "monthly")

    def test_set_facing_requires_an_asset_name(self):
        with self.assertRaises(ValueError):
            asset_inventory.set_facing("", "external")

    def test_set_network_info_persists_valid_ip_and_mac(self):
        asset_inventory.set_network_info("WIN-DC01", "10.20.30.41", "aa:bb:cc:dd:ee:ff")
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"]["ip"], "10.20.30.41")
        self.assertEqual(loaded["WIN-DC01"]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_set_network_info_accepts_a_real_ipv6_address(self):
        asset_inventory.set_network_info("WIN-DC01", "2001:db8::1")
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"]["ip"], "2001:db8::1")

    def test_set_network_info_rejects_an_invalid_ip(self):
        with self.assertRaises(ValueError):
            asset_inventory.set_network_info("WIN-DC01", "not-an-ip")

    def test_set_network_info_rejects_an_invalid_mac(self):
        with self.assertRaises(ValueError):
            asset_inventory.set_network_info("WIN-DC01", mac="not-a-mac")

    def test_set_network_info_blank_clears_a_previous_value(self):
        asset_inventory.set_network_info("WIN-DC01", "10.20.30.41", "aa:bb:cc:dd:ee:ff")
        asset_inventory.set_network_info("WIN-DC01", "", "")
        loaded = asset_inventory.load_ownership()
        self.assertIsNone(loaded["WIN-DC01"].get("ip"))
        self.assertIsNone(loaded["WIN-DC01"].get("mac"))

    def test_set_network_info_does_not_clobber_existing_owner(self):
        asset_inventory.set_owner("WIN-DC01", "Priya Nair", "Identity")
        asset_inventory.set_network_info("WIN-DC01", "10.20.30.41")
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"]["owner"], "Priya Nair")
        self.assertEqual(loaded["WIN-DC01"]["ip"], "10.20.30.41")

    def test_set_network_info_requires_an_asset_name(self):
        with self.assertRaises(ValueError):
            asset_inventory.set_network_info("", "10.20.30.41")


class ReconcilePulledAssets(unittest.TestCase):
    """reconcile_pulled_assets() drives set_network_info() per matched/unmatched
    record, so it needs the same tmpdir + patched DB setup as OwnershipStore above."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_patcher = _patch_db_engine(self.tmpdir.name)
        self.db_patcher.start()

    def tearDown(self):
        self.db_patcher.engine.dispose()
        self.db_patcher.stop()
        self.tmpdir.cleanup()

    def test_matched_asset_gets_ip_mac_written(self):
        pulled = [{"name": "win-dc01", "ip": "10.1.1.5", "mac": None, "type": "windows-server",
                   "source": "infoblox", "source_ref": "ref1", "extra": {}}]
        result = asset_inventory.reconcile_pulled_assets(pulled, ["WIN-DC01"])
        self.assertEqual(result["matched"], [{"asset_name": "WIN-DC01", "ip": "10.1.1.5", "mac": None}])
        self.assertEqual(result["unmatched"], [])
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["WIN-DC01"]["ip"], "10.1.1.5")

    def test_matching_is_case_insensitive_and_normalizes_to_real_casing(self):
        pulled = [{"name": "WEB01.CORP.LOCAL", "ip": "10.0.0.9", "mac": None}]
        result = asset_inventory.reconcile_pulled_assets(pulled, ["web01.corp.local"])
        self.assertEqual(result["matched"][0]["asset_name"], "web01.corp.local")

    def test_unmatched_asset_is_still_stored_but_reported_unmatched(self):
        pulled = [{"name": "new-host", "ip": "10.0.0.1", "mac": None}]
        result = asset_inventory.reconcile_pulled_assets(pulled, ["WIN-DC01"])
        self.assertEqual(result["unmatched"], [{"asset_name": "new-host", "ip": "10.0.0.1", "mac": None}])
        loaded = asset_inventory.load_ownership()
        self.assertEqual(loaded["new-host"]["ip"], "10.0.0.1")

    def test_record_with_no_name_is_skipped(self):
        pulled = [{"name": "", "ip": "10.0.0.1", "mac": None}]
        result = asset_inventory.reconcile_pulled_assets(pulled, [])
        self.assertEqual(len(result["skipped"]), 1)
        self.assertEqual(result["matched"], [])
        self.assertEqual(result["unmatched"], [])

    def test_record_with_neither_ip_nor_mac_is_skipped_without_writing(self):
        pulled = [{"name": "ad-computer-01", "ip": None, "mac": None}]
        result = asset_inventory.reconcile_pulled_assets(pulled, [])
        self.assertEqual(len(result["skipped"]), 1)
        self.assertEqual(asset_inventory.load_ownership(), {})

    def test_invalid_ip_from_source_is_skipped_not_raised(self):
        pulled = [{"name": "bad-ip-host", "ip": "not-an-ip", "mac": None}]
        result = asset_inventory.reconcile_pulled_assets(pulled, [])
        self.assertEqual(len(result["skipped"]), 1)
        self.assertIn("not a valid", result["skipped"][0]["reason"])

    def test_mac_only_record_is_reconciled(self):
        pulled = [{"name": "WIN-DC01", "ip": None, "mac": "aa:bb:cc:dd:ee:ff"}]
        result = asset_inventory.reconcile_pulled_assets(pulled, ["WIN-DC01"])
        self.assertEqual(result["matched"][0]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_one_bad_record_does_not_abort_the_batch(self):
        pulled = [
            {"name": "bad-ip-host", "ip": "not-an-ip", "mac": None},
            {"name": "WIN-DC01", "ip": "10.1.1.5", "mac": None},
        ]
        result = asset_inventory.reconcile_pulled_assets(pulled, ["WIN-DC01"])
        self.assertEqual(len(result["skipped"]), 1)
        self.assertEqual(len(result["matched"]), 1)


class BuildAssetInventoryNetworkInfo(unittest.TestCase):
    def test_ip_mac_come_from_the_finding_when_no_override_exists(self):
        findings = [{
            "id": "FIND-1", "asset": {"name": "WIN-DC01", "type": "windows-server", "ip": "10.1.1.1", "mac": "aa:bb:cc:dd:ee:ff"},
            "severity": "Low", "kev": None,
        }]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertEqual(rows[0]["ip"], "10.1.1.1")
        self.assertEqual(rows[0]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(rows[0]["ip_version"], 4)

    def test_ownership_override_wins_over_the_findings_reported_ip(self):
        findings = [{
            "id": "FIND-1", "asset": {"name": "WIN-DC01", "type": "windows-server", "ip": "10.1.1.1"},
            "severity": "Low", "kev": None,
        }]
        ownership = {"WIN-DC01": {"ip": "2001:db8::1", "mac": "11:22:33:44:55:66"}}
        rows = asset_inventory.build_asset_inventory(findings, ownership=ownership)
        self.assertEqual(rows[0]["ip"], "2001:db8::1")
        self.assertEqual(rows[0]["mac"], "11:22:33:44:55:66")
        self.assertEqual(rows[0]["ip_version"], 6)

    def test_no_ip_anywhere_reports_none_not_a_guess(self):
        findings = [{"id": "FIND-1", "asset": {"name": "WIN-DC01", "type": "windows-server"}, "severity": "Low", "kev": None}]
        rows = asset_inventory.build_asset_inventory(findings, ownership={})
        self.assertIsNone(rows[0]["ip"])
        self.assertIsNone(rows[0]["ip_version"])


if __name__ == "__main__":
    unittest.main()
