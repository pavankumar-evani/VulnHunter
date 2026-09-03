"""
Tests for remediation/enrichment/control_coverage.py - real compensating-control
coverage assessment. Uses in-memory `controls` dicts (not the real shipped
security_controls.yaml, which ships with zero entries) so this suite never depends on
real seed data.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.control_coverage import assess_coverage, find_asset_controls  # noqa: E402


def _finding(asset_name, cve=None, title="", description=""):
    return {"asset": {"name": asset_name}, "cve": cve, "title": title, "description": description}


class FindAssetControls(unittest.TestCase):
    def test_exact_name_match(self):
        controls = {"assets": [{"match": {"name": "WIN-DC01"}, "firewall_rules": []}]}
        self.assertIsNotNone(find_asset_controls("WIN-DC01", controls))
        self.assertIsNone(find_asset_controls("WIN-DC02", controls))

    def test_name_prefix_match(self):
        controls = {"assets": [{"match": {"name_prefix": "WEB-"}, "firewall_rules": []}]}
        self.assertIsNotNone(find_asset_controls("WEB-PORTAL01", controls))
        self.assertIsNone(find_asset_controls("LNX-DB01", controls))

    def test_no_entries_returns_none(self):
        self.assertIsNone(find_asset_controls("ANY-ASSET", {"assets": []}))


class AssessCoverageNoData(unittest.TestCase):
    def test_asset_with_no_entry_has_no_data(self):
        result = assess_coverage(_finding("UNKNOWN-01"), controls={"assets": []})
        self.assertFalse(result["has_data"])
        self.assertIsNone(result["existing_coverage_pct"])
        self.assertIsNone(result["residual_risk_pct"])
        self.assertEqual(result["recommended_controls"], [])

    def test_finding_with_no_asset_has_no_data(self):
        result = assess_coverage({"asset": {}, "title": "x", "description": ""}, controls={"assets": []})
        self.assertFalse(result["has_data"])


class AssessCoverageFirewallOnly(unittest.TestCase):
    def _controls(self, action):
        return {
            "assets": [{
                "match": {"name": "WIN-DC01"},
                "firewall_rules": [{"source": "internet", "dest": "WIN-DC01", "port": 443, "action": action}],
            }],
        }

    def test_deny_rule_gives_full_firewall_coverage(self):
        result = assess_coverage(_finding("WIN-DC01"), controls=self._controls("deny"))
        self.assertTrue(result["has_data"])
        # firewall alone = FIREWALL_WEIGHT(0.6)*1.0 + EDR_WEIGHT(0.4)*0 (no edr coverage recommendation) = 60,
        # but with no edr block at all a recommendation is still added for EDR.
        self.assertEqual(result["existing_coverage_pct"], 60)
        self.assertTrue(any("EDR" in c for c in result["recommended_controls"]))

    def test_allow_rule_gives_no_firewall_coverage_and_a_recommendation(self):
        result = assess_coverage(_finding("WIN-DC01"), controls=self._controls("allow"))
        self.assertEqual(result["existing_coverage_pct"], 0)
        self.assertTrue(any("Tighten the firewall rule" in c for c in result["recommended_controls"]))
        self.assertEqual(result["residual_risk_pct"], 100)


class AssessCoverageWithEdr(unittest.TestCase):
    def test_matching_block_mode_gives_full_edr_coverage(self):
        controls = {
            "assets": [{
                "match": {"name": "WIN-DC01"},
                "firewall_rules": [{"source": "internet", "dest": "WIN-DC01", "action": "deny"}],
                "edr": {"mode": "block", "signature_coverage": ["CVE-2024-56238"]},
            }],
        }
        result = assess_coverage(_finding("WIN-DC01", cve="CVE-2024-56238"), controls=controls)
        # Full firewall (0.6) + full EDR (0.4) = 100% existing coverage, nothing left to recommend.
        self.assertEqual(result["existing_coverage_pct"], 100)
        self.assertEqual(result["residual_risk_pct"], 0)
        self.assertEqual(result["recommended_controls"], [])

    def test_matching_detect_mode_recommends_escalation_to_block(self):
        controls = {
            "assets": [{
                "match": {"name": "WIN-DC01"},
                "firewall_rules": [{"source": "dmz", "dest": "WIN-DC01", "action": "allow"}],
                "edr": {"mode": "detect", "signature_coverage": ["CVE-2024-56238"]},
            }],
        }
        result = assess_coverage(_finding("WIN-DC01", cve="CVE-2024-56238"), controls=controls)
        self.assertTrue(any("detect-only to block" in c for c in result["recommended_controls"]))
        self.assertEqual(result["incremental_coverage_pct"], 100 - result["existing_coverage_pct"])

    def test_no_signature_match_recommends_new_coverage(self):
        controls = {
            "assets": [{
                "match": {"name": "WIN-DC01"},
                "firewall_rules": [],
                "edr": {"mode": "block", "signature_coverage": ["CVE-2099-99999"]},
            }],
        }
        result = assess_coverage(_finding("WIN-DC01", cve="CVE-2024-56238"), controls=controls)
        self.assertTrue(any("Add an EDR" in c for c in result["recommended_controls"]))


if __name__ == "__main__":
    unittest.main()
