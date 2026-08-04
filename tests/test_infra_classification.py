"""
Tests for remediation/enrichment/infra_classification.py - the OS/Network/Network
Security/OT/Cloud sub-classification of Infrastructure Vulnerability Management
findings.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.infra_classification import (  # noqa: E402
    INFRA_CATEGORIES, INFRA_CATEGORY_LABELS, build_infra_category_counts,
    classify_infra_finding, tag_infra_categories,
)


def _finding(asset_type):
    return {"asset": {"type": asset_type}} if asset_type is not None else {"asset": {}}


class ClassifyFinding(unittest.TestCase):
    def test_windows_server_classifies_as_os(self):
        self.assertEqual(classify_infra_finding(_finding("windows-server")), "os")

    def test_windows_endpoint_also_classifies_as_os(self):
        self.assertEqual(classify_infra_finding(_finding("windows-endpoint")), "os")

    def test_unix_server_classifies_as_os(self):
        self.assertEqual(classify_infra_finding(_finding("unix-server")), "os")

    def test_network_routing_switching_classifies_as_network(self):
        self.assertEqual(classify_infra_finding(_finding("network-routing-switching")), "network")

    def test_network_security_device_classifies_as_network_security(self):
        self.assertEqual(classify_infra_finding(_finding("network-security-device")), "network-security")

    def test_iot_ot_device_classifies_as_ot(self):
        self.assertEqual(classify_infra_finding(_finding("iot-ot-device")), "ot")

    def test_cloud_infrastructure_classifies_as_cloud(self):
        self.assertEqual(classify_infra_finding(_finding("cloud-infrastructure")), "cloud")

    def test_application_asset_type_is_not_an_infra_category(self):
        """Application/certificate findings are a different domain entirely - this
        must return None, not a guessed/forced infra bucket."""
        self.assertIsNone(classify_infra_finding(_finding("application")))

    def test_certificate_asset_type_is_not_an_infra_category(self):
        self.assertIsNone(classify_infra_finding(_finding("certificate")))

    def test_missing_asset_type_returns_none(self):
        self.assertIsNone(classify_infra_finding(_finding(None)))
        self.assertIsNone(classify_infra_finding({}))


class TagInfraCategories(unittest.TestCase):
    def test_tag_infra_categories_adds_fields_without_mutating_input(self):
        findings = [_finding("windows-server")]
        original_keys = set(findings[0].keys())
        tagged = tag_infra_categories(findings)
        self.assertEqual(set(findings[0].keys()), original_keys)
        self.assertIn("infra_category", tagged[0])
        self.assertIn("infra_category_label", tagged[0])

    def test_tag_sets_the_correct_label(self):
        tagged = tag_infra_categories([_finding("iot-ot-device")])
        self.assertEqual(tagged[0]["infra_category"], "ot")
        self.assertEqual(tagged[0]["infra_category_label"], "OT / IoT")

    def test_tag_sets_none_label_for_a_non_infra_finding(self):
        tagged = tag_infra_categories([_finding("application")])
        self.assertIsNone(tagged[0]["infra_category"])
        self.assertIsNone(tagged[0]["infra_category_label"])


class InfraCategoryCounts(unittest.TestCase):
    def test_counts_include_every_known_category_even_with_zero_findings(self):
        rows = build_infra_category_counts([])
        self.assertEqual(len(rows), len(INFRA_CATEGORIES))
        self.assertTrue(all(row["count"] == 0 for row in rows))

    def test_cloud_shows_zero_by_default_honestly(self):
        rows = build_infra_category_counts(tag_infra_categories([_finding("windows-server")]))
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(by_id["cloud"]["count"], 0)
        self.assertEqual(by_id["cloud"]["label"], INFRA_CATEGORY_LABELS["cloud"])

    def test_counts_real_tagged_findings_per_category(self):
        findings = tag_infra_categories([
            _finding("windows-server"), _finding("unix-server"), _finding("windows-endpoint"),
            _finding("network-routing-switching"),
            _finding("network-security-device"),
            _finding("iot-ot-device"),
            _finding("application"),  # not infra - must not count anywhere
        ])
        rows = build_infra_category_counts(findings)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(by_id["os"]["count"], 3)
        self.assertEqual(by_id["network"]["count"], 1)
        self.assertEqual(by_id["network-security"]["count"], 1)
        self.assertEqual(by_id["ot"]["count"], 1)
        self.assertEqual(sum(row["count"] for row in rows), 6)  # the application finding excluded


if __name__ == "__main__":
    unittest.main()
