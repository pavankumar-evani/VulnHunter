"""
Tests for remediation/enrichment/scan_type_mapping.py - the finding-category
taxonomy (Infrastructure VM / SCA / Certificate Mgmt) derived from asset.type.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.scan_type_mapping import (  # noqa: E402
    SCAN_TYPE_LABELS, SCAN_TYPES, classify_finding, tag_scan_types,
)


class ClassifyFinding(unittest.TestCase):
    def test_certificate_asset_is_cert_mgmt(self):
        finding = {"asset": {"type": "certificate"}}
        self.assertEqual(classify_finding(finding), "cert-mgmt")

    def test_application_asset_with_a_cve_is_sca(self):
        """Has a CVE => a versioned, publicly-tracked vulnerable dependency - SCA."""
        finding = {"asset": {"type": "application"}, "cve": "CVE-2021-44228"}
        self.assertEqual(classify_finding(finding), "sca")

    def test_application_asset_without_a_cve_is_dast(self):
        """No CVE => an app-specific bug found by actively probing the running app,
        not a versioned shared component anyone else could look up - DAST."""
        finding = {"asset": {"type": "application"}, "cve": None}
        self.assertEqual(classify_finding(finding), "dast")

    def test_application_asset_missing_cve_key_entirely_is_dast(self):
        finding = {"asset": {"type": "application"}}
        self.assertEqual(classify_finding(finding), "dast")

    def test_windows_server_asset_is_infra_vm(self):
        finding = {"asset": {"type": "windows-server"}}
        self.assertEqual(classify_finding(finding), "infra-vm")

    def test_unix_server_asset_is_infra_vm(self):
        finding = {"asset": {"type": "unix-server"}}
        self.assertEqual(classify_finding(finding), "infra-vm")

    def test_network_and_iot_assets_are_infra_vm(self):
        for asset_type in ("network-routing-switching", "network-security-device", "iot-ot-device"):
            finding = {"asset": {"type": asset_type}}
            self.assertEqual(classify_finding(finding), "infra-vm", asset_type)

    def test_missing_asset_defaults_to_infra_vm_rather_than_crashing(self):
        self.assertEqual(classify_finding({}), "infra-vm")

    def test_unknown_asset_type_defaults_to_infra_vm(self):
        finding = {"asset": {"type": "some-future-asset-type"}}
        self.assertEqual(classify_finding(finding), "infra-vm")


class TagScanTypes(unittest.TestCase):
    def test_adds_scan_type_and_label_without_mutating_input(self):
        findings = [{"id": "FIND-1", "asset": {"type": "certificate"}}]
        tagged = tag_scan_types(findings)
        self.assertNotIn("scan_type", findings[0])  # input untouched
        self.assertEqual(tagged[0]["scan_type"], "cert-mgmt")
        self.assertEqual(tagged[0]["scan_type_label"], SCAN_TYPE_LABELS["cert-mgmt"])

    def test_tags_a_mixed_batch_correctly(self):
        findings = [
            {"id": "FIND-1", "asset": {"type": "certificate"}},
            {"id": "FIND-2", "asset": {"type": "application"}, "cve": "CVE-2021-44228"},
            {"id": "FIND-3", "asset": {"type": "windows-server"}},
            {"id": "FIND-4", "asset": {"type": "application"}, "cve": None},
        ]
        tagged = tag_scan_types(findings)
        self.assertEqual([f["scan_type"] for f in tagged], ["cert-mgmt", "sca", "infra-vm", "dast"])


class Taxonomy(unittest.TestCase):
    def test_dast_is_a_documented_scan_type_with_a_label(self):
        """DAST has no sample finding in this repo's demo data (see the module
        docstring), but the category itself must exist in the taxonomy - this is a
        regression guard against silently dropping it."""
        self.assertIn("dast", SCAN_TYPES)
        self.assertIn("dast", SCAN_TYPE_LABELS)

    def test_every_scan_type_has_a_label(self):
        for scan_type in SCAN_TYPES:
            self.assertIn(scan_type, SCAN_TYPE_LABELS)
            self.assertTrue(SCAN_TYPE_LABELS[scan_type])


if __name__ == "__main__":
    unittest.main()
