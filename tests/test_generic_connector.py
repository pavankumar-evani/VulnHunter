"""
Tests for remediation/connectors/generic_connector.py - the vendor-agnostic "bring
your own XDR/EDR/SIEM" webhook adapter. Pure validation/normalization logic only, no
network, no file I/O (dashboard/app.py owns writing accepted findings to
remediation/live-data/, tested separately in tests/test_dashboard.py).
"""
import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.generic_connector import (  # noqa: E402
    normalize_generic_finding, validate_generic_payload,
)


class ValidateGenericPayload(unittest.TestCase):
    def test_valid_minimal_payload_has_no_errors(self):
        payload = {"title": "Reflected XSS", "severity": "High",
                   "asset_name": "APP-ORDERS01", "asset_type": "application"}
        self.assertEqual(validate_generic_payload(payload), [])

    def test_non_dict_payload_is_rejected(self):
        self.assertTrue(validate_generic_payload(["not", "a", "dict"]))
        self.assertTrue(validate_generic_payload(None))

    def test_missing_required_fields_are_each_reported(self):
        errors = validate_generic_payload({})
        self.assertEqual(len(errors), 4)  # title, severity, asset_name, asset_type

    def test_invalid_severity_is_rejected(self):
        payload = {"title": "t", "severity": "Extreme", "asset_name": "a", "asset_type": "application"}
        errors = validate_generic_payload(payload)
        self.assertTrue(any("severity" in e for e in errors))

    def test_invalid_asset_type_is_rejected(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "toaster"}
        errors = validate_generic_payload(payload)
        self.assertTrue(any("asset_type" in e for e in errors))

    def test_malformed_cve_is_rejected(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application",
                   "cve": "not-a-cve"}
        errors = validate_generic_payload(payload)
        self.assertTrue(any("cve" in e for e in errors))

    def test_well_formed_cve_passes(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application",
                   "cve": "CVE-2021-44228"}
        self.assertEqual(validate_generic_payload(payload), [])

    def test_null_cve_is_allowed(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application",
                   "cve": None}
        self.assertEqual(validate_generic_payload(payload), [])


class NormalizeGenericFinding(unittest.TestCase):
    def test_maps_required_fields_into_the_normalized_schema(self):
        payload = {"title": "Reflected XSS", "severity": "High",
                   "asset_name": "APP-ORDERS01", "asset_type": "application"}
        finding = normalize_generic_finding(payload, [], as_of=datetime.date(2026, 8, 4))
        self.assertEqual(finding["title"], "Reflected XSS")
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["asset"], {"name": "APP-ORDERS01", "ip": None, "type": "application", "os": None})

    def test_source_defaults_to_generic(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application"}
        finding = normalize_generic_finding(payload, [])
        self.assertEqual(finding["source"], "generic")

    def test_source_name_override_is_respected(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application"}
        finding = normalize_generic_finding(payload, [], source_name="splunk-es")
        self.assertEqual(finding["source"], "splunk-es")

    def test_kev_and_epss_are_always_null_for_generic_findings(self):
        """Threat-intel enrichment is a separate pipeline stage (threat-intel-enricher)
        that only runs against normalized-findings.json - generic ingestion doesn't
        fabricate KEV/EPSS data it never actually checked."""
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application"}
        finding = normalize_generic_finding(payload, [])
        self.assertIsNone(finding["kev"])
        self.assertIsNone(finding["epss"])

    def test_first_seen_defaults_to_as_of_when_not_provided(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application"}
        finding = normalize_generic_finding(payload, [], as_of=datetime.date(2026, 8, 4))
        self.assertEqual(finding["first_seen"], "2026-08-04")

    def test_explicit_first_seen_is_respected(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application",
                   "first_seen": "2026-01-15"}
        finding = normalize_generic_finding(payload, [])
        self.assertEqual(finding["first_seen"], "2026-01-15")

    def test_assigns_next_sequential_id_after_existing_findings(self):
        existing = [{"id": "FIND-1"}, {"id": "FIND-14"}, {"id": "FIND-7"}]
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application"}
        finding = normalize_generic_finding(payload, existing)
        self.assertEqual(finding["id"], "FIND-15")

    def test_starts_at_find_1_with_no_existing_findings(self):
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application"}
        finding = normalize_generic_finding(payload, [])
        self.assertEqual(finding["id"], "FIND-1")

    def test_ignores_non_find_prefixed_ids_when_computing_the_next_id(self):
        existing = [{"id": "EXC-99"}, {"id": "FIND-3"}]
        payload = {"title": "t", "severity": "High", "asset_name": "a", "asset_type": "application"}
        finding = normalize_generic_finding(payload, existing)
        self.assertEqual(finding["id"], "FIND-4")


if __name__ == "__main__":
    unittest.main()
