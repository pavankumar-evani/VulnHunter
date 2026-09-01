"""
Tests for remediation/enrichment/poc_enrichment.py - the real, NVD-cache-derived
poc_available/user_interaction_required signal backfill. Uses small fabricated
NVD-response-shaped fixtures written to a temp directory - never touches the real
(gitignored) bulk/_nvd_cache/ directory, so these tests are deterministic regardless
of what's been generated locally.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.poc_enrichment import (  # noqa: E402
    build_nvd_signal_index, enrich_file, enrich_findings, poc_available,
    user_interaction_required,
)


_CVSS_VERSION_KEYS = {"v40": "cvssMetricV40", "v31": "cvssMetricV31", "v30": "cvssMetricV30"}


def _cve(cve_id, tags=None, user_interaction=None, cvss_version="v31"):
    references = [{"url": "https://example.test", "tags": tags}] if tags is not None else []
    metrics = {}
    if user_interaction is not None:
        metrics[_CVSS_VERSION_KEYS[cvss_version]] = [{"cvssData": {"userInteraction": user_interaction}}]
    return {"cve": {"id": cve_id, "references": references, "metrics": metrics}}


class PocAvailable(unittest.TestCase):
    def test_true_when_a_reference_is_tagged_exploit(self):
        cve = _cve("CVE-2099-0001", tags=["Exploit", "Third Party Advisory"])["cve"]
        self.assertTrue(poc_available(cve))

    def test_false_when_no_reference_is_tagged_exploit(self):
        cve = _cve("CVE-2099-0002", tags=["Vendor Advisory"])["cve"]
        self.assertFalse(poc_available(cve))

    def test_false_when_no_references_at_all(self):
        self.assertFalse(poc_available({"id": "CVE-2099-0003"}))


class UserInteractionRequired(unittest.TestCase):
    def test_required_metric_is_true(self):
        cve = _cve("CVE-2099-0004", user_interaction="REQUIRED")["cve"]
        self.assertTrue(user_interaction_required(cve))

    def test_none_metric_is_false(self):
        cve = _cve("CVE-2099-0005", user_interaction="NONE")["cve"]
        self.assertFalse(user_interaction_required(cve))

    def test_v2_only_cve_returns_none_not_a_guess(self):
        cve = {"id": "CVE-2099-0006", "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}}
        self.assertIsNone(user_interaction_required(cve))

    def test_no_metrics_at_all_returns_none(self):
        self.assertIsNone(user_interaction_required({"id": "CVE-2099-0007"}))

    def test_v40_passive_is_true(self):
        cve = _cve("CVE-2099-0008", user_interaction="PASSIVE", cvss_version="v40")["cve"]
        self.assertTrue(user_interaction_required(cve))

    def test_v40_active_is_true(self):
        cve = _cve("CVE-2099-0009", user_interaction="ACTIVE", cvss_version="v40")["cve"]
        self.assertTrue(user_interaction_required(cve))

    def test_v40_none_is_false(self):
        cve = _cve("CVE-2099-0010", user_interaction="NONE", cvss_version="v40")["cve"]
        self.assertFalse(user_interaction_required(cve))

    def test_v40_is_preferred_over_v31_when_both_present(self):
        cve = {
            "id": "CVE-2099-0011",
            "metrics": {
                "cvssMetricV40": [{"cvssData": {"userInteraction": "ACTIVE"}}],
                "cvssMetricV31": [{"cvssData": {"userInteraction": "NONE"}}],
            },
        }
        self.assertTrue(user_interaction_required(cve))

    def test_falls_back_to_v31_when_v40_absent(self):
        cve = _cve("CVE-2099-0012", user_interaction="REQUIRED", cvss_version="v31")["cve"]
        self.assertTrue(user_interaction_required(cve))


class BuildNvdSignalIndex(unittest.TestCase):
    def test_missing_cache_dir_returns_empty_dict_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist"
            self.assertEqual(build_nvd_signal_index(missing), {})

    def test_scans_every_cached_file_and_builds_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            (cache_dir / "a.json").write_text(json.dumps([
                _cve("CVE-2099-1001", tags=["Exploit"], user_interaction="NONE"),
            ]), encoding="utf-8")
            (cache_dir / "b.json").write_text(json.dumps([
                _cve("CVE-2099-1002", tags=["Vendor Advisory"], user_interaction="REQUIRED"),
            ]), encoding="utf-8")

            index = build_nvd_signal_index(cache_dir)

            self.assertEqual(index["CVE-2099-1001"],
                              {"poc_available": True, "user_interaction_required": False})
            self.assertEqual(index["CVE-2099-1002"],
                              {"poc_available": False, "user_interaction_required": True})


class EnrichFindings(unittest.TestCase):
    def setUp(self):
        self.index = {"CVE-2099-2001": {"poc_available": True, "user_interaction_required": False}}

    def test_finding_with_indexed_cve_gets_real_signals(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2099-2001"}]
        enriched = enrich_findings(findings, signal_index=self.index)
        self.assertEqual(enriched[0]["poc_available"], True)
        self.assertEqual(enriched[0]["user_interaction_required"], False)

    def test_finding_with_unindexed_cve_gets_none_not_a_guess(self):
        findings = [{"id": "FIND-2", "cve": "CVE-2099-9999"}]
        enriched = enrich_findings(findings, signal_index=self.index)
        self.assertIsNone(enriched[0]["poc_available"])
        self.assertIsNone(enriched[0]["user_interaction_required"])

    def test_finding_with_no_cve_gets_none(self):
        findings = [{"id": "FIND-3"}]
        enriched = enrich_findings(findings, signal_index=self.index)
        self.assertIsNone(enriched[0]["poc_available"])
        self.assertIsNone(enriched[0]["user_interaction_required"])

    def test_does_not_mutate_input(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2099-2001"}]
        original_keys = set(findings[0].keys())
        enrich_findings(findings, signal_index=self.index)
        self.assertEqual(set(findings[0].keys()), original_keys)


class EnrichFile(unittest.TestCase):
    def test_round_trips_through_a_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "cache"
            cache_dir.mkdir()
            (cache_dir / "a.json").write_text(json.dumps([
                _cve("CVE-2099-3001", tags=["Exploit"], user_interaction="NONE"),
            ]), encoding="utf-8")

            findings_path = Path(tmp) / "findings.json"
            findings_path.write_text(json.dumps([{"id": "FIND-1", "cve": "CVE-2099-3001"}]),
                                      encoding="utf-8")

            out = enrich_file(findings_path, cache_dir=cache_dir)
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(result[0]["poc_available"])
            self.assertFalse(result[0]["user_interaction_required"])


if __name__ == "__main__":
    unittest.main()
