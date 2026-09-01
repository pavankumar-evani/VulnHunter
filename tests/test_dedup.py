"""
Tests for remediation/enrichment/dedup.py - cross-scanner deduplication.

Real data has zero existing cross-source duplicates today (confirmed against the actual
committed remediation/output/normalized-findings.json, 9,425 findings, both by cve+asset
and title+asset - see RealDataHasNoFalsePositives below), so the core matching/grouping/
primary-selection logic is exercised with hand-built synthetic fixtures, same convention
as test_enrichment.py.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.dedup import dedup_findings, dedup_file, _normalize_title_key  # noqa: E402


class TitleNormalization(unittest.TestCase):
    def test_lowercases_and_collapses_whitespace(self):
        self.assertEqual(_normalize_title_key("  Open   Telnet\tService  "), "open telnet service")

    def test_none_title_normalizes_to_empty_string_not_a_crash(self):
        self.assertEqual(_normalize_title_key(None), "")


class CveBasedMatching(unittest.TestCase):
    def test_same_cve_same_asset_different_sources_are_grouped(self):
        findings = [
            {"id": "FIND-1", "source": "tenable", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
            {"id": "FIND-2", "source": "armis", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-05"},
        ]
        result = dedup_findings(findings)
        self.assertEqual(result[0]["dedup"]["group_size"], 2)
        self.assertEqual(result[0]["dedup"]["match_basis"], "cve+asset")
        self.assertEqual(result[0]["dedup"]["group_id"], result[1]["dedup"]["group_id"])

    def test_same_cve_different_asset_are_not_grouped(self):
        findings = [
            {"id": "FIND-1", "source": "tenable", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
            {"id": "FIND-2", "source": "armis", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC02"}, "first_seen": "2026-07-05"},
        ]
        result = dedup_findings(findings)
        self.assertIsNone(result[0]["dedup"]["group_id"])
        self.assertIsNone(result[1]["dedup"]["group_id"])

    def test_different_cve_same_asset_are_not_grouped(self):
        findings = [
            {"id": "FIND-1", "source": "tenable", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
            {"id": "FIND-2", "source": "armis", "cve": "CVE-2022-99999", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-05"},
        ]
        result = dedup_findings(findings)
        self.assertIsNone(result[0]["dedup"]["group_id"])
        self.assertIsNone(result[1]["dedup"]["group_id"])


class TitleFallbackMatching(unittest.TestCase):
    def test_null_cve_findings_match_by_normalized_title_and_asset(self):
        findings = [
            {"id": "FIND-1", "source": "armis", "cve": None, "title": "  Open Telnet Service  ", "asset": {"name": "SRV-02"}, "first_seen": "2026-06-01"},
            {"id": "FIND-2", "source": "tenable", "cve": None, "title": "open telnet service", "asset": {"name": "SRV-02"}, "first_seen": "2026-06-15"},
        ]
        result = dedup_findings(findings)
        self.assertEqual(result[0]["dedup"]["group_size"], 2)
        self.assertEqual(result[0]["dedup"]["match_basis"], "title+asset")

    def test_cve_present_never_falls_back_to_title_matching(self):
        """A finding WITH a cve must never be grouped with a null-cve finding just
        because titles happen to match - cve+asset and title+asset are separate,
        non-overlapping identity spaces."""
        findings = [
            {"id": "FIND-1", "source": "tenable", "cve": "CVE-2021-34527", "title": "Print Spooler RCE", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
            {"id": "FIND-2", "source": "armis", "cve": None, "title": "Print Spooler RCE", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-05"},
        ]
        result = dedup_findings(findings)
        self.assertIsNone(result[0]["dedup"]["group_id"])
        self.assertIsNone(result[1]["dedup"]["group_id"])


class PrimarySelection(unittest.TestCase):
    def test_earliest_first_seen_is_primary(self):
        findings = [
            {"id": "FIND-1", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-05"},
            {"id": "FIND-2", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
        ]
        result = dedup_findings(findings)
        self.assertFalse(result[0]["dedup"]["is_primary"])
        self.assertTrue(result[1]["dedup"]["is_primary"])

    def test_exactly_one_primary_per_group_regardless_of_size(self):
        findings = [
            {"id": f"FIND-{i}", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"}
            for i in range(5)
        ]
        result = dedup_findings(findings)
        primaries = [f["dedup"]["is_primary"] for f in result]
        self.assertEqual(sum(primaries), 1)

    def test_tied_first_seen_breaks_by_lowest_id_deterministically(self):
        findings = [
            {"id": "FIND-9", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
            {"id": "FIND-3", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
        ]
        result = dedup_findings(findings)
        primary_ids = [f["id"] for f in result if f["dedup"]["is_primary"]]
        self.assertEqual(primary_ids, ["FIND-3"])

    def test_result_is_deterministic_regardless_of_input_order(self):
        a = {"id": "FIND-1", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"}
        b = {"id": "FIND-2", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-05"}
        forward = dedup_findings([a, b])
        backward = dedup_findings([b, a])
        forward_primary = next(f["id"] for f in forward if f["dedup"]["is_primary"])
        backward_primary = next(f["id"] for f in backward if f["dedup"]["is_primary"])
        self.assertEqual(forward_primary, backward_primary)


class DuplicateOfField(unittest.TestCase):
    def test_duplicate_of_lists_the_other_members_ids_not_its_own(self):
        findings = [
            {"id": "FIND-1", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
            {"id": "FIND-2", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-02"},
            {"id": "FIND-3", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-03"},
        ]
        result = dedup_findings(findings)
        by_id = {f["id"]: f for f in result}
        self.assertEqual(sorted(by_id["FIND-1"]["dedup"]["duplicate_of"]), ["FIND-2", "FIND-3"])
        self.assertNotIn("FIND-1", by_id["FIND-1"]["dedup"]["duplicate_of"])


class SingletonHandling(unittest.TestCase):
    def test_finding_with_no_match_gets_singleton_shape(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"}]
        result = dedup_findings(findings)
        self.assertEqual(result[0]["dedup"], {
            "group_id": None, "group_size": 1, "is_primary": True,
            "duplicate_of": [], "match_basis": None,
        })

    def test_finding_with_no_asset_name_is_never_grouped(self):
        """A missing asset name must never become a shared grouping key - that would
        wrongly lump every asset-less finding together."""
        findings = [
            {"id": "FIND-1", "cve": "CVE-2021-34527", "asset": {}, "first_seen": "2026-07-01"},
            {"id": "FIND-2", "cve": "CVE-2021-34527", "asset": None, "first_seen": "2026-07-01"},
        ]
        result = dedup_findings(findings)
        self.assertIsNone(result[0]["dedup"]["group_id"])
        self.assertIsNone(result[1]["dedup"]["group_id"])


class InputSafety(unittest.TestCase):
    def test_original_findings_list_and_dicts_are_not_mutated(self):
        original = [{"id": "FIND-1", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"}]
        dedup_findings(original)
        self.assertNotIn("dedup", original[0])

    def test_original_finding_fields_are_preserved(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2021-34527", "title": "PrintNightmare", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"}]
        result = dedup_findings(findings)
        self.assertEqual(result[0]["title"], "PrintNightmare")
        self.assertEqual(result[0]["id"], "FIND-1")

    def test_empty_findings_list_returns_empty_list(self):
        self.assertEqual(dedup_findings([]), [])


class DedupFileIO(unittest.TestCase):
    def test_dedup_file_writes_tagged_json(self):
        findings = [
            {"id": "FIND-1", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"},
            {"id": "FIND-2", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-05"},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = Path(tmpdir) / "findings.json"
            in_path.write_text(json.dumps(findings), encoding="utf-8")
            out_path = Path(tmpdir) / "out.json"

            dedup_file(in_path, output_path=out_path)

            result = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(result[0]["dedup"]["group_size"], 2)

    def test_dedup_file_defaults_to_overwriting_input(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2021-34527", "asset": {"name": "WIN-DC01"}, "first_seen": "2026-07-01"}]
        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = Path(tmpdir) / "findings.json"
            in_path.write_text(json.dumps(findings), encoding="utf-8")

            dedup_file(in_path)

            result = json.loads(in_path.read_text(encoding="utf-8"))
            self.assertIn("dedup", result[0])


class RealDataHasNoFalsePositives(unittest.TestCase):
    """Structural check against the actual committed artifact (same convention as
    tests/test_pipeline_artifacts.py) - proves the matching logic doesn't wrongly group
    any of the 9,425 real findings today, not just that it behaves on synthetic fixtures."""

    @classmethod
    def setUpClass(cls):
        path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        cls.findings = json.loads(path.read_text(encoding="utf-8"))
        cls.result = dedup_findings(cls.findings)

    def test_every_real_finding_gets_a_dedup_field(self):
        self.assertEqual(len(self.result), len(self.findings))
        for f in self.result:
            self.assertIn("dedup", f)

    def test_no_finding_is_missing_from_the_output(self):
        original_ids = {f["id"] for f in self.findings}
        result_ids = {f["id"] for f in self.result}
        self.assertEqual(original_ids, result_ids)

    def test_real_data_today_has_zero_cross_source_duplicates(self):
        """Documents a real, current fact about the sample dataset - not a claim this
        will always stay true. If a future connector introduces genuine overlapping
        findings, this test is expected to need updating, same as
        test_pipeline_artifacts.py's own floor-count assertions."""
        group_ids = {f["dedup"]["group_id"] for f in self.result if f["dedup"]["group_id"]}
        self.assertEqual(len(group_ids), 0)


if __name__ == "__main__":
    unittest.main()
