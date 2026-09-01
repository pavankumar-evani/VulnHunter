"""
Tests for remediation/enrichment/eol_lookup.py - the End-of-Life/End-of-Support
classification heuristic. Same "keyword match against a small, real, transparent
reference table, never a guessed date" pattern as pattern_recognition.py's owner/team
suggestion - see that module's tests for the same shape of coverage.
"""
import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.eol_lookup import (  # noqa: E402
    EOL_REFERENCE, classify_eol, tag_eol_eos,
)


class ClassifyEol(unittest.TestCase):
    def test_unknown_os_string_returns_unknown_not_a_guess(self):
        self.assertEqual(classify_eol("Cisco IOS XE 17.x"), {"status": "unknown"})

    def test_none_os_string_returns_unknown(self):
        self.assertEqual(classify_eol(None), {"status": "unknown"})

    def test_empty_os_string_returns_unknown(self):
        self.assertEqual(classify_eol(""), {"status": "unknown"})

    def test_past_eol_date_classifies_as_eol(self):
        result = classify_eol("Microsoft Windows Server 2012 R2", as_of=datetime.date(2026, 8, 4))
        self.assertEqual(result["status"], "eol")
        self.assertEqual(result["eol_date"], "2023-10-10")
        self.assertLess(result["days_until_eol"], 0)

    def test_near_future_eol_date_classifies_as_eol_soon(self):
        # Windows Server 2016's real EOL (2027-01-12) is 161 days after 2026-08-04 -
        # inside the 180-day "eol-soon" window.
        result = classify_eol("Microsoft Windows Server 2016 Standard", as_of=datetime.date(2026, 8, 4))
        self.assertEqual(result["status"], "eol-soon")

    def test_far_future_eol_date_classifies_as_supported(self):
        result = classify_eol("Microsoft Windows Server 2022 Standard", as_of=datetime.date(2026, 8, 4))
        self.assertEqual(result["status"], "supported")

    def test_match_is_case_insensitive(self):
        result = classify_eol("MICROSOFT WINDOWS SERVER 2012 R2", as_of=datetime.date(2026, 8, 4))
        self.assertEqual(result["status"], "eol")

    def test_compound_os_string_still_matches(self):
        """OS Applications' asset.os strings are compound (e.g. "Windows 11 (client
        workstation) - Google Chrome") - the OS portion must still match even with an
        app-name suffix appended."""
        result = classify_eol("Windows 10 (client workstation) - Adobe Acrobat/Reader",
                               as_of=datetime.date(2026, 8, 4))
        self.assertEqual(result["status"], "eol")
        self.assertEqual(result["vendor"], "Microsoft")

    def test_longest_match_wins_on_ambiguity(self):
        """windows server 2019 must not accidentally match a shorter, unrelated entry -
        every real entry's match strings are checked, longest wins on any overlap."""
        result = classify_eol("Microsoft Windows Server 2019 Datacenter (Domain Controller)",
                               as_of=datetime.date(2026, 8, 4))
        self.assertEqual(result["eol_date"], "2029-01-09")

    def test_every_reference_entry_has_required_fields(self):
        required = {"match", "vendor", "eol_date", "source"}
        for entry in EOL_REFERENCE:
            self.assertTrue(required.issubset(entry.keys()), entry)
            # eol_date must be a real, parseable ISO date, not a placeholder string.
            datetime.date.fromisoformat(entry["eol_date"])


class TagEolEos(unittest.TestCase):
    def test_tag_adds_field_without_mutating_input(self):
        findings = [{"id": "FIND-1", "asset": {"os": "Microsoft Windows Server 2012 R2"}}]
        original_keys = set(findings[0].keys())
        tagged = tag_eol_eos(findings, as_of=datetime.date(2026, 8, 4))
        self.assertEqual(set(findings[0].keys()), original_keys)
        self.assertIn("eol_status", tagged[0])

    def test_tag_sets_unknown_for_unmatched_os(self):
        findings = [{"id": "FIND-1", "asset": {"os": "Cisco IOS 15.x"}}]
        tagged = tag_eol_eos(findings, as_of=datetime.date(2026, 8, 4))
        self.assertEqual(tagged[0]["eol_status"], {"status": "unknown"})

    def test_tag_handles_missing_asset_gracefully(self):
        findings = [{"id": "FIND-1"}]
        tagged = tag_eol_eos(findings, as_of=datetime.date(2026, 8, 4))
        self.assertEqual(tagged[0]["eol_status"], {"status": "unknown"})


if __name__ == "__main__":
    unittest.main()
