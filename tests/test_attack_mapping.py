"""
Tests for remediation/enrichment/attack_mapping.py.

These check the heuristic fires (or deliberately doesn't) on realistic finding text -
they do not and cannot assert "this is the objectively correct ATT&CK technique for
this CVE," because no such ground truth exists for an automated keyword matcher. See
the module docstring.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.attack_mapping import map_finding_to_attack, tag_findings  # noqa: E402


class KeywordMatching(unittest.TestCase):
    def test_sql_injection_maps_to_exploit_public_facing_application(self):
        f = {"title": "SQL Injection via string concatenation", "description": ""}
        result = map_finding_to_attack(f)
        self.assertEqual(result[0]["technique_id"], "T1190")

    def test_command_injection_maps_to_command_and_scripting_interpreter(self):
        f = {"title": "Command injection via shell=True", "description": ""}
        result = map_finding_to_attack(f)
        self.assertEqual(result[0]["technique_id"], "T1059")

    def test_printnightmare_style_rce_maps_to_exploitation_of_remote_services(self):
        f = {"title": "MS Windows Print Spooler Remote Code Execution", "description": ""}
        result = map_finding_to_attack(f)
        self.assertEqual(result[0]["technique_id"], "T1210")

    def test_sudo_privilege_escalation_maps_correctly(self):
        f = {"title": "Sudo Heap-Based Buffer Overflow", "description": "allows local privilege escalation to root"}
        result = map_finding_to_attack(f)
        self.assertEqual(result[0]["technique_id"], "T1068")

    def test_hardcoded_secret_maps_to_unsecured_credentials(self):
        f = {"title": "Hardcoded Stripe API key", "description": ""}
        result = map_finding_to_attack(f)
        self.assertEqual(result[0]["technique_id"], "T1552")

    def test_telnet_exposure_maps_to_remote_services(self):
        f = {"title": "Device Exposes Telnet Service", "description": ""}
        result = map_finding_to_attack(f)
        self.assertEqual(result[0]["technique_id"], "T1021")

    def test_certificate_expiry_is_deliberately_unmapped(self):
        """A cert nearing expiry isn't an attack technique - it's a lifecycle finding.
        This must return an empty list, not a guessed/forced technique."""
        f = {"title": "SSL Certificate Expiry", "description": "expires within 30 days"}
        result = map_finding_to_attack(f)
        self.assertEqual(result, [])

    def test_no_keyword_match_returns_empty_list_not_a_guess(self):
        f = {"title": "Some completely unrelated finding about widgets", "description": ""}
        result = map_finding_to_attack(f)
        self.assertEqual(result, [])

    def test_all_matches_can_return_more_than_one_technique(self):
        f = {"title": "Command injection RCE via eval()", "description": ""}
        result = map_finding_to_attack(f, all_matches=True)
        technique_ids = {r["technique_id"] for r in result}
        self.assertIn("T1059", technique_ids)


class TagFindingsBatch(unittest.TestCase):
    def test_tag_findings_adds_field_without_mutating_input(self):
        findings = [{"id": "FIND-1", "title": "SQL Injection", "description": ""}]
        original_keys = set(findings[0].keys())
        tagged = tag_findings(findings)
        self.assertEqual(set(findings[0].keys()), original_keys)  # input untouched
        self.assertIn("attack_techniques", tagged[0])

    def test_tag_findings_against_real_sample_data(self):
        """Sanity check against our own real normalized-findings.json - PrintNightmare
        should map to something, cert expiry should map to nothing."""
        import json
        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        tagged = tag_findings(findings)
        by_id = {f["id"]: f for f in tagged}
        self.assertTrue(len(by_id["FIND-1"]["attack_techniques"]) > 0)   # PrintNightmare
        self.assertEqual(by_id["FIND-13"]["attack_techniques"], [])       # SSL cert expiry


if __name__ == "__main__":
    unittest.main()
