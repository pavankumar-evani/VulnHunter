"""
Tests for remediation/enrichment/compensating_controls.py. Same caveat as
test_attack_mapping.py: these check the heuristic fires (or falls back) on realistic
finding text, not that a suggestion is "the" objectively correct control - no such
ground truth exists for an automated keyword matcher.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.compensating_controls import (  # noqa: E402
    DEFAULT_CONTROLS, suggest_compensating_controls, tag_compensating_controls,
)


class SuggestCompensatingControls(unittest.TestCase):
    def test_exposed_management_service_suggests_network_restriction(self):
        f = {"title": "Telnet management interface exposed", "description": ""}
        controls = suggest_compensating_controls(f)
        self.assertTrue(any("ACL" in c or "firewall" in c for c in controls))

    def test_injection_finding_suggests_a_waf_rule(self):
        f = {"title": "SQL Injection via string concatenation", "description": ""}
        controls = suggest_compensating_controls(f)
        self.assertTrue(any("WAF" in c for c in controls))

    def test_hardcoded_secret_suggests_rotation(self):
        f = {"title": "Hardcoded Stripe API key", "description": ""}
        controls = suggest_compensating_controls(f)
        self.assertTrue(any("Rotate" in c for c in controls))

    def test_certificate_expiry_suggests_monitoring(self):
        f = {"title": "SSL certificate nearing expiration", "description": ""}
        controls = suggest_compensating_controls(f)
        self.assertTrue(any("expiry" in c for c in controls))

    def test_no_keyword_match_falls_back_to_default_controls(self):
        f = {"title": "Something entirely unrelated to any pattern", "description": ""}
        self.assertEqual(suggest_compensating_controls(f), DEFAULT_CONTROLS)

    def test_never_returns_an_empty_list(self):
        for title in ["", "random text", "PrintNightmare RCE", "Telnet exposed", "SQL Injection"]:
            controls = suggest_compensating_controls({"title": title, "description": ""})
            self.assertTrue(len(controls) > 0)


class TagCompensatingControlsBatch(unittest.TestCase):
    def test_tag_adds_field_without_mutating_input(self):
        findings = [{"id": "FIND-1", "title": "Hardcoded password", "description": ""}]
        original_keys = set(findings[0].keys())
        tagged = tag_compensating_controls(findings)
        self.assertEqual(set(findings[0].keys()), original_keys)  # input untouched
        self.assertIn("compensating_controls", tagged[0])

    def test_tag_against_real_sample_data(self):
        import json
        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        tagged = tag_compensating_controls(findings)
        self.assertTrue(all(len(f["compensating_controls"]) > 0 for f in tagged))


if __name__ == "__main__":
    unittest.main()
