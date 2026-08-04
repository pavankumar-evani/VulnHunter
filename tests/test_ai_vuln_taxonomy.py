"""
Tests for remediation/enrichment/ai_vuln_taxonomy.py.

Like test_attack_mapping.py, these check the keyword heuristic fires (or deliberately
doesn't) on realistic finding text - not "this is the objectively correct ATLAS
technique," since no such live-verified ground truth exists here either. See the
module docstring for the same illustrative-cross-reference caveat already applied to
attack_mapping.py's ATT&CK tagging.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.ai_vuln_taxonomy import (  # noqa: E402
    AI_VULNERABILITIES, build_ai_atlas_heatmap, get_vulnerability,
    map_finding_to_ai_vuln, tag_findings,
)


class Taxonomy(unittest.TestCase):
    def test_every_entry_has_the_required_fields(self):
        required = {"id", "name", "summary", "remediation", "atlas_tactic",
                    "atlas_technique_id", "atlas_technique_name"}
        for v in AI_VULNERABILITIES:
            self.assertTrue(required.issubset(v.keys()), v["id"])

    def test_every_id_is_unique(self):
        ids = [v["id"] for v in AI_VULNERABILITIES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_get_vulnerability_returns_the_matching_entry(self):
        v = get_vulnerability("prompt-injection")
        self.assertEqual(v["name"], "Prompt Injection")

    def test_get_vulnerability_returns_none_for_unknown_id(self):
        self.assertIsNone(get_vulnerability("not-a-real-id"))


class KeywordMatching(unittest.TestCase):
    def test_prompt_injection_matches(self):
        f = {"title": "Prompt injection via unsanitized user message", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertEqual(result["id"], "prompt-injection")

    def test_jailbreak_also_matches_prompt_injection(self):
        f = {"title": "Chatbot jailbreak bypasses content policy", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertEqual(result["id"], "prompt-injection")

    def test_system_prompt_leak_matches_sensitive_info_disclosure(self):
        f = {"title": "System prompt leak via crafted query", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertEqual(result["id"], "sensitive-info-disclosure")

    def test_training_data_poisoning_matches(self):
        f = {"title": "Training data poisoning in fine-tuning pipeline", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertEqual(result["id"], "training-data-model-poisoning")

    def test_backdoored_model_also_matches_poisoning(self):
        f = {"title": "Backdoored model returns malicious output on trigger phrase", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertEqual(result["id"], "training-data-model-poisoning")

    def test_unsafe_pickle_deserialization_matches_supply_chain(self):
        f = {"title": "Model checkpoint loaded via unsafe pickle deserialization", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertEqual(result["id"], "supply-chain")

    def test_model_denial_of_service_matches_unbounded_consumption(self):
        f = {"title": "Model denial of service via oversized context", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertEqual(result["id"], "unbounded-consumption")

    def test_model_extraction_matches_model_theft(self):
        f = {"title": "Model extraction attack via systematic API querying", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertEqual(result["id"], "model-theft")

    def test_no_keyword_match_returns_none_not_a_guess(self):
        f = {"title": "SQL Injection via string concatenation", "description": ""}
        result = map_finding_to_ai_vuln(f)
        self.assertIsNone(result)

    def test_no_ai_findings_in_this_repos_real_demo_data(self):
        """Honest scope check: this repo's demo app isn't an AI/ML system, so real
        sample findings should never match this taxonomy - see the module docstring."""
        import json
        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        for f in findings:
            self.assertIsNone(map_finding_to_ai_vuln(f), f.get("id"))


class TagFindingsBatch(unittest.TestCase):
    def test_tag_findings_adds_field_without_mutating_input(self):
        findings = [{"id": "FIND-1", "title": "Prompt injection", "description": ""}]
        original_keys = set(findings[0].keys())
        tagged = tag_findings(findings)
        self.assertEqual(set(findings[0].keys()), original_keys)
        self.assertIn("ai_vulnerability", tagged[0])

    def test_tag_findings_sets_none_for_a_non_matching_finding(self):
        findings = [{"title": "Unrelated finding", "description": ""}]
        tagged = tag_findings(findings)
        self.assertIsNone(tagged[0]["ai_vulnerability"])

    def test_tag_findings_sets_the_matched_id(self):
        findings = [{"title": "Model theft via extraction", "description": ""}]
        tagged = tag_findings(findings)
        self.assertEqual(tagged[0]["ai_vulnerability"], "model-theft")


class AiAtlasHeatmap(unittest.TestCase):
    def test_heatmap_includes_every_known_vulnerability_even_with_zero_findings(self):
        heatmap = build_ai_atlas_heatmap([])
        self.assertEqual(len(heatmap), len(AI_VULNERABILITIES))
        self.assertTrue(all(row["count"] == 0 for row in heatmap))

    def test_heatmap_counts_real_tagged_findings(self):
        findings = tag_findings([
            {"title": "Prompt injection bypass", "description": ""},
            {"title": "Another prompt injection", "description": ""},
            {"title": "Model extraction attack", "description": ""},
        ])
        heatmap = build_ai_atlas_heatmap(findings)
        by_id = {row["id"]: row for row in heatmap}
        self.assertEqual(by_id["prompt-injection"]["count"], 2)
        self.assertEqual(by_id["model-theft"]["count"], 1)

    def test_heatmap_ignores_findings_with_no_matched_vulnerability(self):
        findings = tag_findings([{"title": "SQL Injection", "description": ""}])
        heatmap = build_ai_atlas_heatmap(findings)
        self.assertTrue(all(row["count"] == 0 for row in heatmap))

    def test_heatmap_rows_carry_the_atlas_cross_reference(self):
        heatmap = build_ai_atlas_heatmap([])
        by_id = {row["id"]: row for row in heatmap}
        self.assertEqual(by_id["prompt-injection"]["atlas_technique_id"], "AML.T0051")
        self.assertEqual(by_id["prompt-injection"]["atlas_tactic"], "Initial Access")


if __name__ == "__main__":
    unittest.main()
