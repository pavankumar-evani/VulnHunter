"""
Tests for remediation/enrichment/attack_chains.py - entry/pivot/impact attack-chain
grouping built on attack_mapping.py's existing tactic tagging. Same heuristic caveat as
test_attack_mapping.py: these check the grouping logic fires on realistic tactic
combinations, not that a chain is "the" objectively correct attack path.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.attack_chains import build_chains  # noqa: E402


def _finding(finding_id, asset_name, title, description=""):
    return {"id": finding_id, "asset": {"name": asset_name}, "title": title, "description": description}


class BuildChains(unittest.TestCase):
    def test_entry_and_impact_on_same_asset_form_a_chain(self):
        findings = [
            _finding("FIND-1", "WIN-01", "SQL Injection via login form"),  # Initial Access
            _finding("FIND-2", "WIN-01", "Denial of service via infinite loop"),  # Impact
        ]
        chains = build_chains(findings)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["asset_name"], "WIN-01")
        self.assertEqual(len(chains[0]["entry"]), 1)
        self.assertEqual(chains[0]["entry"][0]["id"], "FIND-1")
        self.assertEqual(len(chains[0]["impact"]), 1)
        self.assertEqual(chains[0]["impact"][0]["id"], "FIND-2")
        self.assertEqual(chains[0]["pivots"], [])

    def test_pivot_finding_included_between_entry_and_impact(self):
        findings = [
            _finding("FIND-1", "WIN-01", "SQL Injection via login form"),  # entry
            _finding("FIND-2", "WIN-01", "Authentication bypass in admin panel"),  # pivot
            _finding("FIND-3", "WIN-01", "Denial of service via infinite loop"),  # impact
        ]
        chains = build_chains(findings)
        self.assertEqual(len(chains), 1)
        pivot_ids = [p["id"] for p in chains[0]["pivots"]]
        self.assertEqual(pivot_ids, ["FIND-2"])

    def test_entry_only_produces_no_chain(self):
        findings = [_finding("FIND-1", "WIN-01", "SQL Injection via login form")]
        self.assertEqual(build_chains(findings), [])

    def test_impact_only_produces_no_chain(self):
        findings = [_finding("FIND-1", "WIN-01", "Denial of service via infinite loop")]
        self.assertEqual(build_chains(findings), [])

    def test_unmapped_findings_never_join_a_chain(self):
        findings = [
            _finding("FIND-1", "WIN-01", "SQL Injection via login form"),  # entry
            _finding("FIND-2", "WIN-01", "Denial of service via infinite loop"),  # impact
            _finding("FIND-3", "WIN-01", "Something entirely unrelated to any pattern"),  # no tactic
        ]
        chains = build_chains(findings)
        all_ids = {f["id"] for stage in ("entry", "pivots", "impact") for f in chains[0][stage]}
        self.assertNotIn("FIND-3", all_ids)

    def test_different_assets_produce_separate_chains(self):
        findings = [
            _finding("FIND-1", "WIN-01", "SQL Injection via login form"),
            _finding("FIND-2", "WIN-01", "Denial of service via infinite loop"),
            _finding("FIND-3", "WIN-02", "SQL Injection via login form"),
            _finding("FIND-4", "WIN-02", "Denial of service via infinite loop"),
        ]
        chains = build_chains(findings)
        self.assertEqual(len(chains), 2)
        self.assertEqual({c["asset_name"] for c in chains}, {"WIN-01", "WIN-02"})

    def test_finding_with_no_asset_is_ignored(self):
        findings = [
            {"id": "FIND-1", "asset": {}, "title": "SQL Injection via login form"},
            _finding("FIND-2", "WIN-01", "SQL Injection via login form"),
            _finding("FIND-3", "WIN-01", "Denial of service via infinite loop"),
        ]
        chains = build_chains(findings)
        self.assertEqual(len(chains), 1)

    def test_does_not_mutate_input(self):
        findings = [_finding("FIND-1", "WIN-01", "SQL Injection via login form")]
        original_keys = set(findings[0].keys())
        build_chains(findings)
        self.assertEqual(set(findings[0].keys()), original_keys)

    def test_already_tagged_findings_are_not_re_tagged(self):
        # A finding pre-tagged with a DIFFERENT technique than title/description would
        # otherwise heuristically match - confirms build_chains() trusts an existing
        # attack_techniques field rather than always recomputing it.
        findings = [{
            "id": "FIND-1", "asset": {"name": "WIN-01"}, "title": "Nothing special",
            "attack_techniques": [{"technique_id": "T1190", "technique_name": "x", "tactic": "Initial Access"}],
        }, {
            "id": "FIND-2", "asset": {"name": "WIN-01"}, "title": "Nothing special either",
            "attack_techniques": [{"technique_id": "T1499", "technique_name": "y", "tactic": "Impact"}],
        }]
        chains = build_chains(findings)
        self.assertEqual(len(chains), 1)


if __name__ == "__main__":
    unittest.main()
