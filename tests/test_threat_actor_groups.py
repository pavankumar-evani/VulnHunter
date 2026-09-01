"""
Tests for remediation/enrichment/threat_actor_groups.py.

These check the reference data's structural integrity and the correlation logic against
synthetic findings - not "this is the objectively correct attribution," since (per the
module docstring) a shared technique doesn't prove a specific group caused a specific
finding. See ai_vuln_taxonomy.py's/attack_mapping.py's tests for the same style of check
applied to this project's other illustrative-cross-reference taxonomies.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.threat_actor_groups import (  # noqa: E402
    INDUSTRIES, THREAT_ACTOR_GROUPS, correlate_findings, groups_for_technique,
)


class ReferenceData(unittest.TestCase):
    def test_every_entry_has_the_required_fields(self):
        required = {
            "id", "name", "aliases", "mitre_url", "summary", "associated_technique_ids",
            "target_industries", "status", "most_recent_activity",
        }
        for g in THREAT_ACTOR_GROUPS:
            self.assertTrue(required.issubset(g.keys()), g.get("id"))

    def test_every_group_is_currently_active(self):
        # All 6 groups were re-verified 2026-08-05 as currently active (not retired) on
        # their live MITRE pages - see the module docstring's honesty note.
        for g in THREAT_ACTOR_GROUPS:
            self.assertEqual(g["status"], "active", g["id"])

    def test_every_target_industry_is_a_known_industry(self):
        for g in THREAT_ACTOR_GROUPS:
            for industry in g["target_industries"]:
                self.assertIn(industry, INDUSTRIES, f"{g['id']}: {industry}")

    def test_every_group_has_at_least_one_target_industry(self):
        for g in THREAT_ACTOR_GROUPS:
            self.assertTrue(len(g["target_industries"]) > 0, g["id"])

    def test_not_every_industry_is_claimed_real_absence_is_allowed(self):
        # Capital Markets/Insurance have no verified sector-specific victimology for any
        # of these 6 groups today - an honest absence, not a bug (see module docstring).
        claimed = {ind for g in THREAT_ACTOR_GROUPS for ind in g["target_industries"]}
        self.assertNotIn("Capital Markets", claimed)
        self.assertNotIn("Insurance", claimed)

    def test_every_id_is_unique(self):
        ids = [g["id"] for g in THREAT_ACTOR_GROUPS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_id_is_a_real_mitre_group_id_shape(self):
        # Real MITRE ATT&CK group IDs are "G" followed by digits (e.g. G0007) - a shape
        # check, not proof of existence, but catches an obvious typo/placeholder.
        import re
        for g in THREAT_ACTOR_GROUPS:
            self.assertRegex(g["id"], r"^G\d{4,}$", g["id"])

    def test_every_mitre_url_points_at_the_groups_page_for_its_own_id(self):
        for g in THREAT_ACTOR_GROUPS:
            self.assertEqual(g["mitre_url"], f"https://attack.mitre.org/groups/{g['id']}/")

    def test_every_group_has_at_least_one_associated_technique(self):
        for g in THREAT_ACTOR_GROUPS:
            self.assertTrue(len(g["associated_technique_ids"]) > 0, g["id"])


class GroupsForTechnique(unittest.TestCase):
    def test_returns_matching_groups(self):
        # T1059 (Command and Scripting Interpreter) is associated with several groups
        # in this reference set - a real, broadly-shared technique.
        groups = groups_for_technique("T1059")
        self.assertTrue(len(groups) >= 2)
        self.assertTrue(all("T1059" in g["associated_technique_ids"] for g in groups))

    def test_unknown_technique_returns_empty(self):
        self.assertEqual(groups_for_technique("T9999"), [])


class CorrelateFindings(unittest.TestCase):
    def test_finding_with_matching_technique_surfaces_its_group(self):
        findings = [{"id": "FIND-1", "attack_techniques": [{"technique_id": "T1059"}]}]
        results = correlate_findings(findings)
        self.assertTrue(len(results) > 0)
        self.assertTrue(all("T1059" in g["matched_technique_ids"] for g in results))

    def test_finding_with_no_techniques_surfaces_nothing(self):
        findings = [{"id": "FIND-1", "attack_techniques": []}, {"id": "FIND-2"}]
        self.assertEqual(correlate_findings(findings), [])

    def test_finding_with_unknown_technique_surfaces_nothing(self):
        findings = [{"id": "FIND-1", "attack_techniques": [{"technique_id": "T9999"}]}]
        self.assertEqual(correlate_findings(findings), [])

    def test_results_sorted_by_finding_count_descending(self):
        findings = (
            [{"id": f"FIND-{i}", "attack_techniques": [{"technique_id": "T1059"}]} for i in range(5)]
            + [{"id": "FIND-X", "attack_techniques": [{"technique_id": "T1071"}]}]
        )
        results = correlate_findings(findings)
        counts = [g["finding_count"] for g in results]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_does_not_mutate_input(self):
        findings = [{"id": "FIND-1", "attack_techniques": [{"technique_id": "T1059"}]}]
        original = [dict(f) for f in findings]
        correlate_findings(findings)
        self.assertEqual(findings, original)


if __name__ == "__main__":
    unittest.main()
