"""
Tests for remediation/enrichment/blast_radius.py - the per-asset Blast Radius scoring
engine. Like test_risk_scoring.py, these check the formula's real behavior against
synthetic inputs - not "this is the objectively correct blast radius," since (per the
module docstring) two of the four source-framework profiling dimensions (Identity &
Privilege, real Network Topology) aren't available with this app's real data at all,
and are honestly disclosed as such rather than approximated.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.config import priority_engine  # noqa: E402
from remediation.enrichment.blast_radius import (  # noqa: E402
    PROFILING_COVERAGE, cross_reference_immediate_risks, load_rules, score_blast_radius,
)


def _asset_row(**overrides):
    row = {
        "name": "GENERIC-ASSET-01",
        "type": "unix-server",
        "facing": "unknown",
        "kev_count": 0,
        "likelihood_score": 0,
    }
    row.update(overrides)
    return row


class ScoreRange(unittest.TestCase):
    def test_scores_always_within_0_to_100(self):
        rows = [
            _asset_row(name="A", type="virtualization-host", facing="external"),
            _asset_row(name="B", type="printer", facing="internal"),
        ]
        scored = score_blast_radius(rows)
        for row in scored:
            self.assertGreaterEqual(row["blast_radius_score"], 0)
            self.assertLessEqual(row["blast_radius_score"], 100)


class CriticalityEffect(unittest.TestCase):
    def test_dc_named_asset_scores_higher_than_generic_asset(self):
        rows = [
            _asset_row(name="WIN-DC01", type="windows-server"),
            _asset_row(name="WEB-05", type="windows-server"),
        ]
        scored = {r["name"]: r for r in score_blast_radius(rows)}
        self.assertGreater(scored["WIN-DC01"]["blast_radius_score"], scored["WEB-05"]["blast_radius_score"])
        self.assertEqual(scored["WIN-DC01"]["blast_radius_factors"]["matched_criticality_keyword"], "dc")

    def test_virtualization_host_scores_higher_than_a_plain_server(self):
        rows = [
            _asset_row(name="HYPERVISOR-01", type="virtualization-host"),
            _asset_row(name="SERVER-01", type="unix-server"),
        ]
        scored = {r["name"]: r for r in score_blast_radius(rows)}
        self.assertGreater(scored["HYPERVISOR-01"]["blast_radius_score"], scored["SERVER-01"]["blast_radius_score"])


class NetworkReachabilityEffect(unittest.TestCase):
    def test_external_facing_scores_higher_than_internal(self):
        rows = [
            _asset_row(name="EXT", facing="external"),
            _asset_row(name="INT", facing="internal"),
        ]
        scored = {r["name"]: r for r in score_blast_radius(rows)}
        self.assertGreater(scored["EXT"]["blast_radius_score"], scored["INT"]["blast_radius_score"])

    def test_unknown_facing_scores_equal_to_internal_not_external(self):
        rows = [
            _asset_row(name="UNKNOWN", facing="unknown"),
            _asset_row(name="INTERNAL", facing="internal"),
            _asset_row(name="EXTERNAL", facing="external"),
        ]
        scored = {r["name"]: r for r in score_blast_radius(rows)}
        self.assertEqual(scored["UNKNOWN"]["blast_radius_score"], scored["INTERNAL"]["blast_radius_score"])
        self.assertLess(scored["UNKNOWN"]["blast_radius_score"], scored["EXTERNAL"]["blast_radius_score"])

    def test_missing_facing_key_treated_same_as_unknown(self):
        row = _asset_row(name="NO-FACING-KEY")
        del row["facing"]
        scored = score_blast_radius([row])[0]
        self.assertEqual(scored["blast_radius_factors"]["facing"], "unknown")


class DoesNotMutateInput(unittest.TestCase):
    def test_score_blast_radius_does_not_mutate_input(self):
        rows = [_asset_row(name="A")]
        rows_before = [dict(r) for r in rows]
        score_blast_radius(rows)
        self.assertEqual(rows, rows_before)


class RealRulesFileIsValid(unittest.TestCase):
    def test_real_rules_file_loads_and_has_expected_top_level_keys(self):
        rules = load_rules()
        required = {"component_weights", "facing_points", "blast_radius_tier_thresholds",
                     "immediate_risk_blast_radius_threshold", "immediate_risk_likelihood_threshold"}
        self.assertTrue(required.issubset(rules.keys()))

    def test_does_not_redeclare_asset_criticality_keywords(self):
        # blast_radius_rules.yaml must not define its own copy of the keywords
        # priority_rules.yaml already owns - confirms there's exactly one source.
        rules = load_rules()
        self.assertNotIn("asset_criticality_keywords", rules)
        self.assertNotIn("asset_type_weights", rules)
        priority_rules = priority_engine.load_rules()
        self.assertIn("asset_criticality_keywords", priority_rules)


class CrossReferenceImmediateRisks(unittest.TestCase):
    def test_high_blast_radius_with_kev_qualifies(self):
        rows = [_asset_row(name="A", type="virtualization-host", facing="external", kev_count=1)]
        scored = score_blast_radius(rows)
        result = cross_reference_immediate_risks(scored)
        self.assertEqual([r["name"] for r in result], ["A"])

    def test_high_blast_radius_with_high_likelihood_but_no_kev_still_qualifies(self):
        rows = [_asset_row(name="A", type="virtualization-host", facing="external",
                            kev_count=0, likelihood_score=75)]
        scored = score_blast_radius(rows)
        result = cross_reference_immediate_risks(scored)
        self.assertEqual([r["name"] for r in result], ["A"])

    def test_high_blast_radius_alone_does_not_qualify_without_exploitability(self):
        rows = [_asset_row(name="A", type="virtualization-host", facing="external",
                            kev_count=0, likelihood_score=0)]
        scored = score_blast_radius(rows)
        self.assertEqual(cross_reference_immediate_risks(scored), [])

    def test_high_exploitability_alone_does_not_qualify_without_blast_radius(self):
        rows = [_asset_row(name="A", type="printer", facing="internal", kev_count=1)]
        scored = score_blast_radius(rows)
        self.assertEqual(cross_reference_immediate_risks(scored), [])

    def test_results_sorted_by_blast_radius_descending(self):
        # Both must clear immediate_risk_blast_radius_threshold (60) to appear in the
        # result at all - same "dc" keyword + virtualization-host type for both (so
        # criticality is identical), differing only in facing, so HIGHER > LOWER but
        # both genuinely qualify rather than one being silently filtered out.
        rows = [
            _asset_row(name="LOWER-DC", type="virtualization-host", facing="internal", kev_count=1),
            _asset_row(name="HIGHER-DC", type="virtualization-host", facing="external", kev_count=1),
        ]
        scored = score_blast_radius(rows)
        result = cross_reference_immediate_risks(scored)
        self.assertEqual([r["name"] for r in result], ["HIGHER-DC", "LOWER-DC"])


class ProfilingCoverageIsHonest(unittest.TestCase):
    def test_exactly_two_dimensions_available_two_not(self):
        statuses = [d["status"] for d in PROFILING_COVERAGE]
        self.assertEqual(statuses.count("available"), 2)
        self.assertEqual(statuses.count("not_available") + statuses.count("partial"), 2)

    def test_every_dimension_has_a_real_detail_string(self):
        for dim in PROFILING_COVERAGE:
            self.assertTrue(dim["detail"])
            self.assertTrue(dim["dimension"])
            self.assertTrue(dim["question"])


if __name__ == "__main__":
    unittest.main()
