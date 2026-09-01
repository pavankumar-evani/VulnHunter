"""
Tests for remediation/enrichment/exposure_score.py - the fleet-wide Aggregate Exposure
Score. Like test_risk_scoring.py, these check the formula's real behavior against
synthetic inputs - not "this is the objectively correct industry-standard output," since
(per the module docstring) this is an originally-authored, disclosed rollup, not a
reproduction of Tenable's Cyber Exposure Score (unpublished) or any other named product.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.exposure_score import (  # noqa: E402
    compute_exposure_score, load_rules, DEFAULT_RULES_PATH,
)

BASE_RULES = {
    "component_weights": {"avg_risk_score": 0.5, "kev_prevalence": 0.3, "avg_epss": 0.2},
    "score_bands": {"Critical": 75, "High": 50, "Medium": 25, "Low": 0},
}


def _asset(**overrides):
    row = {"name": "ASSET-1", "risk_score": 0, "risk_tier": "Low"}
    row.update(overrides)
    return row


def _finding(**overrides):
    f = {"id": "FIND-1", "kev": None, "epss": None}
    f.update(overrides)
    return f


class ScoreComputation(unittest.TestCase):
    def test_all_zero_signals_score_zero(self):
        result = compute_exposure_score([_asset(risk_score=0)], [_finding()], BASE_RULES)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "Low")

    def test_max_signals_score_100(self):
        assets = [_asset(risk_score=100, risk_tier="Critical")]
        findings = [_finding(kev={"listed": True}, epss={"score": 1.0})]
        result = compute_exposure_score(assets, findings, BASE_RULES)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["band"], "Critical")

    def test_weighted_blend_of_the_three_real_components(self):
        # avg_risk_score=50 (0.5 weight -> 25), kev_prevalence=100% (0.3 weight -> 30),
        # avg_epss=50% (0.2 weight -> 10) => 25+30+10 = 65
        assets = [_asset(risk_score=50)]
        findings = [_finding(kev={"listed": True}, epss={"score": 0.5})]
        result = compute_exposure_score(assets, findings, BASE_RULES)
        self.assertEqual(result["score"], 65)
        self.assertEqual(result["components"]["avg_risk_score"], 50.0)
        self.assertEqual(result["components"]["kev_prevalence"], 100.0)
        self.assertEqual(result["components"]["avg_epss"], 50.0)

    def test_empty_fleet_does_not_divide_by_zero(self):
        result = compute_exposure_score([], [], BASE_RULES)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["total_assets"], 0)
        self.assertEqual(result["total_findings"], 0)

    def test_findings_without_epss_are_excluded_from_the_average_not_treated_as_zero(self):
        """A finding with no EPSS score at all (never fetched, or the feed had no entry
        for that CVE) must not silently drag the average toward 0 - same honest
        "missing is not zero" convention used throughout this app's other averages."""
        assets = [_asset(risk_score=0)]
        findings = [_finding(epss={"score": 0.8}), _finding(epss=None)]
        result = compute_exposure_score(assets, findings, BASE_RULES)
        self.assertEqual(result["components"]["avg_epss"], 80.0)  # not 40.0

    def test_kev_count_and_risk_tier_counts_are_real_not_derived_from_the_score(self):
        assets = [_asset(name="A", risk_tier="Critical"), _asset(name="B", risk_tier="Low")]
        findings = [_finding(kev={"listed": True}), _finding(kev=None), _finding(kev={"listed": False})]
        result = compute_exposure_score(assets, findings, BASE_RULES)
        self.assertEqual(result["kev_count"], 1)
        self.assertEqual(result["total_findings"], 3)
        self.assertEqual(result["risk_tier_counts"], {"Critical": 1, "Low": 1})

    def test_score_is_clamped_to_0_100_even_with_unusual_weights(self):
        rules = {**BASE_RULES, "component_weights": {"avg_risk_score": 5.0, "kev_prevalence": 0, "avg_epss": 0}}
        assets = [_asset(risk_score=100)]
        result = compute_exposure_score(assets, [_finding()], rules)
        self.assertEqual(result["score"], 100)  # not 500

    def test_band_picks_the_highest_threshold_the_score_meets(self):
        # avg_risk_score=60 * 0.5 weight = 30, kev/epss both 0 -> total score 30, which
        # meets the Medium band's threshold (25) but not High's (50).
        assets = [_asset(risk_score=60)]
        result = compute_exposure_score(assets, [_finding()], BASE_RULES)
        self.assertEqual(result["score"], 30)
        self.assertEqual(result["band"], "Medium")


class RealRulesFileIsValid(unittest.TestCase):
    def test_real_rules_file_loads_and_has_expected_shape(self):
        rules = load_rules(DEFAULT_RULES_PATH)
        self.assertIn("component_weights", rules)
        self.assertIn("score_bands", rules)
        weights = rules["component_weights"]
        for key in ("avg_risk_score", "kev_prevalence", "avg_epss"):
            self.assertIn(key, weights)
        self.assertAlmostEqual(sum(weights.values()), 1.0, places=6)

    def test_real_rules_file_computes_a_sane_score_against_real_sample_findings(self):
        """Regression guard using this app's own real seed data - the score should be
        a legitimate 0-100 int, not crash or produce nonsense, given the real,
        already-shipped findings/asset pipeline."""
        import json
        from remediation.enrichment import risk_scoring
        from remediation.inventory import asset_inventory

        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        rows = asset_inventory.build_asset_inventory(findings)
        scored_assets = risk_scoring.score_assets(rows, findings)
        result = compute_exposure_score(scored_assets, findings)
        self.assertIsInstance(result["score"], int)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)
        self.assertIn(result["band"], ("Critical", "High", "Medium", "Low"))


if __name__ == "__main__":
    unittest.main()
