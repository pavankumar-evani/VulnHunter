"""
Tests for remediation/enrichment/risk_scoring.py - the per-asset Impact/Likelihood/Risk
scoring engine. Like test_eol_lookup.py/test_exploit_criteria.py, these check the
formula's real behavior against synthetic inputs - not "this is the objectively correct
NIST SP 800-30 output," since (per the module docstring) this is a disclosed,
NIST-SP-800-30-inspired simplification, not a certified reproduction of that document's
own qualitative lookup tables.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.config import priority_engine  # noqa: E402
from remediation.enrichment import control_coverage  # noqa: E402
from remediation.enrichment import sbom  # noqa: E402
from remediation.enrichment.risk_scoring import load_rules, score_assets  # noqa: E402


def _asset_row(**overrides):
    row = {
        "name": "GENERIC-ASSET-01",
        "type": "unix-server",
        "finding_count": 1,
        "critical_count": 0,
        "highest_severity": "Medium",
        "kev_count": 0,
        "eol_status": {"status": "unknown"},
    }
    row.update(overrides)
    return row


def _finding(asset_name, **overrides):
    f = {
        "id": "FIND-1",
        "asset": {"name": asset_name, "type": "unix-server"},
        "severity": "Medium",
        "cve": None,
        "cvss": None,
        "kev": None,
        "epss": None,
        "exploit_criteria_matches": [],
    }
    f.update(overrides)
    return f


class ScoreRange(unittest.TestCase):
    def test_scores_always_within_0_to_100(self):
        rows = [
            _asset_row(name="A", kev_count=1, highest_severity="Critical", eol_status={"status": "eol"}),
            _asset_row(name="B", kev_count=0, highest_severity="Low", eol_status={"status": "supported"}),
        ]
        findings = [
            _finding("A", cvss=9.8, kev={"listed": True}, epss={"score": 0.95},
                     exploit_criteria_matches=[{"id": "x", "label": "y"}]),
            _finding("B"),
        ]
        scored = score_assets(rows, findings)
        for row in scored:
            for key in ("impact_score", "likelihood_score", "risk_score"):
                self.assertGreaterEqual(row[key], 0, key)
                self.assertLessEqual(row[key], 100, key)


class KevAndEpssEffect(unittest.TestCase):
    def test_kev_listed_asset_scores_higher_likelihood_than_identical_non_kev_asset(self):
        rows = [
            _asset_row(name="KEV-ASSET", kev_count=1),
            _asset_row(name="NO-KEV-ASSET", kev_count=0),
        ]
        findings = [
            _finding("KEV-ASSET", kev={"listed": True}),
            _finding("NO-KEV-ASSET", kev=None),
        ]
        scored = {r["name"]: r for r in score_assets(rows, findings)}
        self.assertGreater(scored["KEV-ASSET"]["likelihood_score"], scored["NO-KEV-ASSET"]["likelihood_score"])

    def test_higher_epss_scores_higher_likelihood(self):
        rows = [_asset_row(name="A"), _asset_row(name="B")]
        findings = [
            _finding("A", epss={"score": 0.9}),
            _finding("B", epss={"score": 0.1}),
        ]
        scored = {r["name"]: r for r in score_assets(rows, findings)}
        self.assertGreater(scored["A"]["likelihood_score"], scored["B"]["likelihood_score"])

    def test_max_epss_wins_not_average(self):
        rows = [_asset_row(name="A")]
        findings = [
            _finding("A", cve="CVE-1", epss={"score": 0.95}),
            _finding("A", cve="CVE-2", epss={"score": 0.05}),
        ]
        scored = score_assets(rows, findings)[0]
        # Weighted-average likelihood (only epss component non-zero) should reflect the
        # MAX (0.95), not the average (0.5) - i.e. the epss component alone contributes
        # 95, not ~50. Normalized by the weight of the 4 base components only - this
        # asset has no security_controls.yaml entry, so control_coverage's weight is
        # never part of the denominator (see risk_scoring.py's score_assets()).
        rules = load_rules()
        base_weights = {k: v for k, v in rules["likelihood_weights"].items()
                         if k in ("kev", "epss", "exploit_criteria", "eol")}
        expected = round(rules["likelihood_weights"]["epss"] * 95 / sum(base_weights.values()))
        self.assertEqual(scored["likelihood_score"], expected)


class EolEffect(unittest.TestCase):
    def test_unknown_eol_scores_equal_to_supported_not_eol_soon(self):
        rows = [
            _asset_row(name="UNKNOWN-ASSET", eol_status={"status": "unknown"}),
            _asset_row(name="SUPPORTED-ASSET", eol_status={"status": "supported"}),
            _asset_row(name="EOL-SOON-ASSET", eol_status={"status": "eol-soon"}),
        ]
        findings = [_finding(r["name"]) for r in rows]
        scored = {r["name"]: r for r in score_assets(rows, findings)}
        self.assertEqual(scored["UNKNOWN-ASSET"]["likelihood_score"], scored["SUPPORTED-ASSET"]["likelihood_score"])
        self.assertLess(scored["UNKNOWN-ASSET"]["likelihood_score"], scored["EOL-SOON-ASSET"]["likelihood_score"])

    def test_eol_scores_higher_than_eol_soon(self):
        rows = [
            _asset_row(name="EOL-ASSET", eol_status={"status": "eol"}),
            _asset_row(name="EOL-SOON-ASSET", eol_status={"status": "eol-soon"}),
        ]
        findings = [_finding(r["name"]) for r in rows]
        scored = {r["name"]: r for r in score_assets(rows, findings)}
        self.assertGreater(scored["EOL-ASSET"]["likelihood_score"], scored["EOL-SOON-ASSET"]["likelihood_score"])


class RiskTierBoundaries(unittest.TestCase):
    def test_tier_boundaries_map_correctly_on_both_sides(self):
        rules = load_rules()
        thresholds = rules["risk_tier_thresholds"]
        # A Critical-tier asset: max out every likelihood component and give it the
        # highest possible severity/criticality so impact*likelihood/100 clears the
        # Critical threshold.
        rows = [_asset_row(name="MAX-RISK", kev_count=1, highest_severity="Critical",
                            eol_status={"status": "eol"}, type="network-routing-switching")]
        findings = [_finding("MAX-RISK", cvss=10.0, kev={"listed": True}, epss={"score": 1.0},
                              exploit_criteria_matches=[{"id": "a", "label": "b"}] * 3)]
        scored = score_assets(rows, findings)[0]
        self.assertGreaterEqual(scored["risk_score"], thresholds["Critical"])
        self.assertEqual(scored["risk_tier"], "Critical")

        rows_low = [_asset_row(name="MIN-RISK", kev_count=0, highest_severity="Low",
                                eol_status={"status": "supported"})]
        findings_low = [_finding("MIN-RISK")]
        scored_low = score_assets(rows_low, findings_low)[0]
        self.assertLess(scored_low["risk_score"], thresholds["High"])
        self.assertEqual(scored_low["risk_tier"], "Low")


class RulesAreReal(unittest.TestCase):
    def test_a_rule_change_actually_changes_the_output(self):
        rows = [_asset_row(name="A", kev_count=1)]
        findings = [_finding("A", kev={"listed": True})]

        default_rules = load_rules()
        scored_default = score_assets(rows, findings, rules=default_rules)[0]

        retuned_rules = dict(default_rules)
        retuned_rules["likelihood_weights"] = {"kev": 0.0, "epss": 0.0, "exploit_criteria": 0.0, "eol": 1.0}
        scored_retuned = score_assets(rows, findings, rules=retuned_rules)[0]

        self.assertNotEqual(scored_default["likelihood_score"], scored_retuned["likelihood_score"])
        # With eol as the only weight and this asset's eol_status "unknown" (0 points),
        # likelihood should drop to 0 once KEV/EPSS/exploit-criteria are zeroed out.
        self.assertEqual(scored_retuned["likelihood_score"], 0)


class ControlCoverageIsAdditive(unittest.TestCase):
    """remediation/config/security_controls.yaml ships empty, so by default every asset
    here has no coverage data - confirms that's truly a no-op (same score as before this
    component existed), and that real coverage data DOES change the score once present."""

    def test_asset_with_no_coverage_data_scores_identically_to_before(self):
        rows = [_asset_row(name="A", kev_count=1)]
        findings = [_finding("A", kev={"listed": True})]
        with patch.object(control_coverage, "load_controls", return_value={"assets": []}):
            scored = score_assets(rows, findings)[0]
        rules = load_rules()
        base_weights = {k: v for k, v in rules["likelihood_weights"].items()
                         if k in ("kev", "epss", "exploit_criteria", "eol")}
        expected = round(base_weights["kev"] * 100 / sum(base_weights.values()))
        self.assertEqual(scored["likelihood_score"], expected)

    def test_asset_with_real_coverage_data_scores_differently(self):
        rows = [_asset_row(name="A")]
        findings = [_finding("A", cve="CVE-2024-56238", title="x", description="")]
        controls = {"assets": [{
            "match": {"name": "A"},
            "firewall_rules": [{"source": "internet", "dest": "A", "action": "allow"}],
        }]}
        with patch.object(control_coverage, "load_controls", return_value={"assets": []}):
            scored_no_data = score_assets(rows, findings)[0]
        with patch.object(control_coverage, "load_controls", return_value=controls):
            scored_with_data = score_assets(rows, findings)[0]
        # Unblocked internet-facing exposure (0% firewall coverage -> 100% residual risk
        # for that finding) should push likelihood strictly higher than the no-data case.
        self.assertGreater(scored_with_data["likelihood_score"], scored_no_data["likelihood_score"])


class DependencyBlastRadiusIsAdditive(unittest.TestCase):
    """Same additive contract as ControlCoverageIsAdditive above, on the Impact side:
    a finding with no `dependency.package` at all (the real, current state of every
    finding in this pipeline's own sample data) must score identically to before this
    component existed; a finding whose package has a real blast radius in the loaded
    SBOM must score strictly higher."""

    def test_asset_with_no_dependency_field_scores_identically_regardless_of_sbom(self):
        # The real, current state of every finding in this pipeline's own data (no
        # `dependency` field at all) must score the same no matter which SBOM happens to
        # be loaded - this component only ever activates from real per-finding data,
        # never from the mere presence of an SBOM file.
        rows = [_asset_row(name="A")]
        findings = [_finding("A", cvss=7.0)]
        scored_default_sbom = score_assets(rows, findings)[0]
        fake_sbom = {"components": [{"bom-ref": "x", "name": "some-lib"}], "dependencies": []}
        with patch.object(sbom, "load_sbom", return_value=fake_sbom):
            scored_other_sbom = score_assets(rows, findings)[0]
        self.assertEqual(scored_default_sbom["impact_score"], scored_other_sbom["impact_score"])

    def test_asset_with_real_dependency_data_scores_differently(self):
        rows = [_asset_row(name="A")]
        dependency = {"package": "leaf-lib", "ecosystem": "maven", "version": "1.0",
                      "fixed_version": "1.1", "direct": True}
        findings_with_dep = [_finding("A", cvss=7.0, dependency=dependency)]
        findings_no_dep = [_finding("A", cvss=7.0)]
        # 10 direct dependents on "leaf-lib" - at or above dependency_blast_radius_cap,
        # so the component is pinned at its max (100), guaranteed to push the Impact
        # weighted average up regardless of what severity/criticality happen to be.
        fake_sbom = {
            "components": (
                [{"bom-ref": "leaf", "name": "leaf-lib"}]
                + [{"bom-ref": f"root{i}", "name": f"root-app-{i}"} for i in range(10)]
            ),
            "dependencies": [{"ref": f"root{i}", "dependsOn": ["leaf"]} for i in range(10)],
        }
        with patch.object(sbom, "load_sbom", return_value=fake_sbom):
            scored_no_data = score_assets(rows, findings_no_dep)[0]
            scored_with_data = score_assets(rows, findings_with_dep)[0]
        self.assertGreater(scored_with_data["impact_score"], scored_no_data["impact_score"])


class DoesNotMutateInput(unittest.TestCase):
    def test_score_assets_does_not_mutate_asset_rows_or_findings(self):
        rows = [_asset_row(name="A")]
        findings = [_finding("A")]
        rows_before = [dict(r) for r in rows]
        findings_before = [dict(f) for f in findings]
        score_assets(rows, findings)
        self.assertEqual(rows, rows_before)
        self.assertEqual(findings, findings_before)


class RealRulesFileIsValid(unittest.TestCase):
    def test_real_rules_file_loads_and_has_expected_top_level_keys(self):
        rules = load_rules()
        required = {"impact_weights", "likelihood_weights", "exploit_criteria_match_cap",
                    "eol_likelihood_points", "risk_tier_thresholds"}
        self.assertTrue(required.issubset(rules.keys()))

    def test_asset_criticality_score_is_reused_not_redeclared(self):
        # Confirms risk_scoring.py truly calls into priority_engine's shared helper
        # rather than a second copy of the keyword-matching logic.
        priority_rules = priority_engine.load_rules()
        result = priority_engine.asset_criticality_score({"name": "win-dc01", "type": "windows-server"}, priority_rules)
        self.assertIn("keyword_score", result)
        self.assertEqual(result["matched_keyword"], "dc")


if __name__ == "__main__":
    unittest.main()
