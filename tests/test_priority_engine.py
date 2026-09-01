"""
Tests for remediation/config/priority_engine.py.

Uses an in-memory rules dict for most tests (not the real priority_rules.yaml) so tests
stay independent of that file's actual tuning - if someone reasonably retunes the
weights in priority_rules.yaml, these tests shouldn't break. A handful of tests
specifically load the real file to make sure it's valid YAML matching the expected
shape.
"""
import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.config.priority_engine import (  # noqa: E402
    compute_priority, compute_sla, score_findings, load_rules, DEFAULT_RULES_PATH,
)

BASE_RULES = {
    "sla_days": {"Critical": 3, "High": 7, "Medium": 30, "Low": 90},
    "sla_risk_tier_multiplier": {"Critical": 0.5, "High": 0.75, "Medium": 1.0, "Low": 1.25},
    "kev_override": {"enabled": True, "forces_priority": "Critical"},
    "epss_escalation": {"enabled": True, "threshold": 0.5, "forces_priority_at_least": "High"},
    "asset_criticality_keywords": {"dc": 3, "auth": 3, "bastion": 2, "default": 0},
    "asset_type_weights": {"windows-server": 1, "certificate": 0},
    "severity_weights": {"Critical": 3, "High": 2, "Medium": 1, "Low": 0},
    "priority_thresholds": {"Critical": 6, "High": 4, "Medium": 2, "Low": 0},
}


def finding(**overrides):
    base = {
        "id": "FIND-TEST",
        "severity": "Medium",
        "asset": {"name": "SOME-HOST", "type": "windows-server"},
        "kev": None,
        "epss": None,
        "first_seen": "2026-08-01",
    }
    base.update(overrides)
    return base


class PriorityScoring(unittest.TestCase):
    def test_low_severity_generic_asset_is_low_priority(self):
        f = finding(severity="Low", asset={"name": "WORKSTATION-01", "type": "windows-endpoint"})
        result = compute_priority(f, BASE_RULES)
        self.assertEqual(result["priority"], "Low")

    def test_critical_severity_on_domain_controller_is_critical(self):
        f = finding(severity="Critical", asset={"name": "WIN-DC01", "type": "windows-server"})
        result = compute_priority(f, BASE_RULES)
        # severity 3 + 'dc' keyword 3 + windows-server 1 = 7 >= Critical threshold (6)
        self.assertEqual(result["priority"], "Critical")

    def test_kev_listed_forces_critical_regardless_of_score(self):
        f = finding(severity="Low", asset={"name": "RANDOM-HOST", "type": "certificate"},
                    kev={"listed": True})
        result = compute_priority(f, BASE_RULES)
        self.assertEqual(result["priority"], "Critical")
        self.assertTrue(any("KEV" in r for r in result["reasons"]))

    def test_kev_override_disabled_does_not_force_priority(self):
        rules = {**BASE_RULES, "kev_override": {"enabled": False, "forces_priority": "Critical"}}
        f = finding(severity="Low", asset={"name": "RANDOM-HOST", "type": "certificate"},
                    kev={"listed": True})
        result = compute_priority(f, rules)
        self.assertEqual(result["priority"], "Low")

    def test_high_epss_elevates_to_at_least_high(self):
        f = finding(severity="Low", asset={"name": "RANDOM-HOST", "type": "certificate"},
                    epss={"score": 0.9})
        result = compute_priority(f, BASE_RULES)
        self.assertEqual(result["priority"], "High")

    def test_low_epss_does_not_elevate(self):
        f = finding(severity="Low", asset={"name": "RANDOM-HOST", "type": "certificate"},
                    epss={"score": 0.1})
        result = compute_priority(f, BASE_RULES)
        self.assertEqual(result["priority"], "Low")

    def test_epss_never_downgrades_a_higher_score(self):
        """A finding that already scores Critical from severity+asset must not be
        pulled down to 'High' just because epss_escalation's target is High."""
        f = finding(severity="Critical", asset={"name": "WIN-DC01", "type": "windows-server"},
                    epss={"score": 0.6})
        result = compute_priority(f, BASE_RULES)
        self.assertEqual(result["priority"], "Critical")


class SlaComputation(unittest.TestCase):
    def test_sla_due_date_and_not_breached(self):
        f = finding(first_seen="2026-08-01")
        sla = compute_sla(f, "High", BASE_RULES, as_of=datetime.date(2026, 8, 3))
        self.assertEqual(sla["due_date"], "2026-08-08")  # +7 days
        self.assertEqual(sla["days_remaining"], 5)
        self.assertFalse(sla["breached"])

    def test_sla_breached_when_past_due_date(self):
        f = finding(first_seen="2026-07-01")
        sla = compute_sla(f, "Critical", BASE_RULES, as_of=datetime.date(2026, 8, 3))  # +3 days -> way overdue
        self.assertTrue(sla["breached"])
        self.assertLess(sla["days_remaining"], 0)

    def test_sla_handles_missing_first_seen_gracefully(self):
        f = finding(first_seen=None)
        sla = compute_sla(f, "High", BASE_RULES)
        self.assertIsNone(sla["due_date"])
        self.assertIsNone(sla["breached"])

    def test_no_asset_risk_tier_uses_neutral_multiplier(self):
        """Omitting asset_risk_tier (every caller before this feature, and any caller
        that doesn't compute risk_tier) must reproduce the exact pre-existing behavior -
        no silent SLA-window change for code that hasn't opted in."""
        f = finding(first_seen="2026-08-01")
        sla = compute_sla(f, "High", BASE_RULES, as_of=datetime.date(2026, 8, 3))
        self.assertEqual(sla["due_date"], "2026-08-08")  # +7 days, unchanged
        self.assertEqual(sla["risk_tier_multiplier"], 1.0)

    def test_critical_risk_tier_asset_tightens_the_sla_window(self):
        f = finding(first_seen="2026-08-01")
        sla = compute_sla(f, "High", BASE_RULES, as_of=datetime.date(2026, 8, 3), asset_risk_tier="Critical")
        self.assertEqual(sla["due_date"], "2026-08-05")  # 7 * 0.5 = 3.5 -> round to 4 days
        self.assertEqual(sla["risk_tier_multiplier"], 0.5)

    def test_low_risk_tier_asset_loosens_the_sla_window(self):
        f = finding(first_seen="2026-08-01")
        sla = compute_sla(f, "High", BASE_RULES, as_of=datetime.date(2026, 8, 3), asset_risk_tier="Low")
        self.assertEqual(sla["due_date"], "2026-08-10")  # 7 * 1.25 = 8.75 -> round to 9 days
        self.assertEqual(sla["risk_tier_multiplier"], 1.25)

    def test_unknown_risk_tier_falls_back_to_neutral_multiplier(self):
        f = finding(first_seen="2026-08-01")
        sla = compute_sla(f, "High", BASE_RULES, as_of=datetime.date(2026, 8, 3), asset_risk_tier="not-a-real-tier")
        self.assertEqual(sla["risk_tier_multiplier"], 1.0)

    def test_multiplier_never_drops_sla_below_one_day(self):
        rules = {**BASE_RULES, "sla_days": {**BASE_RULES["sla_days"], "Critical": 1},
                  "sla_risk_tier_multiplier": {**BASE_RULES["sla_risk_tier_multiplier"], "Critical": 0.1}}
        f = finding(first_seen="2026-08-01")
        sla = compute_sla(f, "Critical", rules, as_of=datetime.date(2026, 8, 1), asset_risk_tier="Critical")
        self.assertEqual(sla["due_date"], "2026-08-02")  # floored at 1 day, not 0


class ScoreFindingsBatch(unittest.TestCase):
    def test_score_findings_sorts_highest_priority_first(self):
        findings = [
            finding(severity="Low", asset={"name": "X", "type": "certificate"}),
            finding(severity="Critical", asset={"name": "WIN-DC01", "type": "windows-server"}),
        ]
        findings[0]["id"] = "FIND-LOW"
        findings[1]["id"] = "FIND-CRIT"
        scored = score_findings(findings, rules=BASE_RULES)
        self.assertEqual(scored[0]["id"], "FIND-CRIT")
        self.assertEqual(scored[0]["priority"], "Critical")

    def test_score_findings_does_not_mutate_input(self):
        findings = [finding()]
        original_keys = set(findings[0].keys())
        score_findings(findings, rules=BASE_RULES)
        self.assertEqual(set(findings[0].keys()), original_keys)  # no 'priority' key added to original

    def test_risk_tier_by_asset_feeds_the_sla_multiplier_per_finding(self):
        findings = [
            finding(asset={"name": "CRIT-ASSET", "type": "windows-server"}, first_seen="2026-08-01"),
            finding(asset={"name": "LOW-ASSET", "type": "windows-server"}, first_seen="2026-08-01"),
        ]
        findings[0]["id"] = "FIND-ON-CRIT-ASSET"
        findings[1]["id"] = "FIND-ON-LOW-ASSET"
        risk_tier_by_asset = {"CRIT-ASSET": "Critical", "LOW-ASSET": "Low"}
        scored = score_findings(findings, rules=BASE_RULES, risk_tier_by_asset=risk_tier_by_asset)
        by_id = {f["id"]: f for f in scored}
        self.assertEqual(by_id["FIND-ON-CRIT-ASSET"]["sla"]["risk_tier_multiplier"], 0.5)
        self.assertEqual(by_id["FIND-ON-LOW-ASSET"]["sla"]["risk_tier_multiplier"], 1.25)

    def test_omitting_risk_tier_by_asset_uses_neutral_multiplier_for_everyone(self):
        findings = [finding(asset={"name": "SOME-HOST", "type": "windows-server"})]
        scored = score_findings(findings, rules=BASE_RULES)
        self.assertEqual(scored[0]["sla"]["risk_tier_multiplier"], 1.0)


class RealRulesFileIsValid(unittest.TestCase):
    def test_real_rules_file_loads_and_has_expected_top_level_keys(self):
        rules = load_rules(DEFAULT_RULES_PATH)
        for key in ("sla_days", "sla_risk_tier_multiplier", "kev_override", "epss_escalation",
                    "asset_criticality_keywords", "asset_type_weights", "severity_weights",
                    "priority_thresholds"):
            self.assertIn(key, rules, f"priority_rules.yaml missing '{key}'")

    def test_real_rules_file_sla_risk_tier_multiplier_covers_every_tier(self):
        rules = load_rules(DEFAULT_RULES_PATH)
        for tier in ("Critical", "High", "Medium", "Low"):
            self.assertIn(tier, rules["sla_risk_tier_multiplier"])

    def test_real_rules_file_scores_a_known_finding_as_expected(self):
        """Regression guard using our own real sample data - PrintNightmare (KEV-listed,
        on a domain controller) should always come out Critical against the real
        shipped rules file, however else it's tuned."""
        import json
        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        by_id = {f["id"]: f for f in findings}
        rules = load_rules(DEFAULT_RULES_PATH)
        result = compute_priority(by_id["FIND-1"], rules)  # PrintNightmare on WIN-DC01
        self.assertEqual(result["priority"], "Critical")


if __name__ == "__main__":
    unittest.main()
