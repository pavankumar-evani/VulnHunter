"""Tests for decision calibration (Brier, ECE, reliability bins, override rate, insufficient data, recommendations) and the decision API (auth, dry evaluate)."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "dashboard"))
import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.decisions import calibration, gate, registry, schema, service  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

# 9 judged outcomes: low half-open bin [0, .5) holds 4, high bin [.5, 1] holds 5.
PAIRS = [(0.2, 0), (0.4, 0), (0.3, 1), (0.1, 0), (0.6, 1), (0.8, 1), (0.9, 0), (0.7, 0), (1.0, 1)]


def rows_for(pairs, decision="soc-alert-triage", route="review"):
    return [{"decision": decision, "question": "verdict", "probability": p, "route": route, "outcome": "accepted" if y else "overridden", "model_calls_avoided": 1} for p, y in pairs]


def policy(**cal):
    pol = gate.load_policy()
    pol["calibration"] = {**pol["calibration"], **cal}
    return pol


class Math(unittest.TestCase):
    def test_brier_on_a_fixed_dataset(self):
        self.assertAlmostEqual(calibration.brier(PAIRS), 2.20 / 9, places=9)

    def test_reliability_bins_and_ece_on_a_fixed_dataset(self):
        bins, ece = calibration.reliability(PAIRS, 2)
        self.assertEqual([b["n"] for b in bins], [4, 5])
        self.assertAlmostEqual(bins[0]["mean_probability"], 0.25)
        self.assertAlmostEqual(bins[0]["accuracy"], 0.25)
        self.assertAlmostEqual(bins[1]["mean_probability"], 0.8)
        self.assertAlmostEqual(bins[1]["accuracy"], 0.6)
        self.assertAlmostEqual(bins[1]["gap"], -0.2)
        self.assertAlmostEqual(ece, 5 / 9 * 0.2, places=9)

    def test_probability_one_lands_in_the_top_bin(self):
        bins, _ = calibration.reliability([(1.0, 1), (0.0, 0)], 5)
        self.assertEqual([b["n"] for b in bins], [1, 1])

    def test_perfectly_calibrated_has_zero_ece(self):
        _, ece = calibration.reliability([(0.5, 1), (0.5, 0), (0.9, 1)] + [(0.9, 1)] * 8 + [(0.9, 0)], 5)
        self.assertAlmostEqual(ece, 0.0, places=9)

    def test_summary_reports_measured_figures(self):
        r = calibration.summarise(rows_for(PAIRS), policy(min_outcomes=9, min_band_outcomes=3, bins=2))
        d = r["decisions"]["soc-alert-triage"]
        self.assertEqual(d["status"], "measured")
        self.assertAlmostEqual(d["brier"], round(2.2 / 9, 4))
        self.assertAlmostEqual(d["ece"], round(5 / 9 * 0.2, 4))
        self.assertAlmostEqual(d["override_rate"], round(5 / 9, 4))
        self.assertFalse(d["calibrated"])        # ECE 0.111 > 0.10
        self.assertTrue(any(x["kind"] == "do-not-trust-probabilities" for x in d["recommendations"]))
        self.assertEqual(r["model_calls_avoided"], 9)

    def test_insufficient_data_never_claims_calibration(self):
        r = calibration.summarise(rows_for(PAIRS), gate.load_policy())     # 9 < 30
        d = r["decisions"]["soc-alert-triage"]
        self.assertEqual(d["status"], "not-enough-outcomes")
        self.assertIn("at least 30", d["message"])
        for k in ("brier", "ece", "calibrated", "override_rate", "bins"):
            self.assertNotIn(k, d)

    def test_unjudged_rows_do_not_count(self):
        rows = rows_for(PAIRS) + [{**rows_for([(0.9, 1)])[0], "outcome": None}] * 50
        d = calibration.summarise(rows, policy(min_outcomes=9, bins=2))["decisions"]["soc-alert-triage"]
        self.assertEqual((d["logged"], d["judged"]), (59, 9))

    def test_band_override_rates_need_enough_outcomes(self):
        r = calibration.summarise(rows_for(PAIRS), policy(min_outcomes=9, min_band_outcomes=5, bins=2))
        bands = r["decisions"]["soc-alert-triage"]["bands"]      # thresholds auto 0.95, review 0.6
        self.assertEqual(bands["auto"]["n"], 1)
        self.assertIsNone(bands["auto"]["override_rate"])
        self.assertEqual(bands["review"]["n"], 4)                # 0.6, 0.8, 0.9, 0.7 fall in [0.6, 0.95)
        self.assertEqual(bands["human"]["n"], 4)

    def test_recommend_raising_auto_threshold_from_data(self):
        # 20 answers at 0.96: 4 overridden (20%), well over the 5% limit; 10 at 0.99 all accepted
        pairs = [(0.96, 1)] * 16 + [(0.96, 0)] * 4 + [(0.99, 1)] * 10
        pol = policy(min_outcomes=30, min_band_outcomes=10)
        d = calibration.summarise(rows_for(pairs), pol)["decisions"]["soc-alert-triage"]
        rec = [x for x in d["recommendations"] if x["kind"] == "raise-auto-threshold"]
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["to"], 0.99)
        self.assertEqual(pol["decisions"]["soc-alert-triage"]["thresholds"]["auto"], 0.95)   # advice only: the policy is untouched

    def test_environment_decisions_get_no_auto_advice(self):
        pairs = [(0.995, 1)] * 15 + [(0.995, 0)] * 15
        d = calibration.summarise(rows_for(pairs, "change-approval-needed"), policy(min_outcomes=30, min_band_outcomes=10))["decisions"]["change-approval-needed"]
        self.assertTrue(any("never be routed auto" in x["message"] for x in d["recommendations"]))
        self.assertFalse(any(x["kind"] == "consider-lowering-auto-threshold" for x in d["recommendations"]))


class Store(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_record_and_outcome_round_trip(self):
        d = registry.get("soc-alert-triage")
        res = service.evaluate("soc-alert-triage", {"signals": {"ioc_malicious": True, "kev_match": True}, "severity": "High"})
        ids = calibration.record(d, res["_answers"], res["gate"]["route"], ref="alert:7", model_calls_avoided=1, engine=self.e)
        self.assertEqual(len(ids), 1)
        self.assertTrue(calibration.record_outcome(ids[0], "overridden", "likely-false-positive", engine=self.e))
        self.assertFalse(calibration.record_outcome(ids[0], "accepted", engine=self.e))      # judged once
        row = calibration.rows(self.e)[0]
        self.assertEqual((row["outcome"], row["outcome_value"], row["ref"], row["model_calls_avoided"]), ("overridden", "likely-false-positive", "alert:7", 1))

    def test_only_identifiers_are_stored(self):
        d = registry.get("soc-alert-triage")
        res = service.evaluate("soc-alert-triage", {"signals": {}, "severity": "High"})
        with self.assertRaises(schema.SchemaViolation):
            calibration.record(d, res["_answers"], "review", ref="a free text note about Jane", engine=self.e)
        cols = {c.name for c in db_module.decision_log.columns}
        self.assertFalse(cols & {"text", "prompt", "note", "notes", "user", "email", "actor"})

    def test_bad_outcome_and_value_are_rejected(self):
        res = service.evaluate("soc-alert-triage", {"signals": {}, "severity": "High"})
        i = calibration.record(registry.get("soc-alert-triage"), res["_answers"], "review", engine=self.e)[0]
        with self.assertRaises(schema.SchemaViolation):
            calibration.record_outcome(i, "maybe", engine=self.e)
        with self.assertRaises(schema.SchemaViolation):
            calibration.record_outcome(i, "accepted", "not-a-verdict", engine=self.e)
        with self.assertRaises(KeyError):
            calibration.record_outcome(9999, "accepted", engine=self.e)

    def test_soc_verdict_is_judged_from_the_analysts_disposition(self):
        alert = {"id": 5, "severity": "High"}
        inv = {"signals": {"ioc_malicious": True, "kev_match": True}}
        self.assertEqual(len(service.log_soc_verdict(alert, inv, engine=self.e)), 1)
        self.assertEqual(service.judge_soc_disposition(5, "false-positive", engine=self.e), 1)
        r = calibration.rows(self.e)[0]
        self.assertEqual((r["value"], r["outcome"], r["outcome_value"]), ("likely-true-positive", "overridden", "likely-false-positive"))
        service.log_soc_verdict({"id": 6, "severity": "High"}, inv, engine=self.e)
        self.assertEqual(service.judge_soc_disposition(6, "true-positive", engine=self.e), 1)
        self.assertEqual(calibration.rows(self.e)[1]["outcome"], "accepted")

    def test_an_escalate_verdict_is_never_judged(self):
        service.log_soc_verdict({"id": 8, "severity": "High"}, {"signals": {}}, engine=self.e)
        self.assertEqual(service.judge_soc_disposition(8, "true-positive", engine=self.e), 0)
        self.assertIsNone(calibration.rows(self.e)[0]["outcome"])

    def test_logging_failure_never_raises(self):
        self.assertEqual(service.log_soc_verdict({"id": 1}, {}, engine=self.e), [])

    def test_report_on_an_empty_database(self):
        r = calibration.report(self.e)
        self.assertTrue(all(d["status"] == "not-enough-outcomes" for d in r["decisions"].values()))
        self.assertEqual(r["model_calls_avoided"], 0)


class DecisionApi(unittest.TestCase):
    PW = "test-password-123"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", self.PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", self.PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": self.PW})

    BODY = {"decision": "soc-alert-triage", "state": {"signals": {"ioc_malicious": True, "kev_match": True}, "severity": "High"}}

    def test_login_is_required_for_evaluate_and_policy(self):
        self.assertEqual(self.client.post("/api/decisions/evaluate", json=self.BODY).status_code, 401)
        self.assertEqual(self.client.get("/api/decisions/policy").status_code, 401)

    def test_calibration_is_admin_only(self):
        self.assertEqual(self.client.get("/api/decisions/calibration").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/decisions/calibration").status_code, 403)
        self.login("admin@t.local")
        r = self.client.get("/api/decisions/calibration")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["decisions"]["soc-alert-triage"]["status"], "not-enough-outcomes")

    def test_evaluate_is_dry_and_typed(self):
        self.login("user@t.local")
        r = self.client.post("/api/decisions/evaluate", json=self.BODY)
        self.assertEqual(r.status_code, 200)
        j = r.json()
        self.assertEqual(j["answers"][0]["value"], "likely-true-positive")
        self.assertIn(j["gate"]["route"], ("auto", "review", "human"))
        self.assertFalse(j["router"]["needs_model"])
        self.assertEqual(calibration.rows(self.engine), [])            # no side effects

    def test_evaluate_rejects_unknown_decisions_and_purposes(self):
        self.login("user@t.local")
        self.assertEqual(self.client.post("/api/decisions/evaluate", json={"decision": "nope", "state": {}}).status_code, 400)
        self.assertEqual(self.client.post("/api/decisions/evaluate", json={**self.BODY, "purpose": "chat"}).status_code, 400)

    def test_policy_endpoint_states_what_can_never_be_auto(self):
        self.login("user@t.local")
        d = {x["name"]: x for x in self.client.get("/api/decisions/policy").json()["decisions"]}
        self.assertFalse(d["change-approval-needed"]["auto_allowed"])
        self.assertTrue(d["change-approval-needed"]["touches_environment"])
        self.assertTrue(d["finding-routing"]["auto_allowed"])
        self.assertEqual(d["soc-alert-triage"]["questions"][0]["options"], ["likely-true-positive", "likely-false-positive", "escalate-l2"])

    def test_setting_a_disposition_judges_a_logged_verdict(self):
        self.login("admin@t.local")
        from remediation.hunting import store as hunt_store
        alert, _ = hunt_store.receive_alert({"external_id": "x1", "title": "Odd login", "severity": "High", "source": "t", "asset": "web1"}, engine=self.engine)
        aid = alert["id"]
        service.log_soc_verdict(alert, {"signals": {"ioc_malicious": True, "kev_match": True}}, engine=self.engine)
        r = self.client.put(f"/api/soc/alerts/{aid}", json={"status": "closed", "disposition": "true-positive"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(calibration.rows(self.engine)[0]["outcome"], "accepted")


if __name__ == "__main__":
    unittest.main()
