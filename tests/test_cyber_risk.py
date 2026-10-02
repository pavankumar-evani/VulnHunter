"""
Tests for cyber risk quantification and the cyber health score.
"""
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.risk import quant, store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
S = {"name": "Ransomware on the file estate", "tef_min": 0.1, "tef_likely": 0.5, "tef_max": 2, "loss_min": 100_000, "loss_likely": 500_000, "loss_max": 3_000_000,
     "asset_scope": "FS-*", "category": "ransomware", "owner": "ciso@t"}


class QuantTests(unittest.TestCase):
    def test_validation(self):
        quant.validate(S)
        for change in ({"tef_min": 1, "tef_likely": 0.5}, {"loss_max": 10}, {"tef_min": -1}, {"loss_min": "abc"}, {"tef_max": 400, "tef_likely": 300}):
            with self.assertRaises(quant.ScenarioError, msg=str(change)):
                quant.validate({**S, **change})

    def test_the_result_matches_the_arithmetic_and_is_repeatable(self):
        r = quant.simulate(S, 20000, seed=7)
        mean_f, mean_l = (0.1 + 4 * 0.5 + 2) / 6, (100_000 + 4 * 500_000 + 3_000_000) / 6
        self.assertAlmostEqual(r["ale"] / (mean_f * mean_l), 1.0, delta=0.08)  # E[N*L] = E[N] * E[L]
        self.assertEqual(r, quant.simulate(S, 20000, seed=7))
        self.assertNotEqual(r["ale"], quant.simulate(S, 20000, seed=8)["ale"])
        self.assertLessEqual(r["p50"], r["p90"])
        self.assertLessEqual(r["p90"], r["p95"])
        self.assertLessEqual(r["p95"], r["max"])
        self.assertEqual([e["probability"] for e in r["exceedance"]], [0.5, 0.25, 0.1, 0.05, 0.01])
        self.assertTrue(0 < r["prob_any_loss"] <= 1)

    def test_tolerance_probability_and_trial_limits(self):
        r = quant.simulate(S, 5000, 1, tolerance=10**12, appetite=1)
        self.assertEqual((r["prob_over_tolerance"], r["prob_over_appetite"] > 0.3), (0.0, True))
        self.assertEqual(quant.simulate(S, 1, 1)["trials"], quant.MIN_TRIALS)
        self.assertEqual(quant.simulate(S, 10**9, 1)["trials"], quant.MAX_TRIALS)

    def test_degenerate_and_zero_scenarios(self):
        fixed = {**S, "tef_min": 2, "tef_likely": 2, "tef_max": 2, "loss_min": 1000, "loss_likely": 1000, "loss_max": 1000}
        self.assertAlmostEqual(quant.simulate(fixed, 10000, 3)["ale"], 2000, delta=100)
        never = {**S, "tef_min": 0, "tef_likely": 0, "tef_max": 0}
        r = quant.simulate(never, 2000, 1)
        self.assertEqual((r["ale"], r["max"], r["prob_any_loss"]), (0, 0, 0))

    def test_pert_stays_in_range_and_poisson_handles_large_rates(self):
        rng = random.Random(1)
        vals = [quant.pert(rng, 5, 8, 20) for _ in range(2000)]
        self.assertTrue(all(5 <= v <= 20 for v in vals))
        self.assertAlmostEqual(sum(vals) / len(vals), (5 + 32 + 20) / 6, delta=0.4)
        self.assertGreater(sum(quant.poisson(rng, 100) for _ in range(200)) / 200, 90)
        self.assertEqual(quant.poisson(rng, 0), 0)

    def test_options_are_ranked_by_net_benefit(self):
        s = {**S, "options": [{"name": "EDR", "annual_cost": 50_000, "frequency_reduction": 0.4, "loss_reduction": 0.1},
                              {"name": "Gold plating", "annual_cost": 5_000_000, "frequency_reduction": 0.05, "loss_reduction": 0}]}
        r = quant.evaluate_options(s, 10000, 1, 250_000)
        self.assertEqual([o["name"] for o in r["options"]], ["EDR", "Gold plating"])
        edr, gold = r["options"]
        self.assertTrue(edr["worth_it"] and not gold["worth_it"])
        self.assertLess(edr["ale_after"], r["baseline"]["ale"])
        self.assertGreater(edr["return"], 0)
        self.assertLess(gold["return"], 0)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_save_validate_update_delete(self):
        s = store.save(S, "a", engine=self.e)
        self.assertEqual((s["category"], s["status"], s["options"]), ("ransomware", "active", []))
        upd = store.save({**S, "name": "Renamed", "options": [{"name": "EDR", "annual_cost": 1, "frequency_reduction": 0.5, "loss_reduction": 0}]}, "b", scenario_id=s["id"], engine=self.e)
        self.assertEqual((upd["name"], len(upd["options"])), ("Renamed", 1))
        for bad in ({"name": " "}, {"category": "weather"}, {"status": "weird"}, {"tef_min": 5}, {"options": [{"name": "x", "annual_cost": -1}]},
                    {"options": [{"name": "x", "annual_cost": 1, "frequency_reduction": 1.5}]}):
            with self.assertRaises(quant.ScenarioError, msg=str(bad)):
                store.save({**S, **bad}, "a", engine=self.e)
        with self.assertRaises(KeyError):
            store.save(S, "a", scenario_id=999, engine=self.e)
        self.assertTrue(store.remove(s["id"], self.e))
        self.assertFalse(store.remove(s["id"], self.e))

    def test_signals_read_the_live_findings_without_changing_the_numbers(self):
        f = lambda host, kev=False, sla=False: {"asset": {"name": host}, "severity": "Critical", "kev": {"listed": True} if kev else None, "sla": {"breached": sla}}  # noqa: E731
        sig = store.signals(S, [f("FS-1", True, True), f("FS-2"), f("WEB-1", True), {**f("FS-3", True), "status": "resolved"}])
        self.assertEqual((sig["assets_with_findings"], sig["open_findings"], sig["known_exploited"], sig["past_sla"]), (2, 2, 1, 1))
        self.assertIn("second look", sig["reading"])
        self.assertIn("No known-exploited", store.signals(S, [f("FS-1")])["reading"])
        self.assertIn("No open findings", store.signals(S, [f("WEB-1")])["reading"])
        self.assertIsNone(store.signals({**S, "asset_scope": ""}, [f("FS-1")]))

    def test_portfolio_totals_active_scenarios_against_appetite(self):
        a = store.save(S, "a", engine=self.e)
        store.save({**S, "name": "Retired", "status": "retired"}, "a", engine=self.e)
        small = store.save({**S, "name": "Small", "tef_min": 0.01, "tef_likely": 0.02, "tef_max": 0.05, "loss_min": 1000, "loss_likely": 2000, "loss_max": 5000}, "a", engine=self.e)
        p = store.portfolio(store.list_all(self.e), [], {"trials": 3000, "appetite_annual_loss": 100, "scenario_tolerance": 1, "currency": "EUR"})
        self.assertEqual([r["id"] for r in p["scenarios"]], [a["id"], small["id"]])  # largest first, retired left out
        self.assertEqual(p["total_ale"], sum(r["ale"] for r in p["scenarios"]))
        self.assertFalse(p["within_appetite"])
        self.assertEqual(p["currency"], "EUR")
        p2 = store.portfolio(store.list_all(self.e), [], {"trials": 3000, "appetite_annual_loss": 10**12})
        self.assertTrue(p2["within_appetite"])


class HealthTests(unittest.TestCase):
    POL = {"health_domains": {"vuln": {"label": "Vulnerabilities", "weight": 3, "tests": ["a", "b", "c"]}, "gov": {"label": "Governance", "weight": 1, "tests": ["d"]},
                              "det": {"label": "Detection", "weight": 2, "from": "detection"}}}

    def ev(self, **kw):
        return {k: {"result": v} for k, v in kw.items()}

    def test_scores_weights_and_what_was_not_measured(self):
        h = store.health(self.ev(a="pass", b="warn", c="na", d="fail"), None, self.POL)
        dom = {d["key"]: d for d in h["domains"]}
        self.assertEqual(dom["vuln"]["score"], 75)  # na is left out: (1 + 0.5) / 2
        self.assertEqual(dom["gov"]["score"], 0)
        self.assertIsNone(dom["det"]["score"])
        self.assertEqual(h["not_measured"], ["Detection"])
        self.assertEqual(h["score"], round((75 * 3 + 0 * 1) / 4))  # detection is not counted at all

    def test_detection_domain_uses_judged_rules_only(self):
        det = {"rules": [{"metrics": {"tier": t}} for t in ("healthy", "high_fidelity", "noisy", "low_volume")]}
        h = store.health(self.ev(a="pass"), det, self.POL)
        self.assertEqual({d["key"]: d["score"] for d in h["domains"]}["det"], 67)  # 2 of the 3 judged rules
        self.assertEqual(store.health(self.ev(), {"rules": [{"metrics": {"tier": "low_volume"}}]}, self.POL)["score"], None)
        self.assertEqual(store.health({}, None, self.POL)["score"], None)

    def test_real_policy_loads_and_covers_every_test(self):
        from remediation.grc import evidence
        pol = store.policy()
        listed = {t for d in pol["health_domains"].values() for t in d.get("tests", [])}
        self.assertEqual(sorted(listed - set(evidence.TESTS)), [])


class RiskApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.findings = [{"id": "F1", "asset": {"name": "FS-1"}, "severity": "Critical", "kev": {"listed": True}, "sla": {"breached": True}}]
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=self.findings)]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def test_admin_only(self):
        for p in ("/api/cyber-risk/overview", "/api/cyber-risk/scenarios"):
            self.assertEqual(self.client.get(p).status_code, 401, p)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/cyber-risk/overview").status_code, 403)

    def test_scenario_flow_overview_and_what_if(self):
        self.login("admin@t.local")
        body = {**S, "options": [{"name": "EDR", "annual_cost": 50000, "frequency_reduction": 0.4, "loss_reduction": 0.1}]}
        r = self.client.post("/api/cyber-risk/scenarios", json=body)
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["id"]
        self.assertEqual(self.client.post("/api/cyber-risk/scenarios", json={**body, "tef_min": 5}).status_code, 400)
        a = self.client.get(f"/api/cyber-risk/scenarios/{sid}/analysis").json()
        self.assertEqual((a["options"][0]["name"], a["signals"]["known_exploited"]), ("EDR", 1))
        self.assertGreater(a["baseline"]["ale"], a["options"][0]["ale_after"])
        ov = self.client.get("/api/cyber-risk/overview").json()
        self.assertEqual(ov["portfolio"]["scenarios"][0]["id"], sid)
        what = self.client.post("/api/cyber-risk/simulate", json={**body, "tef_likely": 1.0, "tef_max": 3})
        self.assertGreater(what.json()["baseline"]["ale"], a["baseline"]["ale"])
        self.assertEqual(self.client.post("/api/cyber-risk/simulate", json={**body, "options": [{"name": "x", "annual_cost": -5}]}).status_code, 400)
        self.assertEqual(self.client.put(f"/api/cyber-risk/scenarios/{sid}", json={**body, "name": "Renamed"}).json()["name"], "Renamed")
        self.assertEqual(self.client.put("/api/cyber-risk/scenarios/999", json=body).status_code, 404)
        self.assertEqual(self.client.get("/api/cyber-risk/scenarios/999/analysis").status_code, 404)
        self.assertEqual(self.client.delete(f"/api/cyber-risk/scenarios/{sid}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/cyber-risk/scenarios/{sid}").status_code, 404)


if __name__ == "__main__":
    unittest.main()
