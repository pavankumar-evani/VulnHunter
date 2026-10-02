"""
Tests for SOC operations: cases, queues and tiers, priority, service-level clocks, escalation with required notes, automatic escalation, automatic cases,
metrics, log analysis and the TTP classifier.
"""
import datetime
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
from remediation.utils import db as db_module  # noqa: E402

from remediation.hunting import store, ttp  # noqa: E402
from remediation.soc import cases, loganalysis, metrics  # noqa: E402

T0 = datetime.datetime(2026, 10, 15, 8, 0, tzinfo=datetime.timezone.utc)


def at(minutes):
    return T0 + datetime.timedelta(minutes=minutes)


NOTE = "Checked the host and the account; the process tree looks wrong, handing over."


class CaseWorkflow(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        cases.add_analyst("l1@example.test", 1, self.e)
        cases.add_analyst("l2@example.test", 2, self.e)

    def open(self, **kw):
        f = {"title": "Suspicious process on WEB-1", "severity": "High", "assets": ["WEB-1"]}
        f.update(kw)
        return cases.open_case(f, "alice", self.e, T0)

    def test_priority_is_impact_times_urgency(self):
        self.assertEqual(self.open()["priority"], "P3")  # single x High(3) = 3
        self.assertEqual(self.open(severity="Critical", assets=["a", "b"])["priority"], "P2")  # multiple x 4 = 8
        self.assertEqual(self.open(severity="Critical", assets=[f"h{i}" for i in range(6)])["priority"], "P1")  # widespread x 4 = 12\n        self.assertEqual(self.open(severity="Low")["priority"], "P4")

    def test_impact_grows_with_hosts(self):
        self.assertEqual(self.open(assets=["a"])["impact"], "single")
        self.assertEqual(self.open(assets=["a", "b"])["impact"], "multiple")
        self.assertEqual(self.open(assets=[f"h{i}" for i in range(6)])["impact"], "widespread")

    def test_a_new_case_sits_in_l1(self):
        c = self.open()
        self.assertEqual((c["tier"], c["queue"], c["status"]), (1, "L1", "new"))

    def test_assigning_acknowledges_and_starts_work(self):
        c = cases.assign(self.open()["id"], "l1@example.test", "alice", self.e, at(10))
        self.assertEqual(c["status"], "in_progress")
        self.assertEqual(c["acknowledged_at"], "2026-10-15T08:10:00Z")

    def test_a_tier_one_analyst_cannot_take_an_l2_case(self):
        c = self.open(tier=2)
        with self.assertRaises(ValueError):
            cases.assign(c["id"], "l1@example.test", "alice", self.e, at(1))
        cases.assign(c["id"], "l2@example.test", "alice", self.e, at(1))

    def test_escalation_needs_a_handoff_note(self):
        c = self.open()
        with self.assertRaises(ValueError):
            cases.escalate(c["id"], "too short", "alice", self.e, at(5))
        c = cases.escalate(c["id"], NOTE, "alice", self.e, at(5))
        self.assertEqual((c["tier"], c["queue"], c["status"], c["assignee"], c["escalation_count"]), (2, "L2", "escalated", None, 1))
        self.assertEqual(c["summary"], NOTE)
        self.assertEqual(c["events"][-1]["kind"], "escalated")

    def test_cannot_escalate_past_the_top_tier(self):
        c = self.open(tier=3)
        with self.assertRaises(ValueError):
            cases.escalate(c["id"], NOTE, "alice", self.e, at(5))

    def test_pickup_clock_starts_at_escalation_and_stops_when_the_higher_tier_takes_it(self):
        c = cases.escalate(self.open()["id"], NOTE, "alice", self.e, at(5))
        self.assertEqual(cases.get_case(c["id"], self.e, at(10))["sla"]["pickup"]["state"], "running")
        c = cases.assign(c["id"], "l2@example.test", "bob", self.e, at(12))
        self.assertTrue(c["sla"]["pickup"]["done"])
        self.assertEqual(c["sla"]["pickup"]["state"], "met")

    def test_resolve_needs_a_summary_and_an_allowed_code(self):
        c = self.open()
        with self.assertRaises(ValueError):
            cases.resolve(c["id"], "false-positive", "", "alice", self.e, at(3))
        with self.assertRaises(ValueError):
            cases.resolve(c["id"], "accepted-risk", NOTE, "alice", self.e, at(3))  # L1 may not accept risk
        with self.assertRaises(ValueError):
            cases.resolve(c["id"], "nonsense", NOTE, "alice", self.e, at(3))
        c = cases.resolve(c["id"], "false-positive", NOTE, "alice", self.e, at(3))
        self.assertEqual((c["status"], c["resolution"]), ("resolved", "false-positive"))

    def test_resolving_closes_the_linked_alerts_with_a_disposition(self):
        a, _ = store.receive_alert({"external_id": "x1", "title": "t", "severity": "High"}, self.e)
        c = self.open(alert_ids=[a["id"]])
        self.assertEqual(store.get_alert(a["id"], self.e)["status"], "investigating")
        cases.resolve(c["id"], "true-positive", NOTE, "alice", self.e, at(3))
        al = store.get_alert(a["id"], self.e)
        self.assertEqual((al["status"], al["disposition"]), ("closed", "true-positive"))

    def test_close_requires_resolved_and_reopen_counts(self):
        c = self.open()
        with self.assertRaises(ValueError):
            cases.close(c["id"], NOTE, "alice", self.e, at(2))
        cases.resolve(c["id"], "benign", NOTE, "alice", self.e, at(3))
        cases.close(c["id"], "", "alice", self.e, at(4))
        with self.assertRaises(ValueError):
            cases.reopen(c["id"], "", "alice", self.e, at(5))
        c = cases.reopen(c["id"], "New alert on the same host", "alice", self.e, at(5))
        self.assertEqual((c["status"], c["reopen_count"], c["resolution"]), ("new", 1, None))

    def test_a_closed_case_cannot_be_edited(self):
        c = self.open()
        cases.resolve(c["id"], "benign", NOTE, "alice", self.e, at(3))
        with self.assertRaises(ValueError):
            cases.assign(c["id"], "l1@example.test", "alice", self.e, at(4))

    def test_sla_states(self):
        c = self.open(severity="Critical")  # single x 4 = 4 -> P3: ack 120m
        self.assertEqual(c["priority"], "P3")
        self.assertEqual(cases.get_case(c["id"], self.e, at(30))["sla"]["ack"]["state"], "running")
        self.assertEqual(cases.get_case(c["id"], self.e, at(100))["sla"]["ack"]["state"], "at_risk")
        g = cases.get_case(c["id"], self.e, at(130))
        self.assertEqual((g["sla"]["ack"]["state"], g["sla"]["worst"]), ("breached", "breached"))

    def test_sweep_escalates_once_per_tier_with_an_event(self):
        c = self.open(severity="Critical", assets=[f"h{i}" for i in range(6)])  # P1: resolve 240m
        self.assertEqual(cases.sweep(self.e, at(200)), [])
        self.assertEqual(cases.sweep(self.e, at(250)), [c["id"]])
        g = cases.get_case(c["id"], self.e, at(251))
        self.assertEqual((g["tier"], g["status"]), (2, "escalated"))
        self.assertEqual(g["events"][-1]["kind"], "auto_escalated")
        self.assertEqual(cases.sweep(self.e, at(260)), [])  # not again straight away
        self.assertEqual(cases.sweep(self.e, at(500)), [c["id"]])  # but after another full target, to L3
        self.assertEqual(cases.get_case(c["id"], self.e, at(501))["tier"], 3)
        self.assertEqual(cases.sweep(self.e, at(5000)), [])  # top tier

    def test_suggested_assignee_is_the_least_loaded_in_tier(self):
        cases.add_analyst("l1b@example.test", 1, self.e)
        cases.assign(self.open()["id"], "l1@example.test", "alice", self.e, at(1))
        self.assertEqual(cases.suggest_assignee(1, self.e), "l1b@example.test")
        self.assertIsNone(cases.suggest_assignee(3, self.e))

    def test_summary_is_built_from_the_facts(self):
        c = self.open(techniques=[{"id": "T1059", "name": "Command and Scripting Interpreter"}], recommendation="likely-true-positive")
        s = cases.summarise(c)
        for part in ("P3", "WEB-1", "T1059", "likely-true-positive", "not yet owned"):
            self.assertIn(part, s)


class AutoCase(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def alert(self, i, sev="High"):
        a, _ = store.receive_alert({"external_id": f"e{i}", "title": f"Alert {i}", "severity": sev, "asset": "WEB-1", "technique": "T1190"}, self.e)
        return a

    def test_opens_for_a_likely_true_positive_once(self):
        a = self.alert(1)
        c = cases.auto_case(a, {"verdict": "likely-true-positive", "confidence": "high"}, self.e, T0)
        self.assertEqual((c["source"], c["tier"], c["recommendation"]), ("auto", 1, "likely-true-positive"))
        self.assertIsNone(cases.auto_case(a, {"verdict": "likely-true-positive", "confidence": "high"}, self.e, T0))

    def test_skips_false_positives_and_low_severity(self):
        self.assertIsNone(cases.auto_case(self.alert(1), {"verdict": "likely-false-positive", "confidence": "high"}, self.e, T0))
        self.assertIsNone(cases.auto_case(self.alert(2, "Low"), {"verdict": "likely-true-positive", "confidence": "high"}, self.e, T0))


class Metrics(unittest.TestCase):
    def test_metrics_from_cases(self):
        e = create_engine("sqlite:///:memory:")
        cases.add_analyst("l1@example.test", 1, e)
        a = cases.open_case({"title": "a", "severity": "High", "assets": ["h"], "recommendation": "likely-true-positive"}, "x", e, T0)
        cases.assign(a["id"], "l1@example.test", "x", e, at(10))
        cases.resolve(a["id"], "true-positive", NOTE, "l1@example.test", e, at(60))
        b = cases.open_case({"title": "b", "severity": "Low", "assets": ["h"], "recommendation": "likely-true-positive", "source": "auto"}, "x", e, T0)
        cases.resolve(b["id"], "false-positive", NOTE, "l1@example.test", e, at(20))
        c = cases.open_case({"title": "c", "severity": "High", "assets": ["h"]}, "x", e, T0)
        cases.escalate(c["id"], NOTE, "x", e, at(5))
        m = metrics.compute(e, days=7, now=at(120))
        self.assertEqual((m["totals"]["opened"], m["totals"]["resolved"], m["totals"]["open_now"]), (3, 2, 1))
        self.assertEqual(m["mttr_minutes"], 40.0)
        self.assertEqual(m["mtta_minutes"], 15.0)  # a acked at 10, b acked at resolve (20)
        self.assertEqual(m["backlog"]["by_queue"], {"L2": 1})
        self.assertEqual(m["resolution_mix"], {"true-positive": 1, "false-positive": 1})
        self.assertEqual(m["false_positive_rate"], 0.5)
        self.assertEqual(m["recommendation_accuracy"]["likely-true-positive"], {"agreed": 1, "judged": 2, "rate": 0.5})
        self.assertAlmostEqual(m["automation_rate"], 0.333, places=3)
        self.assertAlmostEqual(m["escalation"]["rate"], 0.333, places=3)
        self.assertEqual(len(m["daily"]), 7)
        self.assertEqual(sum(d["opened"] for d in m["daily"]), 3)

    def test_empty_metrics_are_none_not_zero(self):
        m = metrics.compute(create_engine("sqlite:///:memory:"), days=7, now=T0)
        self.assertIsNone(m["mttr_minutes"])
        self.assertIsNone(m["sla"]["resolve"]["compliance"])


class LogAnalysis(unittest.TestCase):
    def test_beaconing_burst_and_auth_pattern(self):
        lines = []
        for i in range(10):  # every 60 s to the same destination
            lines.append(f"2026-10-15 08:{i:02d}:00 src=10.0.0.5 dst=185.220.101.4 action=allow")
        for i in range(30):  # a burst at 09:00
            lines.append(f"2026-10-15 09:00:{i:02d} src=10.0.0.{20 + i % 3} dst=10.0.1.1 action=allow")
        for m in range(10, 20):  # steady background, 3 per minute
            for s in (5, 25, 45):
                lines.append(f"2026-10-15 09:{m}:{s:02d} src=10.0.0.9 dst=10.0.1.2 action=allow")
        for i in range(6):
            lines.append(f"2026-10-15 10:00:{i:02d} user=bob src=45.33.32.9 msg=authentication failure")
        lines.append("2026-10-15 10:01:00 user=bob src=45.33.32.9 msg=login successful")
        r = loganalysis.analyse("\n".join(lines))
        self.assertTrue(any(b["destination"] == "185.220.101.4" for b in r["beaconing"]))
        self.assertTrue(r["bursts"])
        self.assertEqual(r["auth_pattern"][0]["who"], "bob")
        self.assertEqual(r["auth_pattern"][0]["failures_before_success"], 6)
        self.assertIn("185.220.101.4", r["indicators"]["ips"])

    def test_json_lines_and_empty_input(self):
        r = loganalysis.analyse('{"timestamp": "2026-10-15T08:00:00Z", "user": "carol", "src_ip": "10.1.1.1"}\n{"user": "carol"}')
        self.assertEqual(r["lines"], 2)
        self.assertEqual(r["top"]["users"][0], {"value": "carol", "count": 2})
        self.assertEqual(loganalysis.analyse("")["lines"], 0)

    def test_regular_intervals_below_five_seconds_are_not_beacons(self):
        lines = [f"2026-10-15 08:00:{i:02d} src=10.0.0.5 dst=10.0.0.6" for i in range(0, 20, 2)]
        self.assertEqual(loganalysis.analyse("\n".join(lines))["beaconing"], [])


class TtpClassifier(unittest.TestCase):
    def test_known_wording_is_identified(self):
        r = ttp.classify("Multiple failed logins for 40 accounts from one source, password spraying")
        self.assertEqual(r["techniques"][0]["id"], "T1110")
        self.assertTrue(r["confident"])
        self.assertTrue(r["techniques"][0]["evidence"])

    def test_ransom_wording(self):
        r = ttp.classify("files encrypted and a ransom note dropped, .locked extension")
        self.assertEqual(r["techniques"][0]["id"], "T1486")

    def test_a_stated_id_is_reported_as_stated(self):
        r = ttp.classify("Analyst noted T1059.001 on the host")
        self.assertEqual((r["techniques"][0]["id"], r["techniques"][0]["source"], r["confident"]), ("T1059.001", "stated", True))

    def test_unrelated_text_is_not_confident(self):
        self.assertFalse(ttp.classify("Weekly team lunch scheduled for Friday")["confident"])
        self.assertEqual(ttp.classify("zzzz qqqq")["techniques"], [])

    def test_labelled_history_shifts_the_answer(self):
        text = "frobnicator widget qwertyx"
        self.assertEqual(ttp.classify(text)["known_tokens"], 0)
        r = ttp.classify(text, [(text, "T1499")])
        self.assertEqual(r["techniques"][0]["id"], "T1499")

    def test_same_input_same_output(self):
        a = ttp.classify("password spraying against vpn")
        self.assertEqual(a, ttp.classify("password spraying against vpn"))


class SocOpsApi(unittest.TestCase):
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
        self.login("admin@t.local")

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": self.PW})

    def test_admin_only(self):
        self.login("user@t.local")
        for path in ("/api/soc/cases", "/api/soc/metrics", "/api/soc/analysts", "/api/soc/cases/1"):
            self.assertEqual(self.client.get(path).status_code, 403, path)
        self.assertEqual(self.client.post("/api/soc/ttp", json={"text": "x"}).status_code, 403)

    def test_case_lifecycle_over_the_api(self):
        c = self.client.post("/api/soc/cases", json={"title": "Odd logins", "severity": "High", "assets": ["WEB-1"]})
        self.assertEqual(c.status_code, 200)
        cid = c.json()["id"]
        r = self.client.post(f"/api/soc/cases/{cid}/escalate", json={"summary": "short"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post(f"/api/soc/cases/{cid}/escalate", json={"summary": NOTE})
        self.assertEqual((r.json()["tier"], r.json()["status"]), (2, "escalated"))
        self.assertEqual(self.client.post(f"/api/soc/cases/{cid}/assign", json={}).json()["assignee"], "admin@t.local")
        r = self.client.post(f"/api/soc/cases/{cid}/resolve", json={"resolution": "true-positive", "summary": NOTE})
        self.assertEqual(r.json()["status"], "resolved")
        d = self.client.get(f"/api/soc/cases/{cid}").json()
        self.assertEqual([e["kind"] for e in d["events"]][:3], ["opened", "escalated", "assigned"])
        self.assertIn("Odd logins", d["generated_summary"])
        self.assertEqual(self.client.get("/api/soc/cases/999").status_code, 404)
        self.assertEqual(self.client.post(f"/api/soc/cases/{cid}/bogus", json={}).status_code, 404)
        self.assertEqual(self.client.post("/api/soc/cases/999/note", json={"note": "x"}).status_code, 404)

    def test_metrics_ttp_and_logs(self):
        self.client.post("/api/soc/cases", json={"title": "a", "severity": "Low"})
        m = self.client.get("/api/soc/metrics?days=7").json()
        self.assertEqual(m["totals"]["opened"], 1)
        t = self.client.post("/api/soc/ttp", json={"text": "password spraying with many failed logins"}).json()
        self.assertEqual(t["techniques"][0]["id"], "T1110")
        cid = self.client.get("/api/soc/cases").json()["cases"][0]["id"]
        lg = self.client.post(f"/api/soc/cases/{cid}/analyse-logs", json={"text": "2026-10-15 08:00:00 user=bob msg=hello"}).json()
        self.assertEqual(lg.get("lines"), 1, lg)
        kinds = [e["kind"] for e in self.client.get(f"/api/soc/cases/{cid}").json()["events"]]
        self.assertIn("evidence", kinds)

    def test_analysts_and_tier_rule(self):
        self.client.post("/api/soc/analysts", json={"email": "l1@t.local", "tier": 1})
        cid = self.client.post("/api/soc/cases", json={"title": "x", "tier": 2}).json()["id"]
        r = self.client.post(f"/api/soc/cases/{cid}/assign", json={"assignee": "l1@t.local"})
        self.assertEqual(r.status_code, 400)
        self.client.delete("/api/soc/analysts/l1@t.local")
        self.assertEqual(self.client.get("/api/soc/analysts").json()["analysts"], [])

    def test_usecases_recommend_and_draft_routes(self):
        from remediation.hunting import store as hs
        a, _ = hs.receive_alert({"external_id": "z1", "title": "t", "severity": "High", "technique": "T1190"}, self.engine)
        u = self.client.get("/api/detections/usecases")
        self.assertEqual(u.status_code, 200)
        self.assertIn("counts", u.json())
        self.assertEqual(self.client.post("/api/detections/usecases/nope/status", json={"status": "accepted", "note": "x"}).status_code, 404)
        self.assertEqual(self.client.get(f"/api/soc/alerts/{a['id']}/recommend-playbook").json()["basis"], "none")
        self.assertEqual(self.client.get("/api/soc/alerts/999/recommend-playbook").status_code, 404)
        d = self.client.post("/api/soar/draft-playbook", json={"alert_id": a["id"]}).json()
        self.assertTrue(d["dry_run"])
        self.assertIn("T1190", d["prompt"])
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/detections/usecases").status_code, 403)
        self.assertEqual(self.client.post("/api/soar/draft-playbook", json={"alert_id": 1}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
