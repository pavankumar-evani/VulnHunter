"""
Tests for the support desk's ITSM layer: priority (impact x urgency), SLA clocks, team
routing, team-agent access, pause/resume/reopen, finding links, and analytics.
Store tests use fixed timestamps and an in-memory engine; API tests use a temp SQLite file.
"""
import datetime
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
from sqlalchemy import create_engine, text  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import data as dashboard_data  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.assignments import store as assignments_store  # noqa: E402
from remediation.support import analytics, routing, sla, store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

UTC = datetime.timezone.utc
T0 = datetime.datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def at(minutes):
    return T0 + datetime.timedelta(minutes=minutes)


class PolicyTests(unittest.TestCase):
    def test_priority_matrix(self):
        cases = {("organization", "urgent"): "P1", ("organization", "high"): "P1", ("organization", "normal"): "P2",
                 ("team", "high"): "P2", ("team", "normal"): "P3", ("individual", "urgent"): "P3",
                 ("individual", "normal"): "P4", ("individual", "low"): "P4"}
        for (impact, urgency), expected in cases.items():
            self.assertEqual(sla.priority_for(impact, urgency), expected, (impact, urgency))

    def test_due_times_follow_the_targets(self):
        r, s = sla.due_times(sla.fmt(T0), "P1")
        self.assertEqual((sla.parse(r) - T0).total_seconds() / 60, 30)
        self.assertEqual((sla.parse(s) - T0).total_seconds() / 3600, 4)


class ClockTests(unittest.TestCase):
    def ticket(self, **kw):
        base = {"created_at": sla.fmt(T0), "priority": "P1", "status": "open", "response_due_at": sla.fmt(at(30)),
                "resolution_due_at": sla.fmt(at(240)), "first_response_at": None, "resolved_at": None, "paused_at": None}
        base.update(kw)
        return base

    def test_running_clock_goes_ok_then_at_risk_then_breached(self):
        t = self.ticket()
        self.assertEqual(sla.evaluate(t, at(10))["response"]["state"], "ok")
        self.assertEqual(sla.evaluate(t, at(26))["response"]["state"], "at_risk")
        e = sla.evaluate(t, at(45))
        self.assertEqual(e["response"]["state"], "breached")
        self.assertTrue(e["breached"])

    def test_finished_clocks_are_met_or_missed(self):
        met = sla.evaluate(self.ticket(first_response_at=sla.fmt(at(20))), at(100))
        self.assertEqual(met["response"]["state"], "met")
        missed = sla.evaluate(self.ticket(first_response_at=sla.fmt(at(50))), at(100))
        self.assertEqual(missed["response"]["state"], "missed")
        done = sla.evaluate(self.ticket(status="resolved", resolved_at=sla.fmt(at(200)), first_response_at=sla.fmt(at(5))), at(500))
        self.assertEqual(done["resolution"]["state"], "met")
        self.assertFalse(done["breached"])

    def test_paused_clock_does_not_breach(self):
        e = sla.evaluate(self.ticket(status="waiting_on_requester", paused_at=sla.fmt(at(60)), first_response_at=sla.fmt(at(5))), at(900))
        self.assertEqual(e["resolution"]["state"], "paused")
        self.assertFalse(e["breached"])

    def test_old_tickets_without_itsm_fields_are_safe(self):
        e = sla.evaluate({"created_at": sla.fmt(T0), "status": "open"}, at(5))
        self.assertEqual((e["breached"], e["at_risk"]), (False, False))
        self.assertEqual(e["response"]["state"], "n/a")


class RoutingTests(unittest.TestCase):
    RULES = {"default_team": "Triage", "rules": [
        {"name": "access", "kinds": ["access"], "keywords": ["sso"], "team": "Security Operations"},
        {"name": "connectors", "keywords": ["connector"], "team": "Platform Engineering"},
        {"name": "p1", "min_priority": "P1", "team": "Security Operations"},
        {"name": "ghost", "keywords": ["ghost"], "team": "Team That Does Not Exist"}]}
    TEAMS = {"Security Operations", "Platform Engineering", "Triage"}

    def go(self, kind="bug", subject="s", description="d", priority="P3"):
        return routing.route(kind, subject, description, priority, self.TEAMS, self.RULES)

    def test_first_matching_rule_wins(self):
        self.assertEqual(self.go(kind="access")["team"], "Security Operations")
        self.assertEqual(self.go(subject="Tenable connector fails")["team"], "Platform Engineering")

    def test_keywords_are_case_insensitive_and_in_the_description_too(self):
        self.assertEqual(self.go(description="The CONNECTOR times out")["team"], "Platform Engineering")

    def test_min_priority_rule_only_matches_when_urgent_enough(self):
        self.assertEqual(self.go(priority="P1")["rule"], "p1")
        self.assertEqual(self.go(priority="P3")["rule"], "default")

    def test_a_rule_for_a_team_that_does_not_exist_is_skipped(self):
        r = self.go(subject="ghost story")
        self.assertEqual((r["team"], r["rule"]), ("Triage", "default"))

    def test_no_default_means_unrouted(self):
        r = routing.route("bug", "s", "d", "P3", self.TEAMS, {"rules": []})
        self.assertIsNone(r["team"])


class StoreItsmTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        self.teams = ["Platform Engineering", "Security Operations"]

    def tearDown(self):
        self.engine.dispose()

    def make(self, now=T0, **kw):
        args = dict(kind="bug", subject="Tenable connector fails", description="d", severity="normal",
                    impact="team", team_names=self.teams, engine=self.engine, now=now)
        args.update(kw)
        return store.create_ticket("a@t.local", **args)

    def test_new_ticket_is_prioritised_routed_and_timed(self):
        t = self.make()
        self.assertEqual((t["priority"], t["team"]), ("P3", "Platform Engineering"))
        self.assertEqual(sla.parse(t["response_due_at"]) - T0, datetime.timedelta(hours=4))

    def test_first_staff_reply_stops_the_response_clock_requester_reply_does_not(self):
        t = self.make()
        store.add_comment(t["id"], "a@t.local", "any news?", engine=self.engine, now=at(5))
        self.assertIsNone(store.get_ticket(t["id"], self.engine)["first_response_at"])
        store.add_comment(t["id"], "tech@t.local", "looking", internal=True, engine=self.engine, now=at(6))
        self.assertIsNone(store.get_ticket(t["id"], self.engine)["first_response_at"])
        store.add_comment(t["id"], "tech@t.local", "looking now", engine=self.engine, now=at(7))
        self.assertEqual(store.get_ticket(t["id"], self.engine)["first_response_at"], sla.fmt(at(7)))

    def test_acknowledging_an_open_ticket_counts_as_the_first_response(self):
        t = self.make()
        r = store.update_ticket(t["id"], "tech@t.local", status="in_progress", engine=self.engine, now=at(9))
        self.assertEqual(r["first_response_at"], sla.fmt(at(9)))

    def test_waiting_on_requester_pauses_and_a_reply_pushes_the_due_time_out(self):
        t = self.make(severity="urgent", impact="organization")  # P1, 4h resolution
        due = t["resolution_due_at"]
        store.update_ticket(t["id"], "tech@t.local", status="waiting_on_requester", engine=self.engine, now=at(60))
        paused = store.get_ticket(t["id"], self.engine)
        self.assertEqual(paused["sla"]["resolution"]["state"], "paused")
        store.add_comment(t["id"], "a@t.local", "here is the log", engine=self.engine, now=at(180))
        r = store.get_ticket(t["id"], self.engine)
        self.assertEqual(r["status"], "in_progress")
        self.assertIsNone(r["paused_at"])
        self.assertEqual(sla.parse(r["resolution_due_at"]) - sla.parse(due), datetime.timedelta(minutes=120))

    def test_changing_severity_recomputes_priority_and_due_times(self):
        t = self.make()
        r = store.update_ticket(t["id"], "admin@t.local", severity="urgent", impact="organization", engine=self.engine, now=at(3))
        self.assertEqual(r["priority"], "P1")
        self.assertEqual(sla.parse(r["resolution_due_at"]) - T0, datetime.timedelta(hours=4))

    def test_reopening_counts_and_clears_resolved_at(self):
        t = self.make()
        store.update_ticket(t["id"], "x@t.local", status="resolved", engine=self.engine, now=at(30))
        r = store.update_ticket(t["id"], "x@t.local", status="open", engine=self.engine, now=at(60))
        self.assertEqual(r["reopen_count"], 1)
        self.assertIsNone(r["resolved_at"])

    def test_team_filter_and_finding_link(self):
        self.make(finding_id="FIND-7")
        self.make(subject="login problem", kind="access", team_names=self.teams)
        self.assertEqual(len(store.list_tickets(team="Platform Engineering", engine=self.engine)), 1)
        self.assertEqual(len(store.list_tickets(finding_id="FIND-7", engine=self.engine)), 1)

    def test_bad_impact_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make(impact="galaxy")

    def test_an_old_table_gains_the_new_columns(self):
        eng = create_engine("sqlite:///:memory:")
        with eng.begin() as c:
            c.execute(text("CREATE TABLE support_tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, kind VARCHAR NOT NULL, "
                           "severity VARCHAR NOT NULL, subject VARCHAR NOT NULL, description TEXT NOT NULL, status VARCHAR NOT NULL, "
                           "requester_email VARCHAR NOT NULL, assignee_email VARCHAR, resolution TEXT, created_at VARCHAR NOT NULL, "
                           "updated_at VARCHAR NOT NULL, resolved_at VARCHAR)"))
            c.execute(text("INSERT INTO support_tickets (kind,severity,subject,description,status,requester_email,created_at,updated_at) "
                           "VALUES ('bug','normal','old','d','open','a@t.local','2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')"))
        db_module.ensure_schema(eng)
        old = store.get_ticket(1, eng)
        self.assertEqual(old["subject"], "old")
        self.assertEqual(old["sla"]["response"]["state"], "n/a")
        eng.dispose()


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        teams = ["Platform Engineering", "Security Operations"]
        mk = lambda now, **kw: store.create_ticket("a@t.local", **{**dict(kind="bug", subject="connector issue", description="d", severity="normal", impact="team", team_names=teams, engine=self.engine, now=now), **kw})  # noqa: E731
        self.a = mk(T0)                                           # P3, resolved fast
        store.add_comment(self.a["id"], "t@t.local", "on it", engine=self.engine, now=at(30))
        store.update_ticket(self.a["id"], "t@t.local", status="resolved", engine=self.engine, now=at(120))
        self.b = mk(T0, severity="urgent", impact="organization", subject="login outage", kind="access")   # P1, left to breach
        self.c = mk(at(60), subject="report export")               # open, other team
        store.update_ticket(self.c["id"], "t@t.local", assignee_email="tech@t.local", engine=self.engine, now=at(61))
        self.now = at(600)

    def tickets(self):
        return store.list_tickets(engine=self.engine)

    def test_headline_numbers(self):
        a = analytics.compute(self.tickets(), as_of=self.now)
        self.assertEqual(a["totals"]["tickets"], 3)
        self.assertEqual(a["totals"]["resolved"], 1)
        self.assertEqual(a["mttr_hours"], 2.0)
        self.assertEqual(a["first_response_avg_minutes"], 30)

    def test_by_team_and_priority(self):
        a = analytics.compute(self.tickets(), as_of=self.now)
        names = {r["name"] for r in a["by_team"]}
        self.assertIn("Platform Engineering", names)
        self.assertEqual(a["by_priority"]["P1"]["total"], 1)
        self.assertEqual(a["by_priority"]["P3"]["mttr_hours"], 2.0)

    def test_sla_compliance_uses_only_finished_clocks(self):
        a = analytics.compute(self.tickets(), as_of=self.now)
        self.assertEqual(a["sla_compliance_pct"], 100)  # the one resolved ticket met both clocks

    def test_empty_desk_returns_none_not_zero(self):
        a = analytics.compute([], as_of=self.now)
        self.assertIsNone(a["mttr_hours"])
        self.assertIsNone(a["sla_compliance_pct"])
        self.assertIsNone(a["reopen_rate_pct"])
        self.assertEqual(len(a["trend"]), 14)

    def test_ageing_and_trend_buckets(self):
        a = analytics.compute(self.tickets(), as_of=at(60 * 24 * 10))
        self.assertEqual({b["bucket"]: b["count"] for b in a["ageing"]}["8-30 days"], 2)
        self.assertEqual(sum(d["created"] for d in a["trend"]), 3)  # created 10 days earlier, inside the 14-day window
        self.assertEqual(sum(d["resolved"] for d in a["trend"]), 1)

    def test_breached_open_counts_the_unanswered_p1(self):
        a = analytics.compute(self.tickets(), as_of=self.now)
        self.assertGreaterEqual(a["totals"]["breached_open"], 1)


PW = "test-password-123"
ADMIN, ALPHA, ALPHA2, BETA, SOLO = "admin@t.local", "alpha@t.local", "alpha2@t.local", "beta@t.local", "solo@t.local"


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.patches = [
            patch.object(db_module, "get_engine", return_value=self.engine),
            patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
            patch.object(dashboard_data, "load_live_queue", side_effect=lambda: [{
                "id": "F-1", "title": "t", "priority": "High", "severity": "High", "asset": {"name": "a1"}, "cve": None,
                "first_seen": "2026-08-01", "score": 5, "sla": {"breached": False, "days_remaining": 9, "due_date": "2026-08-20"}}]),
            patch.object(dashboard_app_module, "_team_by_asset_name", return_value={"a1": "Platform Engineering"}),
            patch.object(routing, "load_rules", return_value={"rules": [
                {"name": "connectors", "keywords": ["connector"], "team": "Platform Engineering"}]}),
        ]
        for p in self.patches:
            p.start()
        auth_users.create_user(ADMIN, PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user(ALPHA, PW, "Alpha", role="user", team="Platform Engineering", engine=self.engine)
        auth_users.create_user(ALPHA2, PW, "Alpha Two", role="user", team="Platform Engineering", engine=self.engine)
        auth_users.create_user(BETA, PW, "Beta", role="user", team="Security Operations", engine=self.engine)
        auth_users.create_user(SOLO, PW, "Solo", role="user", engine=self.engine)
        for name in ("Platform Engineering", "Security Operations"):
            assignments_store.create_team(name, ADMIN, engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/api/auth/login", json={"email": email, "password": PW}).status_code, 200)

    def open_ticket(self, **over):
        body = {"kind": "bug", "subject": "The connector fails", "description": "details", "severity": "high", "impact": "team"}
        body.update(over)
        return self.client.post("/api/support/tickets", json=body)

    def test_ticket_is_routed_prioritised_and_timed_on_creation(self):
        self.login(SOLO)
        t = self.open_ticket().json()
        self.assertEqual((t["team"], t["priority"]), ("Platform Engineering", "P2"))
        self.assertEqual(t["sla"]["response"]["state"], "ok")

    def test_team_members_work_their_queue_but_other_teams_cannot_see_it(self):
        self.login(SOLO)
        ref = self.open_ticket().json()["ref"]
        self.login(ALPHA)
        listing = self.client.get("/api/support/tickets").json()
        self.assertEqual([t["ref"] for t in listing["tickets"]], [ref])
        self.assertTrue(listing["is_agent"])
        self.assertEqual(listing["summary"]["open"], 1)
        self.login(BETA)
        self.assertEqual(self.client.get("/api/support/tickets").json()["tickets"], [])
        self.assertEqual(self.client.get(f"/api/support/tickets/{ref}").status_code, 404)

    def test_agent_can_triage_but_not_reprioritise_or_reroute(self):
        self.login(SOLO)
        ref = self.open_ticket().json()["ref"]
        self.login(ALPHA)
        ok = self.client.post(f"/api/support/tickets/{ref}/update", json={"status": "in_progress", "assignee_email": ALPHA})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.json()["assignee_email"], ALPHA)
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/update", json={"severity": "low"}).status_code, 403)
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/update", json={"team": "Security Operations"}).status_code, 403)
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/escalate", json={"confirm": False}).status_code, 403)

    def test_requester_cannot_triage(self):
        self.login(SOLO)
        ref = self.open_ticket().json()["ref"]
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/update", json={"status": "closed"}).status_code, 403)

    def test_admin_can_reroute_and_reprioritise(self):
        self.login(SOLO)
        ref = self.open_ticket().json()["ref"]
        self.login(ADMIN)
        r = self.client.post(f"/api/support/tickets/{ref}/update", json={"team": "security operations", "severity": "urgent", "impact": "organization"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["team"], r.json()["priority"]), ("Security Operations", "P1"))
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/update", json={"team": "Nope"}).status_code, 400)

    def test_agents_see_internal_notes_requesters_do_not(self):
        self.login(SOLO)
        ref = self.open_ticket().json()["ref"]
        self.login(ALPHA)
        self.client.post(f"/api/support/tickets/{ref}/comments", json={"body": "root cause is the proxy", "internal": True})
        self.assertEqual(len(self.client.get(f"/api/support/tickets/{ref}").json()["comments"]), 1)
        self.login(SOLO)
        self.assertEqual(self.client.get(f"/api/support/tickets/{ref}").json()["comments"], [])

    def test_ticket_can_link_to_a_visible_finding_and_be_found_from_it(self):
        self.login(SOLO)
        r = self.open_ticket(finding_id="F-1")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.open_ticket(finding_id="NOPE").status_code, 404)
        self.assertEqual(len(self.client.get("/api/findings/F-1/tickets").json()["tickets"]), 1)

    def test_analytics_scope_depends_on_who_asks(self):
        self.login(SOLO)
        self.open_ticket()
        self.open_ticket(subject="Something unrelated", description="x", impact="individual", severity="low")
        self.assertEqual(self.client.get("/api/support/analytics").status_code, 403)
        self.login(ADMIN)
        a = self.client.get("/api/support/analytics").json()
        self.assertEqual((a["scope"], a["totals"]["tickets"]), ("all teams", 2))
        self.login(ALPHA)
        b = self.client.get("/api/support/analytics").json()
        self.assertEqual((b["scope"], b["totals"]["tickets"]), ("Platform Engineering", 1))

    def test_policy_endpoint_exposes_the_live_targets(self):
        self.login(SOLO)
        p = self.client.get("/api/support/policy").json()
        self.assertIn("P1", p["sla"]["targets"])

    def test_anonymous_callers_are_refused(self):
        for path in ("/api/support/analytics", "/api/support/policy", "/api/findings/F-1/tickets"):
            self.assertEqual(self.client.get(path).status_code, 401, path)


if __name__ == "__main__":
    unittest.main()
