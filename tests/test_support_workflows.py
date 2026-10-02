"""
Tests for the support desk's escalation and satisfaction workflows, and for ticket links
on the findings queue: SLA alerts (once per level, right recipients, email only when SMTP is
configured), CSAT rating rules, and the open-ticket counts on /api/queue.
"""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import data as dashboard_data  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.assignments import store as assignments_store  # noqa: E402
from remediation.audit.activity_log import list_activity  # noqa: E402
from remediation.support import analytics, escalation, routing, sla, store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)


def ago(minutes):
    return NOW - datetime.timedelta(minutes=minutes)


TEAMS = {"platform engineering": {"name": "Platform Engineering", "manager_email": "boss@t.local"}}
USERS = [{"email": "admin@t.local", "role": "admin"}, {"email": "tech@t.local", "role": "user"}]


class EscalationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def ticket(self, age_minutes, **kw):
        base = dict(kind="bug", subject="Tenable connector fails", description="d", severity="urgent", impact="organization",
                    team_names=["Platform Engineering"], engine=self.engine, now=ago(age_minutes))
        base.update(kw)
        t = store.create_ticket("req@t.local", **base)
        return t["id"]

    def listing(self):
        return store.list_tickets(status="open_all", engine=self.engine)

    def test_healthy_tickets_raise_nothing(self):
        self.ticket(2)
        self.assertEqual(escalation.run(self.listing(), TEAMS, USERS, None, engine=self.engine), [])

    def test_at_risk_goes_to_the_manager_when_nobody_is_assigned(self):
        self.ticket(26)  # P1 response due in 30 min, 80% = 24 min
        (a,) = escalation.run(self.listing(), TEAMS, USERS, None, engine=self.engine)
        self.assertEqual((a["level"], a["recipients"]), ("at_risk", ["boss@t.local"]))

    def test_at_risk_goes_to_the_assignee_when_there_is_one(self):
        tid = self.ticket(26)
        store.update_ticket(tid, "x@t.local", assignee_email="tech@t.local", status="waiting_on_requester", engine=self.engine, now=ago(25))
        store.update_ticket(tid, "x@t.local", status="in_progress", engine=self.engine, now=ago(24))
        t = [x for x in self.listing() if x["id"] == tid][0]
        self.assertEqual(escalation.recipients(t, "at_risk", TEAMS["platform engineering"], USERS), ["tech@t.local"])

    def test_breach_alerts_assignee_manager_and_admins(self):
        self.ticket(120)
        (a,) = escalation.run(self.listing(), TEAMS, USERS, None, engine=self.engine)
        self.assertEqual(a["level"], "breached")
        self.assertEqual(set(a["recipients"]), {"boss@t.local", "admin@t.local"})

    def test_each_level_alerts_exactly_once(self):
        self.ticket(120)
        self.assertEqual(len(escalation.run(self.listing(), TEAMS, USERS, None, engine=self.engine)), 1)
        self.assertEqual(escalation.run(self.listing(), TEAMS, USERS, None, engine=self.engine), [])
        self.assertEqual(len(list_activity(engine=self.engine, action="support.sla_alert.breached")), 1)

    def test_preview_records_and_sends_nothing(self):
        self.ticket(120)
        sender = MagicMock()
        sender.is_configured.return_value = True
        alerts = escalation.run(self.listing(), TEAMS, USERS, sender, send=False, engine=self.engine)
        self.assertEqual(len(alerts), 1)
        sender.send_email.assert_not_called()
        self.assertEqual(list_activity(engine=self.engine, action="support.sla_alert.breached"), [])

    def test_email_only_when_smtp_is_configured_and_failures_do_not_stop_others(self):
        self.ticket(120)
        self.ticket(130)
        sender = MagicMock()
        sender.is_configured.return_value = True
        sender.send_email.side_effect = [RuntimeError("relay down"), None]
        alerts = escalation.run(self.listing(), TEAMS, USERS, sender, engine=self.engine)
        self.assertEqual(sorted(a["emailed"] for a in alerts), [False, True])
        off = MagicMock()
        off.is_configured.return_value = False
        self.ticket(140)
        alerts = escalation.run(self.listing(), TEAMS, USERS, off, engine=self.engine)
        self.assertTrue(alerts and not alerts[0]["emailed"])
        off.send_email.assert_not_called()

    def test_resolved_and_paused_tickets_are_not_escalated(self):
        a = self.ticket(120)
        store.update_ticket(a, "t@t.local", status="resolved", engine=self.engine, now=ago(5))
        b = self.ticket(120)
        store.update_ticket(b, "t@t.local", status="waiting_on_requester", engine=self.engine, now=ago(100))
        pending = escalation.pending_alerts(self.listing(), TEAMS, USERS, self.engine)
        self.assertNotIn(a, [int(p["ref"][4:]) for p in pending])
        for p in pending:  # the paused ticket's response clock may still be breached, its resolution clock is paused
            self.assertNotEqual(int(p["ref"][4:]), a)

    def test_escalation_view_names_who_would_be_told(self):
        self.ticket(120)
        t = self.listing()[0]
        v = escalation.escalation_view(t, TEAMS["platform engineering"], USERS)
        self.assertEqual(v["level"], "breached")
        self.assertIn("boss@t.local", v["notify"])
        self.assertIsNone(escalation.escalation_view({**t, "status": "resolved"}, None, USERS))


class CsatStoreTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        t = store.create_ticket("req@t.local", "bug", "s", "d", engine=self.engine, now=ago(500))
        self.tid = t["id"]

    def tearDown(self):
        self.engine.dispose()

    def resolve(self):
        store.update_ticket(self.tid, "t@t.local", status="resolved", engine=self.engine, now=ago(10))

    def test_only_the_requester_can_rate_and_only_after_resolution(self):
        with self.assertRaises(ValueError):
            store.rate_ticket(self.tid, "req@t.local", 5, engine=self.engine)
        self.resolve()
        with self.assertRaises(PermissionError):
            store.rate_ticket(self.tid, "other@t.local", 5, engine=self.engine)
        r = store.rate_ticket(self.tid, "REQ@t.local", 4, "good", engine=self.engine)
        self.assertEqual((r["csat_score"], r["csat_comment"]), (4, "good"))

    def test_rating_is_once_and_validated(self):
        self.resolve()
        for bad in (0, 6, True, "5", 3.5):
            with self.assertRaises(ValueError, msg=repr(bad)):
                store.rate_ticket(self.tid, "req@t.local", bad, engine=self.engine)
        store.rate_ticket(self.tid, "req@t.local", 5, engine=self.engine)
        with self.assertRaises(ValueError):
            store.rate_ticket(self.tid, "req@t.local", 1, engine=self.engine)

    def test_analytics_reports_satisfaction(self):
        self.resolve()
        store.rate_ticket(self.tid, "req@t.local", 4, engine=self.engine)
        a = analytics.compute(store.list_tickets(engine=self.engine))
        self.assertEqual(a["csat"], {"average": 4.0, "responses": 1, "response_rate_pct": 100, "satisfied_pct": 100})
        none = analytics.compute([])
        self.assertIsNone(none["csat"]["average"])


PW = "test-password-123"


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.patches = [
            patch.object(db_module, "get_engine", return_value=self.engine),
            patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
            patch.object(dashboard_data, "load_live_queue", side_effect=lambda: [
                {"id": "F-1", "title": "t", "priority": "High", "severity": "High", "asset": {"name": "a1"}, "cve": None,
                 "first_seen": "2026-08-01", "score": 5, "sla": {"breached": False, "days_remaining": 9, "due_date": "2026-08-20"}},
                {"id": "F-2", "title": "u", "priority": "High", "severity": "High", "asset": {"name": "a1"}, "cve": None,
                 "first_seen": "2026-08-01", "score": 5, "sla": {"breached": False, "days_remaining": 9, "due_date": "2026-08-20"}}]),
            patch.object(dashboard_app_module, "_team_by_asset_name", return_value={"a1": "Platform Engineering"}),
            patch.object(routing, "load_rules", return_value={"rules": [{"name": "c", "keywords": ["connector"], "team": "Platform Engineering"}]}),
        ]
        for p in self.patches:
            p.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("tech@t.local", PW, "Tech", role="user", team="Platform Engineering", engine=self.engine)
        auth_users.create_user("req@t.local", PW, "Req", role="user", engine=self.engine)
        auth_users.create_user("other@t.local", PW, "Other", role="user", engine=self.engine)
        assignments_store.create_team("Platform Engineering", "admin@t.local", manager_email="boss@t.local", engine=self.engine)
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
        body = {"kind": "bug", "subject": "The connector fails", "description": "d", "severity": "urgent", "impact": "organization"}
        body.update(over)
        return self.client.post("/api/support/tickets", json=body).json()

    def test_requester_rates_a_resolved_ticket_once(self):
        self.login("req@t.local")
        ref = self.open_ticket()["ref"]
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/csat", json={"score": 5}).status_code, 400)
        self.login("tech@t.local")
        self.client.post(f"/api/support/tickets/{ref}/update", json={"status": "resolved"})
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/csat", json={"score": 5}).status_code, 403)  # agent, not requester
        self.login("other@t.local")
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/csat", json={"score": 5}).status_code, 404)
        self.login("req@t.local")
        r = self.client.post(f"/api/support/tickets/{ref}/csat", json={"score": 5, "comment": "fast"})
        self.assertEqual((r.status_code, r.json()["csat_score"]), (200, 5))
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/csat", json={"score": 1}).status_code, 400)

    def test_staff_see_the_escalation_view_and_requesters_do_not(self):
        self.login("req@t.local")
        ref = self.open_ticket()["ref"]
        self.assertNotIn("escalation", self.client.get(f"/api/support/tickets/{ref}").json())
        self.login("tech@t.local")
        self.assertIn("escalation", self.client.get(f"/api/support/tickets/{ref}").json())

    def test_run_escalations_previews_then_raises_once(self):
        self.login("req@t.local")
        self.open_ticket()
        self.assertEqual(self.client.post("/api/support/escalations/run", json={"confirm": False}).status_code, 403)
        self.login("admin@t.local")
        with patch.object(dashboard_app_module.email_sender, "is_configured", return_value=False), \
                patch.object(sla, "evaluate", side_effect=lambda t, **k: {"priority": "P1", "breached": True, "at_risk": False,
                                                                         "response": {"state": "breached"}, "resolution": {"state": "ok"}}):
            preview = self.client.post("/api/support/escalations/run", json={"confirm": False}).json()
            self.assertTrue(preview["preview_only"])
            self.assertEqual(len(preview["alerts"]), 1)
            self.assertEqual(len(self.client.post("/api/support/escalations/run", json={"confirm": False}).json()["alerts"]), 1)  # still pending
            raised = self.client.post("/api/support/escalations/run", json={"confirm": True}).json()
            self.assertEqual(len(raised["alerts"]), 1)
            self.assertEqual(self.client.post("/api/support/escalations/run", json={"confirm": True}).json()["alerts"], [])

    def test_queue_shows_open_ticket_counts_for_linked_findings_only_when_signed_in(self):
        self.login("req@t.local")
        self.open_ticket(finding_id="F-1")
        rows = {f["id"]: f for f in self.client.get("/api/queue").json()["findings"]}
        self.assertEqual(rows["F-1"]["open_tickets"], 1)
        self.assertNotIn("open_tickets", rows["F-2"])
        self.client.cookies.clear()
        anon = {f["id"]: f for f in self.client.get("/api/queue").json()["findings"]}
        self.assertNotIn("open_tickets", anon["F-1"])


if __name__ == "__main__":
    unittest.main()
