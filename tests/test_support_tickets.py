"""
Tests for the in-app support tickets (remediation/support/store.py and the
/api/support/tickets routes). Store tests use a fresh in-memory SQLite engine; API tests
use a temporary on-disk SQLite file and a real TestClient login, same harness as
tests/test_assignments_api.py. No test ever sends real email.
"""
import datetime
import os
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
from remediation.support import store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 2, 9, 0, tzinfo=datetime.timezone.utc)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def make(self, who="a@t.local", **kw):
        args = dict(kind="bug", subject="Queue is empty", description="It shows 0 rows.", engine=self.engine, now=NOW)
        args.update(kw)
        return store.create_ticket(who, **{k: v for k, v in args.items()})

    def test_create_assigns_a_reference_and_starts_open(self):
        t = self.make()
        self.assertEqual(t["ref"], f"TKT-{t['id']}")
        self.assertEqual(t["status"], "open")
        self.assertEqual(t["severity"], "normal")
        self.assertEqual(store.parse_ref(t["ref"]), t["id"])

    def test_rejects_bad_input(self):
        for bad in (dict(kind="nope"), dict(severity="critical"), dict(subject="  "), dict(description=""),
                    dict(subject="x" * 201)):
            with self.assertRaises(ValueError, msg=str(bad)):
                self.make(**bad)
        with self.assertRaises(ValueError):
            store.parse_ref("TKT-abc")

    def test_requester_email_is_normalised_and_filterable(self):
        self.make("A@T.local")
        self.make("b@t.local")
        mine = store.list_tickets(requester_email="a@t.local", engine=self.engine)
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["requester_email"], "a@t.local")

    def test_internal_comments_are_hidden_unless_asked_for(self):
        t = self.make()
        store.add_comment(t["id"], "admin@t.local", "visible", engine=self.engine, now=NOW)
        store.add_comment(t["id"], "admin@t.local", "private", internal=True, engine=self.engine, now=NOW)
        self.assertEqual([c["body"] for c in store.list_comments(t["id"], engine=self.engine)], ["visible"])
        self.assertEqual(len(store.list_comments(t["id"], include_internal=True, engine=self.engine)), 2)

    def test_requester_reply_reopens_a_ticket_waiting_on_them(self):
        t = self.make("a@t.local")
        store.update_ticket(t["id"], "admin@t.local", status="waiting_on_requester", engine=self.engine, now=NOW)
        store.add_comment(t["id"], "a@t.local", "here is the log", engine=self.engine, now=NOW)
        self.assertEqual(store.get_ticket(t["id"], self.engine)["status"], "in_progress")

    def test_resolving_stamps_resolved_at_and_reopening_clears_it(self):
        t = self.make()
        r = store.update_ticket(t["id"], "admin@t.local", status="resolved", resolution="Fixed in 1.2", engine=self.engine, now=NOW)
        self.assertEqual(r["resolution"], "Fixed in 1.2")
        self.assertIsNotNone(r["resolved_at"])
        r = store.update_ticket(t["id"], "admin@t.local", status="open", engine=self.engine, now=NOW)
        self.assertIsNone(r["resolved_at"])

    def test_assignment_and_unassignment(self):
        t = self.make()
        r = store.update_ticket(t["id"], "admin@t.local", assignee_email="Tech@T.local", engine=self.engine)
        self.assertEqual(r["assignee_email"], "tech@t.local")
        r = store.update_ticket(t["id"], "admin@t.local", clear_assignee=True, engine=self.engine)
        self.assertIsNone(r["assignee_email"])

    def test_summary_counts_open_unassigned_and_urgent(self):
        a = self.make(severity="urgent")
        self.make()
        done = self.make()
        store.update_ticket(a["id"], "admin@t.local", assignee_email="x@t.local", engine=self.engine)
        store.update_ticket(done["id"], "admin@t.local", status="closed", engine=self.engine)
        s = store.summary(engine=self.engine)
        self.assertEqual((s["total"], s["open"], s["unassigned_open"], s["urgent_open"]), (3, 2, 1, 1))

    def test_unknown_ticket_raises(self):
        with self.assertRaises(KeyError):
            store.add_comment(999, "a@t.local", "x", engine=self.engine)
        with self.assertRaises(KeyError):
            store.update_ticket(999, "a@t.local", status="closed", engine=self.engine)


PW = "test-password-123"
ADMIN, U1, U2 = "admin@t.local", "u1@t.local", "u2@t.local"


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.patches = [
            patch.object(db_module, "get_engine", return_value=self.engine),
            patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
        ]
        for p in self.patches:
            p.start()
        auth_users.create_user(ADMIN, PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user(U1, PW, "User One", role="user", engine=self.engine)
        auth_users.create_user(U2, PW, "User Two", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        r = self.client.post("/api/auth/login", json={"email": email, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)

    def open_ticket(self, **over):
        body = {"kind": "bug", "subject": "It broke", "description": "details", "severity": "normal"}
        body.update(over)
        return self.client.post("/api/support/tickets", json=body)

    def test_every_route_refuses_anonymous_callers(self):
        self.assertEqual(self.client.get("/api/support/tickets").status_code, 401)
        self.assertEqual(self.open_ticket().status_code, 401)
        self.assertEqual(self.client.get("/api/support/tickets/TKT-1").status_code, 401)

    def test_user_opens_a_ticket_and_sees_only_their_own(self):
        self.login(U1)
        t = self.open_ticket().json()
        self.login(U2)
        self.open_ticket(subject="Mine")
        listing = self.client.get("/api/support/tickets").json()
        self.assertFalse(listing["is_admin"])
        self.assertEqual([x["subject"] for x in listing["tickets"]], ["Mine"])
        self.assertNotIn("summary", listing)
        # another user's ticket is a 404, not a 403: ticket numbers can't be probed
        self.assertEqual(self.client.get(f"/api/support/tickets/{t['ref']}").status_code, 404)

    def test_admin_sees_everything_with_a_summary(self):
        self.login(U1)
        self.open_ticket()
        self.login(ADMIN)
        listing = self.client.get("/api/support/tickets").json()
        self.assertTrue(listing["is_admin"])
        self.assertEqual(listing["summary"]["open"], 1)
        self.assertFalse(listing["escalation_configured"])

    def test_internal_notes_never_reach_the_requester(self):
        self.login(U1)
        ref = self.open_ticket().json()["ref"]
        self.login(ADMIN)
        self.client.post(f"/api/support/tickets/{ref}/comments", json={"body": "reply to user"})
        self.client.post(f"/api/support/tickets/{ref}/comments", json={"body": "secret", "internal": True})
        self.assertEqual(len(self.client.get(f"/api/support/tickets/{ref}").json()["comments"]), 2)
        self.login(U1)
        bodies = [c["body"] for c in self.client.get(f"/api/support/tickets/{ref}").json()["comments"]]
        self.assertEqual(bodies, ["reply to user"])
        # a requester cannot mark their own comment internal
        r = self.client.post(f"/api/support/tickets/{ref}/comments", json={"body": "me", "internal": True})
        self.assertFalse(r.json()["comments"][-1]["internal"])

    def test_triage_is_admin_only(self):
        self.login(U1)
        ref = self.open_ticket().json()["ref"]
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/update", json={"status": "closed"}).status_code, 403)
        self.login(ADMIN)
        r = self.client.post(f"/api/support/tickets/{ref}/update", json={"status": "in_progress", "assignee_email": ADMIN})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "in_progress")
        self.assertEqual(r.json()["assignee_email"], ADMIN)
        bad = self.client.post(f"/api/support/tickets/{ref}/update", json={"status": "bogus"})
        self.assertEqual(bad.status_code, 400)

    def test_validation_errors_are_400s(self):
        self.login(U1)
        self.assertEqual(self.open_ticket(kind="nope").status_code, 400)
        self.assertEqual(self.open_ticket(subject="").status_code, 400)
        self.assertEqual(self.client.get("/api/support/tickets/not-a-ref").status_code, 400)

    def test_escalation_previews_by_default_and_never_sends_without_config(self):
        self.login(U1)
        ref = self.open_ticket(description="internal host db01").json()["ref"]
        self.assertEqual(self.client.post(f"/api/support/tickets/{ref}/escalate", json={"confirm": False}).status_code, 403)
        self.login(ADMIN)
        with patch.dict(os.environ, {"QUANTA_SUPPORT_EMAIL": "support@example.test"}), \
                patch.object(dashboard_app_module.email_sender, "is_configured", return_value=False), \
                patch.object(dashboard_app_module.email_sender, "send_email") as send:
            preview = self.client.post(f"/api/support/tickets/{ref}/escalate", json={"confirm": False}).json()
            self.assertTrue(preview["preview_only"])
            self.assertEqual(preview["to"], "support@example.test")
            self.assertFalse(preview["configured"])
            r = self.client.post(f"/api/support/tickets/{ref}/escalate", json={"confirm": True})
            self.assertEqual(r.status_code, 400)
            send.assert_not_called()

    def test_confirmed_escalation_sends_public_content_only(self):
        self.login(U1)
        ref = self.open_ticket().json()["ref"]
        self.login(ADMIN)
        self.client.post(f"/api/support/tickets/{ref}/comments", json={"body": "private note", "internal": True})
        with patch.dict(os.environ, {"QUANTA_SUPPORT_EMAIL": "support@example.test"}), \
                patch.object(dashboard_app_module.email_sender, "is_configured", return_value=True), \
                patch.object(dashboard_app_module.email_sender, "send_email") as send:
            r = self.client.post(f"/api/support/tickets/{ref}/escalate", json={"confirm": True})
            self.assertEqual(r.status_code, 200, r.text)
            to, subject, text = send.call_args[0][:3]
            self.assertEqual(to, ["support@example.test"])
            self.assertIn(ref, subject)
            self.assertNotIn("private note", text)


if __name__ == "__main__":
    unittest.main()
