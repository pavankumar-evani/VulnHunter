"""
API tests for the ownership & assignment routes (dashboard/app.py, "ownership &
assignment (ITSM layer)"): finding assignment, team records, the work queue, and the
analytics endpoint - including the access rules (who may assign to whom, 404-not-403
for out-of-scope findings) and the team-routing effect on what each user can see.

Uses a small, fixed, fake queue (never the real ~9,400-finding dataset) and a temporary
on-disk SQLite file, so it is fast, deterministic, and never touches real data. Same
harness pattern as tests/test_dashboard.py (TestClient, patched db_module.get_engine,
generous rate limiters).
"""
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
import data as dashboard_data  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.assignments import store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
ADMIN, ALPHA1, ALPHA2, BETA1, SOLO = (
    "admin@t.local", "alpha1@t.local", "alpha2@t.local", "beta1@t.local", "solo@t.local")


def _finding(fid, asset, prio="High", breached=False):
    return {"id": fid, "title": f"Title {fid}", "priority": prio, "severity": prio,
            "asset": {"name": asset}, "cve": None, "first_seen": "2026-08-01", "score": 5,
            "sla": {"breached": breached, "days_remaining": -3 if breached else 20, "due_date": "2026-08-20"}}


def _fake_queue():
    # F-1/F-2 belong to Alpha's assets, F-3 to Beta's, F-4's asset has no team.
    return [_finding("F-1", "a1", "Critical", True), _finding("F-2", "a2"),
            _finding("F-3", "a3", "Medium"), _finding("F-4", "a4", "Critical")]


ASSET_TEAMS = {"a1": "Alpha", "a2": "Alpha", "a3": "Beta", "a4": None}


class AssignmentApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.patches = [
            patch.object(db_module, "get_engine", return_value=self.engine),
            patch.object(dashboard_data, "load_live_queue", side_effect=_fake_queue),
            patch.object(dashboard_app_module, "_team_by_asset_name", return_value=ASSET_TEAMS),
            patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
        ]
        for p in self.patches:
            p.start()
        auth_users.create_user(ADMIN, PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user(ALPHA1, PW, "Alpha One", role="user", team="Alpha", engine=self.engine)
        auth_users.create_user(ALPHA2, PW, "Alpha Two", role="user", team="Alpha", engine=self.engine)
        auth_users.create_user(BETA1, PW, "Beta One", role="user", team="Beta", engine=self.engine)
        auth_users.create_user(SOLO, PW, "Solo", role="user", engine=self.engine)
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

    def assign(self, fid, **body):
        return self.client.post(f"/api/findings/{fid}/assign", json=body)

    # ------------------------------------------------------------------ access

    def test_every_new_read_route_refuses_anonymous_callers(self):
        for path in ("/api/teams", "/api/assignable-users", "/api/assignments", "/api/analytics/ownership",
                     "/api/findings/F-1/assignment"):
            self.assertEqual(self.client.get(path).status_code, 401, path)

    def test_mutations_refuse_anonymous_callers(self):
        self.assertEqual(self.assign("F-1", assignee_email=ALPHA1).status_code, 401)

    def test_admin_only_routes_refuse_a_plain_user(self):
        self.login(ALPHA1)
        self.assertEqual(self.client.post("/api/admin/teams", json={"name": "X"}).status_code, 403)
        self.assertEqual(self.client.delete("/api/findings/F-1/assignment").status_code, 403)
        self.assertEqual(self.client.post("/api/assignments/bulk", json={"finding_ids": ["F-1"], "team": "Alpha"}).status_code, 403)
        self.assertEqual(self.client.post("/api/assignments/auto-assign", json={}).status_code, 403)

    # -------------------------------------------------------------- assigning

    def test_admin_assigns_and_the_assignee_inherits_their_team(self):
        self.login(ADMIN)
        r = self.assign("F-3", assignee_email=ALPHA1)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["assignee_name"], r.json()["assigned_team"], r.json()["status"]),
                         ("Alpha One", "Alpha", "open"))

    def test_assignment_detail_includes_history(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1, notes="Please prioritize")
        detail = self.client.get("/api/findings/F-1/assignment").json()
        self.assertEqual(detail["ownership_state"], "assigned")
        self.assertEqual(detail["history"][0]["action"], "finding.assign")
        self.assertEqual(detail["history"][0]["actor"], ADMIN)

    def test_unknown_assignee_and_unknown_team_are_rejected(self):
        self.login(ADMIN)
        self.assertEqual(self.assign("F-1", assignee_email="ghost@t.local").status_code, 400)
        self.assertEqual(self.assign("F-1", team="Nonexistent").status_code, 400)

    def test_assigning_nobody_is_rejected(self):
        self.login(ADMIN)
        self.assertEqual(self.assign("F-1").status_code, 400)

    def test_team_name_is_matched_case_insensitively_to_the_catalog_spelling(self):
        self.login(ADMIN)
        self.assertEqual(self.assign("F-1", team="alpha").json()["assigned_team"], "Alpha")

    def test_team_member_can_self_assign_and_assign_a_teammate(self):
        self.login(ALPHA1)
        self.assertEqual(self.assign("F-1", assignee_email=ALPHA1).status_code, 200)
        self.assertEqual(self.assign("F-2", assignee_email=ALPHA2).status_code, 200)

    def test_team_member_cannot_assign_outside_their_team(self):
        self.login(ALPHA1)
        self.assertEqual(self.assign("F-1", assignee_email=BETA1).status_code, 403)
        self.assertEqual(self.assign("F-1", team="Beta").status_code, 403)

    def test_member_without_a_team_can_only_assign_to_themselves(self):
        self.login(SOLO)
        # Solo has no team, so (per the project's scoping convention) sees everything.
        self.assertEqual(self.assign("F-4", assignee_email=SOLO).status_code, 200)
        self.assertEqual(self.assign("F-4", assignee_email=ALPHA1).status_code, 403)

    def test_out_of_scope_finding_is_a_404_not_a_403(self):
        self.login(ALPHA1)
        self.assertEqual(self.assign("F-3", assignee_email=ALPHA1).status_code, 404)  # Beta's finding
        self.assertEqual(self.client.get("/api/findings/F-3/assignment").status_code, 404)
        self.assertEqual(self.assign("F-999", assignee_email=ALPHA1).status_code, 404)

    # ------------------------------------------------- routing changes visibility

    def test_assigning_to_another_team_moves_the_finding_into_that_teams_view(self):
        self.login(BETA1)
        self.assertEqual(self.client.get("/api/findings/F-1/assignment").status_code, 404)
        self.login(ADMIN)
        self.assign("F-1", team="Beta")
        self.login(BETA1)
        self.assertEqual(self.client.get("/api/findings/F-1/assignment").status_code, 200)
        self.login(ALPHA1)
        self.assertEqual(self.client.get("/api/findings/F-1/assignment").status_code, 404)

    def test_queue_attaches_assignment_for_logged_in_viewers_only(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1)
        rows = {f["id"]: f for f in self.client.get("/api/queue").json()["findings"]}
        self.assertEqual(rows["F-1"]["assignment"]["assignee_email"], ALPHA1)
        self.assertIsNone(rows["F-2"]["assignment"])
        self.client.cookies.clear()
        anon = {f["id"]: f for f in self.client.get("/api/queue").json()["findings"]}
        self.assertNotIn("assignment", anon["F-1"])  # never leak assignee identity to anonymous reads

    # ----------------------------------------------------------------- status

    def test_assignee_updates_status_and_others_cannot(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1)
        self.login(ALPHA1)
        ok = self.client.post("/api/findings/F-1/assignment/status", json={"status": "in_progress"})
        self.assertEqual((ok.status_code, ok.json()["status"]), (200, "in_progress"))
        self.login(ALPHA2)
        self.assertEqual(self.client.post("/api/findings/F-1/assignment/status", json={"status": "blocked"}).status_code, 403)

    def test_team_manager_may_update_status(self):
        self.login(ADMIN)
        self.client.post("/api/admin/teams", json={"name": "Alpha", "manager_email": ALPHA2})
        self.assign("F-1", assignee_email=ALPHA1)
        self.login(ALPHA2)
        self.assertEqual(self.client.post("/api/findings/F-1/assignment/status", json={"status": "blocked"}).status_code, 200)

    def test_status_validation_and_unassigned_findings(self):
        self.login(ADMIN)
        self.assertEqual(self.client.post("/api/findings/F-1/assignment/status", json={"status": "open"}).status_code, 404)
        self.assign("F-1", assignee_email=ALPHA1)
        self.assertEqual(self.client.post("/api/findings/F-1/assignment/status", json={"status": "done"}).status_code, 400)

    def test_unassign_is_admin_only_and_audited(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1)
        self.assertEqual(self.client.delete("/api/findings/F-1/assignment").status_code, 200)
        self.assertEqual(self.client.delete("/api/findings/F-1/assignment").status_code, 404)
        self.assertEqual(self.client.get("/api/findings/F-1/assignment").json()["history"][0]["action"], "finding.unassign")

    # ------------------------------------------------------------------- bulk

    def test_bulk_assign(self):
        self.login(ADMIN)
        r = self.client.post("/api/assignments/bulk", json={"finding_ids": ["F-1", "F-2"], "assignee_email": ALPHA1})
        self.assertEqual(r.json(), {"assigned": 2})
        self.assertEqual(len(store.load_assignments(self.engine)), 2)

    def test_bulk_assign_rejects_empty_unknown_and_oversized_requests(self):
        self.login(ADMIN)
        post = lambda ids: self.client.post("/api/assignments/bulk", json={"finding_ids": ids, "team": "Alpha"})  # noqa: E731
        self.assertEqual(post([]).status_code, 400)
        self.assertEqual(post(["F-1", "NOPE"]).status_code, 400)
        self.assertEqual(post([f"F-{i}" for i in range(dashboard_app_module.MAX_BULK_ASSIGN + 1)]).status_code, 400)
        self.assertEqual(store.load_assignments(self.engine), [])

    def test_auto_assign_previews_then_applies_only_to_gaps(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1)  # already assigned: must not be touched
        preview = self.client.post("/api/assignments/auto-assign", json={}).json()
        self.assertEqual(preview, {"would_assign": 2, "skipped_no_team": 1, "already_assigned": 1, "dry_run": True})
        self.assertEqual(len(store.load_assignments(self.engine)), 1)
        applied = self.client.post("/api/assignments/auto-assign", json={"confirm": True}).json()
        self.assertEqual(applied["assigned"], 2)
        rows = store.assignments_by_finding(self.engine)
        self.assertEqual((rows["F-2"]["assigned_team"], rows["F-3"]["assigned_team"]), ("Alpha", "Beta"))
        self.assertNotIn("F-4", rows)

    # ------------------------------------------------------------------ teams

    def test_team_crud(self):
        self.login(ADMIN)
        created = self.client.post("/api/admin/teams", json={"name": "Platform", "description": "Core", "manager_email": ALPHA1})
        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual(self.client.post("/api/admin/teams", json={"name": "platform"}).status_code, 400)  # duplicate
        self.assertEqual(self.client.post("/api/admin/teams", json={"name": "X", "manager_email": "ghost@t.local"}).status_code, 400)
        updated = self.client.put("/api/admin/teams/Platform", json={"description": "Changed", "manager_email": ALPHA2})
        self.assertEqual(updated.json()["manager_email"], ALPHA2)
        self.assertEqual(self.client.put("/api/admin/teams/Nope", json={}).status_code, 404)
        self.assertEqual(self.client.delete("/api/admin/teams/Platform").status_code, 200)

    def test_cannot_delete_a_team_that_still_has_members(self):
        self.login(ADMIN)
        self.client.post("/api/admin/teams", json={"name": "Alpha"})   # formalize the implied team
        self.assertEqual(self.client.delete("/api/admin/teams/Alpha").status_code, 409)

    def test_team_listing_merges_implied_teams_and_counts_members(self):
        self.login(ADMIN)
        teams = {t["name"]: t for t in self.client.get("/api/teams").json()["teams"]}
        self.assertEqual((teams["Alpha"]["members"], teams["Alpha"]["explicit"]), (2, False))
        self.assertEqual(teams["Beta"]["members"], 1)

    def test_a_team_member_only_sees_their_own_team_in_listings(self):
        self.login(ALPHA1)
        self.assertEqual([t["name"] for t in self.client.get("/api/teams").json()["teams"]], ["Alpha"])
        emails = {u["email"] for u in self.client.get("/api/assignable-users").json()["users"]}
        self.assertEqual(emails, {ALPHA1, ALPHA2})

    def test_admin_assignable_users_is_everyone(self):
        self.login(ADMIN)
        self.assertEqual(len(self.client.get("/api/assignable-users").json()["users"]), 5)

    # ------------------------------------------------------- work queue + analytics

    def test_work_queue_views_and_counts(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1)
        self.login(ALPHA1)
        mine = self.client.get("/api/assignments?view=mine").json()
        self.assertEqual([r["id"] for r in mine["rows"]], ["F-1"])
        team = self.client.get("/api/assignments?view=team").json()
        self.assertEqual({r["id"] for r in team["rows"]}, {"F-1", "F-2"})   # scoped to Alpha's two
        self.assertEqual(team["counts"]["needs_owner"], 1)                    # F-2 has a team, no person
        self.assertEqual(self.client.get("/api/assignments?view=bogus").status_code, 400)

    def test_work_queue_hides_resolved_unless_asked(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1)
        self.login(ALPHA1)
        self.client.post("/api/findings/F-1/assignment/status", json={"status": "resolved"})
        self.assertEqual(self.client.get("/api/assignments?view=mine").json()["total"], 0)
        self.assertEqual(self.client.get("/api/assignments?view=mine&include_resolved=true").json()["total"], 1)

    def test_work_queue_sorts_breached_critical_first_and_truncates(self):
        self.login(ADMIN)
        data = self.client.get("/api/assignments?view=all&limit=2").json()
        self.assertEqual([r["id"] for r in data["rows"]], ["F-1", "F-4"])
        self.assertTrue(data["truncated"])
        self.assertEqual(data["total"], 4)

    def test_analytics_for_an_admin_covers_everything(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1)
        out = self.client.get("/api/analytics/ownership").json()
        self.assertEqual((out["totals"]["open"], out["totals"]["assigned"], out["totals"]["unowned"]), (4, 1, 1))
        team_names = {t["name"] for t in out["by_team"]}
        self.assertTrue({"Alpha", "Beta", "(no team)"} <= team_names)
        self.assertEqual(out["unowned_urgent"][0]["id"], "F-4")

    def test_analytics_for_a_team_member_is_scoped_to_their_team(self):
        self.login(ADMIN)
        self.assign("F-1", assignee_email=ALPHA1)
        self.login(ALPHA2)
        out = self.client.get("/api/analytics/ownership").json()
        self.assertEqual(out["totals"]["open"], 2)
        self.assertEqual({t["name"] for t in out["by_team"]}, {"Alpha"})
        self.assertEqual({u["email"] for u in out["by_user"]}, {ALPHA1, ALPHA2})


if __name__ == "__main__":
    unittest.main()
