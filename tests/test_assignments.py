"""
Tests for remediation/assignments - finding assignment, team records, auto-routing,
and ownership analytics. Every test uses a fresh in-memory SQLite engine (never the
real, shared remediation/quanta.db), same pattern as test_remediation_approvals.py.
"""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.assignments import analytics, store  # noqa: E402
from remediation.audit.activity_log import list_activity  # noqa: E402

NOW = datetime.datetime(2026, 9, 10, 12, 0, tzinfo=datetime.timezone.utc)


class _EngineCase(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        self.lock = str(Path(tempfile.gettempdir()) / "vh-test-assignments.lock")

    def tearDown(self):
        self.engine.dispose()

    def assign(self, fid="FIND-1", actor="admin@x.com", **kw):
        kw.setdefault("assignee_email", "dev@x.com")
        return store.assign(fid, actor, engine=self.engine, now=NOW, lock_path=self.lock, **kw)


class Assign(_EngineCase):
    def test_assign_creates_an_open_record(self):
        rec = self.assign(team="Platform")
        self.assertEqual(rec["status"], "open")
        self.assertEqual(rec["assignee_email"], "dev@x.com")
        self.assertEqual(rec["assigned_team"], "Platform")
        self.assertEqual(store.get_assignment("FIND-1", self.engine)["assigned_by"], "admin@x.com")

    def test_email_is_normalized_to_lowercase(self):
        self.assertEqual(self.assign(assignee_email="  Dev@X.com ")["assignee_email"], "dev@x.com")

    def test_requires_a_person_or_a_team(self):
        with self.assertRaises(ValueError):
            store.assign("FIND-1", "a@x.com", engine=self.engine, lock_path=self.lock)

    def test_team_only_assignment_is_allowed(self):
        rec = store.assign("FIND-1", "a@x.com", team="SecOps", engine=self.engine, lock_path=self.lock)
        self.assertIsNone(rec["assignee_email"])
        self.assertEqual(rec["assigned_team"], "SecOps")

    def test_reassigning_to_same_person_keeps_status(self):
        self.assign()
        store.set_status("FIND-1", "in_progress", "dev@x.com", engine=self.engine, lock_path=self.lock)
        self.assertEqual(self.assign(team="Platform")["status"], "in_progress")

    def test_reassigning_to_a_new_person_resets_to_open(self):
        self.assign()
        store.set_status("FIND-1", "in_progress", "dev@x.com", engine=self.engine, lock_path=self.lock)
        self.assertEqual(self.assign(assignee_email="other@x.com")["status"], "open")

    def test_assigned_at_survives_reassignment(self):
        first = self.assign()
        later = store.assign("FIND-1", "a@x.com", assignee_email="other@x.com", engine=self.engine,
                             now=NOW + datetime.timedelta(days=2), lock_path=self.lock)
        self.assertEqual(later["assigned_at"], first["assigned_at"])
        self.assertNotEqual(later["updated_at"], first["updated_at"])

    def test_overlong_notes_rejected(self):
        with self.assertRaises(ValueError):
            self.assign(notes="x" * (store.MAX_NOTES + 1))


class Status(_EngineCase):
    def test_status_requires_an_existing_assignment(self):
        with self.assertRaises(KeyError):
            store.set_status("FIND-1", "blocked", "a@x.com", engine=self.engine, lock_path=self.lock)

    def test_invalid_status_rejected(self):
        self.assign()
        with self.assertRaises(ValueError):
            store.set_status("FIND-1", "done", "a@x.com", engine=self.engine, lock_path=self.lock)

    def test_status_change_is_recorded_in_history(self):
        self.assign()
        store.set_status("FIND-1", "blocked", "dev@x.com", notes="waiting on vendor patch",
                         engine=self.engine, lock_path=self.lock)
        history = store.assignment_history("FIND-1", self.engine)
        self.assertEqual([h["action"] for h in history], ["finding.status", "finding.assign"])
        self.assertEqual(history[0]["details"]["to"], "blocked")
        self.assertEqual(history[0]["details"]["notes"], "waiting on vendor patch")


class Unassign(_EngineCase):
    def test_unassign_removes_the_record_and_audits_it(self):
        self.assign()
        store.unassign("FIND-1", "admin@x.com", engine=self.engine, lock_path=self.lock)
        self.assertIsNone(store.get_assignment("FIND-1", self.engine))
        self.assertEqual(store.assignment_history("FIND-1", self.engine)[0]["action"], "finding.unassign")

    def test_unassigning_something_never_assigned_raises(self):
        with self.assertRaises(KeyError):
            store.unassign("FIND-9", "a@x.com", engine=self.engine, lock_path=self.lock)


class Bulk(_EngineCase):
    def test_bulk_assign_writes_every_finding_with_its_own_audit_row(self):
        n = store.bulk_assign(["F-1", "F-2", "F-2", "F-3"], "admin@x.com", assignee_email="dev@x.com",
                              engine=self.engine, now=NOW, lock_path=self.lock)
        self.assertEqual(n, 3)  # de-duplicated
        self.assertEqual(len(store.load_assignments(self.engine)), 3)
        self.assertEqual(len(store.assignment_history("F-2", self.engine)), 1)

    def test_bulk_assign_validates_before_writing_anything(self):
        with self.assertRaises(ValueError):
            store.bulk_assign(["F-1"], "a@x.com", engine=self.engine, lock_path=self.lock)
        self.assertEqual(store.load_assignments(self.engine), [])

    def test_bulk_assign_updates_existing_rows_in_the_same_call(self):
        self.assign("F-1")
        store.bulk_assign(["F-1", "F-2"], "admin@x.com", assignee_email="new@x.com",
                          engine=self.engine, now=NOW, lock_path=self.lock)
        rows = store.assignments_by_finding(self.engine)
        self.assertEqual(rows["F-1"]["assignee_email"], "new@x.com")
        self.assertEqual(rows["F-2"]["assignee_email"], "new@x.com")


class AutoAssign(_EngineCase):
    FINDINGS = [
        {"id": "F-1", "team": "Platform"},
        {"id": "F-2", "team": "Platform"},
        {"id": "F-3", "team": None},          # asset has no team: nothing honest to route to
        {"id": "F-4", "team": "SecOps"},      # already assigned below: never overwritten
    ]

    def test_dry_run_writes_nothing_and_reports_the_plan(self):
        store.assign("F-4", "a@x.com", assignee_email="dev@x.com", engine=self.engine, lock_path=self.lock)
        out = store.auto_assign_from_assets(self.FINDINGS, "admin@x.com", engine=self.engine, lock_path=self.lock)
        self.assertEqual(out, {"would_assign": 2, "skipped_no_team": 1, "already_assigned": 1, "dry_run": True})
        self.assertEqual(len(store.load_assignments(self.engine)), 1)

    def test_apply_routes_only_the_gaps_and_leaves_existing_assignments_alone(self):
        store.assign("F-4", "a@x.com", assignee_email="dev@x.com", team="Elsewhere",
                     engine=self.engine, lock_path=self.lock)
        out = store.auto_assign_from_assets(self.FINDINGS, "admin@x.com", engine=self.engine,
                                            now=NOW, lock_path=self.lock, dry_run=False)
        self.assertEqual(out["assigned"], 2)
        rows = store.assignments_by_finding(self.engine)
        self.assertEqual(rows["F-1"]["assigned_team"], "Platform")
        self.assertIsNone(rows["F-1"]["assignee_email"])
        self.assertNotIn("F-3", rows)
        self.assertEqual(rows["F-4"]["assigned_team"], "Elsewhere")
        # One summary audit row for the whole batch, not one per finding...
        self.assertEqual(store.assignment_history("F-1", self.engine), [])
        batch = [e for e in list_activity(engine=self.engine) if e["action"] == "finding.auto_assign"]
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0]["details"], {"count": 2, "by_team": {"Platform": 2}})
        # ...while the assignment record itself still says who/why.
        self.assertEqual(rows["F-1"]["assigned_by"], "admin@x.com")
        self.assertIn("Auto-routed", rows["F-1"]["notes"])


class Teams(_EngineCase):
    def test_create_and_list(self):
        t = store.create_team("Platform", "admin@x.com", description="Core", manager_email="Lead@X.com",
                              engine=self.engine, now=NOW, lock_path=self.lock)
        self.assertEqual(t["manager_email"], "lead@x.com")
        self.assertEqual([x["name"] for x in store.list_teams(engine=self.engine)], ["Platform"])

    def test_duplicate_name_is_case_insensitive(self):
        store.create_team("Platform", "a@x.com", engine=self.engine, lock_path=self.lock)
        with self.assertRaises(ValueError):
            store.create_team("platform", "a@x.com", engine=self.engine, lock_path=self.lock)

    def test_blank_and_overlong_names_rejected(self):
        for bad in ("", "   ", "x" * (store.MAX_TEAM_NAME + 1)):
            with self.assertRaises(ValueError):
                store.create_team(bad, "a@x.com", engine=self.engine, lock_path=self.lock)

    def test_implied_teams_from_users_and_assets_are_listed_as_not_explicit(self):
        store.create_team("Platform", "a@x.com", engine=self.engine, lock_path=self.lock)
        listed = store.list_teams(known_team_names=["platform", "Network Ops", None, ""], engine=self.engine)
        self.assertEqual([(t["name"], t["explicit"]) for t in listed], [("Network Ops", False), ("Platform", True)])

    def test_update_and_delete(self):
        store.create_team("Platform", "a@x.com", engine=self.engine, lock_path=self.lock)
        t = store.update_team("platform", "a@x.com", description="New", manager_email="m@x.com",
                              engine=self.engine, lock_path=self.lock)
        self.assertEqual(t["description"], "New")
        with self.assertRaises(ValueError):
            store.delete_team("Platform", "a@x.com", in_use_count=2, engine=self.engine, lock_path=self.lock)
        store.delete_team("Platform", "a@x.com", engine=self.engine, lock_path=self.lock)
        self.assertEqual(store.load_teams(self.engine), [])

    def test_missing_team_raises(self):
        with self.assertRaises(KeyError):
            store.update_team("Nope", "a@x.com", engine=self.engine, lock_path=self.lock)
        with self.assertRaises(KeyError):
            store.delete_team("Nope", "a@x.com", engine=self.engine, lock_path=self.lock)


AS_OF = datetime.date(2026, 9, 10)


def _f(fid, team=None, prio="High", breached=False, days_remaining=10, first_seen="2026-09-05"):
    return {"id": fid, "team": team, "priority": prio, "title": fid, "asset": {"name": f"a-{fid}"},
            "first_seen": first_seen, "score": 5,
            "sla": {"breached": breached, "days_remaining": days_remaining, "due_date": "2026-09-01"}}


def _a(fid, email=None, team=None, status="open"):
    return {"finding_id": fid, "assignee_email": email, "assigned_team": team, "status": status}


USERS = [{"email": "dev@x.com", "name": "Dev", "role": "user", "team": "Platform"},
         {"email": "idle@x.com", "name": "Idle", "role": "user", "team": "Platform"}]
TEAMS = [{"name": "Platform", "manager_email": "lead@x.com", "explicit": True}]


class Analytics(unittest.TestCase):
    def run_it(self, findings, assignments):
        return analytics.ownership_analytics(findings, assignments, USERS, TEAMS, as_of=AS_OF)

    def test_ownership_states(self):
        out = self.run_it(
            [_f("1", "Platform"), _f("2"), _f("3", "Platform")],
            [_a("1", "dev@x.com"), ],
        )
        t = out["totals"]
        self.assertEqual((t["assigned"], t["team_only"], t["unowned"], t["open"]), (1, 1, 1, 3))

    def test_assignment_team_overrides_the_asset_team(self):
        out = self.run_it([_f("1", "Platform")], [_a("1", team="SecOps")])
        names = {b["name"]: b["open"] for b in out["by_team"]}
        self.assertEqual(names.get("SecOps"), 1)
        self.assertEqual(names.get("Platform"), 0)

    def test_resolved_is_counted_but_leaves_the_live_workload(self):
        out = self.run_it([_f("1", breached=True, prio="Critical")], [_a("1", "dev@x.com", status="resolved")])
        self.assertEqual(out["totals"]["open"], 0)
        self.assertEqual(out["totals"]["resolved"], 1)
        self.assertEqual(out["totals"]["breached"], 0)
        self.assertEqual(out["status_counts"]["resolved"], 1)

    def test_sla_and_priority_rollups_per_user(self):
        out = self.run_it(
            [_f("1", prio="Critical", breached=True), _f("2", prio="High", days_remaining=2), _f("3", prio="Low")],
            [_a("1", "dev@x.com"), _a("2", "dev@x.com", status="in_progress"), _a("3", "dev@x.com", status="blocked")],
        )
        dev = next(u for u in out["by_user"] if u["email"] == "dev@x.com")
        self.assertEqual((dev["open"], dev["critical"], dev["high"], dev["breached"], dev["at_risk"]), (3, 1, 1, 1, 1))
        self.assertEqual((dev["in_progress"], dev["blocked"]), (1, 1))

    def test_users_with_no_work_still_appear_for_workload_balancing(self):
        out = self.run_it([_f("1")], [])
        idle = next(u for u in out["by_user"] if u["email"] == "idle@x.com")
        self.assertEqual(idle["open"], 0)

    def test_team_member_count(self):
        out = self.run_it([], [])
        self.assertEqual(next(b for b in out["by_team"] if b["name"] == "Platform")["members"], 2)

    def test_ageing_buckets_split_by_ownership_state(self):
        out = self.run_it(
            [_f("1", first_seen="2026-09-08"), _f("2", first_seen="2026-06-01", team="Platform"),
             _f("3", first_seen="2026-08-25")],
            [_a("1", "dev@x.com")],
        )
        by = {b["bucket"]: b for b in out["ageing"]}
        self.assertEqual(by["0-7 days"]["assigned"], 1)
        self.assertEqual(by["90+ days"]["team_only"], 1)
        self.assertEqual(by["8-30 days"]["unowned"], 1)

    def test_unowned_urgent_lists_breached_critical_first_and_excludes_owned(self):
        out = self.run_it(
            [_f("A", prio="High"), _f("B", prio="Critical", breached=True), _f("C", prio="Low"),
             _f("D", prio="Critical", team="Platform")],
            [],
        )
        self.assertEqual([x["id"] for x in out["unowned_urgent"]], ["B", "A"])
        self.assertEqual(out["unowned_urgent_total"], 2)

    def test_percentages_with_an_empty_queue_do_not_divide_by_zero(self):
        t = self.run_it([], [])["totals"]
        self.assertEqual((t["assigned_pct"], t["owned_pct"]), (0.0, 0.0))

    def test_unknown_assignee_still_gets_counted(self):
        out = self.run_it([_f("1")], [_a("1", "ghost@x.com")])
        self.assertTrue(any(u["email"] == "ghost@x.com" and u["open"] == 1 for u in out["by_user"]))


if __name__ == "__main__":
    unittest.main()
