"""Integrity self-heal: each action in dry run and confirmed, audit trail, and that nothing is deleted."""
import datetime
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, insert, text

from remediation.audit import activity_log
from remediation.integrity import heal, service
from remediation.utils import db as db_module
from remediation.utils import file_lock

NOW = datetime.datetime(2026, 10, 6, 12, 0, tzinfo=datetime.timezone.utc)


class HealBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.out = self.root / "remediation" / "output"
        self.out.mkdir(parents=True)
        self.engine = create_engine(f"sqlite:///{self.root / 'q.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        os.environ.pop("QUANTA_FILES_BACKEND", None)
        self.engine.dispose()
        self.tmp.cleanup()

    def run_heal(self, names, confirm):
        return heal.run(actions=names, confirm=confirm, actor="admin@x", engine=self.engine, root=self.root, now=NOW)

    def audit(self, action=None):
        return activity_log.list_activity(engine=self.engine, action=action)


class StaleLockTests(HealBase):
    def setUp(self):
        super().setUp()
        self.dead = self.out / "a.json.lock"
        self.dead.write_text(f"99999999 {file_lock._HOSTNAME} tok\n", encoding="utf-8")
        self.live = self.out / "b.json.lock"
        self.live.write_text(f"{os.getpid()} {file_lock._HOSTNAME} tok\n", encoding="utf-8")

    def test_dry_run_changes_nothing_and_logs_nothing(self):
        r = self.run_heal(["remove_stale_locks"], False)
        self.assertTrue(r["preview"])
        self.assertEqual(r["results"][0]["status"], "would run")
        self.assertTrue(self.dead.exists())
        self.assertEqual(self.audit("integrity.heal.remove_stale_locks"), [])

    def test_confirmed_removes_only_the_dead_owners_lock_and_audits(self):
        r = self.run_heal(["remove_stale_locks"], True)
        self.assertEqual(r["results"][0]["status"], "done")
        self.assertFalse(self.dead.exists())
        self.assertTrue(self.live.exists())
        entry = self.audit("integrity.heal.remove_stale_locks")[0]
        self.assertEqual(entry["actor"], "admin@x")
        self.assertEqual(entry["details"]["result"]["removed"][0]["path"], "remediation/output/a.json.lock")

    def test_nothing_to_do_is_reported_and_not_logged(self):
        self.dead.unlink()
        r = self.run_heal(["remove_stale_locks"], True)
        self.assertEqual(r["results"][0]["status"], "nothing to do")
        self.assertEqual(self.audit("integrity.heal.remove_stale_locks"), [])


class FindingsRestoreTests(HealBase):
    def setUp(self):
        super().setUp()
        self.f = self.out / "normalized-findings.json"
        self.bak = self.out / "normalized-findings.json.bak"
        self.bak.write_text(json.dumps([{"id": "F1"}, {"id": "F2"}]), encoding="utf-8")

    def test_dry_run_leaves_the_corrupt_file_alone(self):
        self.f.write_text('[{"id": "F1"', encoding="utf-8")
        r = self.run_heal(["restore_findings_from_bak"], False)
        self.assertEqual(r["results"][0]["planned"][0]["findings_in_bak"], 2)
        self.assertEqual(self.f.read_text(encoding="utf-8"), '[{"id": "F1"')

    def test_confirmed_restores_and_keeps_the_bad_copy(self):
        self.f.write_text('[{"id": "F1"', encoding="utf-8")
        r = self.run_heal(["restore_findings_from_bak"], True)
        self.assertEqual(len(json.loads(self.f.read_text(encoding="utf-8"))), 2)
        kept = r["results"][0]["done"]["restored"][0]["bad_copy_kept_as"]
        self.assertEqual((self.out / kept).read_text(encoding="utf-8"), '[{"id": "F1"')
        self.assertTrue(self.bak.exists())
        self.assertTrue(self.audit("integrity.heal.restore_findings_from_bak"))

    def test_valid_primary_is_never_touched(self):
        self.f.write_text(json.dumps([{"id": "NEW"}]), encoding="utf-8")
        r = self.run_heal(["restore_findings_from_bak"], True)
        self.assertEqual(r["results"][0]["status"], "nothing to do")
        self.assertEqual(json.loads(self.f.read_text(encoding="utf-8")), [{"id": "NEW"}])

    def test_invalid_bak_means_no_restore_and_a_manual_step(self):
        self.f.write_text("garbage", encoding="utf-8")
        self.bak.write_text("also garbage", encoding="utf-8")
        r = self.run_heal(["restore_findings_from_bak"], True)
        self.assertEqual(r["results"][0]["status"], "nothing to do")
        self.assertEqual(self.f.read_text(encoding="utf-8"), "garbage")
        self.assertTrue(any(m["id"] == "findings_file" for m in r["manual"]))


class MissingTableTests(HealBase):
    def test_dry_run_then_confirmed_recreates_without_touching_rows(self):
        activity_log.record_activity("someone", "keep.me", engine=self.engine)
        with self.engine.begin() as conn:
            conn.execute(text("DROP TABLE teams"))
        r = self.run_heal(["recreate_missing_tables"], False)
        self.assertIn({"table": "teams"}, r["results"][0]["planned"])
        self.assertNotIn("teams", __import__("sqlalchemy").inspect(self.engine).get_table_names())
        r = self.run_heal(["recreate_missing_tables"], True)
        self.assertEqual(r["results"][0]["status"], "done")
        self.assertIn("teams", __import__("sqlalchemy").inspect(self.engine).get_table_names())
        self.assertTrue(self.audit("keep.me"))                   # existing rows survive
        self.assertTrue(self.audit("integrity.heal.recreate_missing_tables"))


class SnapshotTests(HealBase):
    def setUp(self):
        super().setUp()
        cfg = self.root / "remediation" / "config"
        cfg.mkdir(parents=True)
        self.a = cfg / "a.yaml"
        self.b = cfg / "b.yaml"
        self.a.write_text("a: local\n", encoding="utf-8")
        self.b.write_text("b: 1\n", encoding="utf-8")
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.file_snapshots).values(path="remediation/config/a.yaml", content="a: db\n", sha="x", version=3, deleted=False, updated_at=1.0))
        os.environ["QUANTA_FILES_BACKEND"] = "db"

    def test_dry_run_changes_nothing(self):
        r = self.run_heal(["rebuild_file_snapshots"], False)
        self.assertEqual(len(r["results"][0]["planned"]), 2)
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(text("SELECT COUNT(*) FROM file_snapshots")).scalar(), 1)
        self.assertEqual(sorted(p.name for p in self.a.parent.iterdir()), ["a.yaml", "b.yaml"])

    def test_confirmed_seeds_missing_and_keeps_local_copy_of_divergent(self):
        r = self.run_heal(["rebuild_file_snapshots"], True)
        done = r["results"][0]["done"]
        self.assertEqual(done["seeded"], ["remediation/config/b.yaml"])
        kept = done["local_copies_kept"][0]["kept_as"]
        self.assertEqual((self.a.parent / kept).read_text(encoding="utf-8"), "a: local\n")
        self.assertEqual(self.a.read_text(encoding="utf-8"), "a: local\n")      # nothing overwritten here
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(text("SELECT content FROM file_snapshots WHERE path = 'remediation/config/a.yaml'")).scalar(), "a: db\n")
            self.assertEqual(conn.execute(text("SELECT COUNT(*) FROM file_snapshots")).scalar(), 2)
        self.assertTrue(self.audit("integrity.heal.rebuild_file_snapshots"))

    def test_nothing_to_do_when_the_backend_is_off(self):
        os.environ.pop("QUANTA_FILES_BACKEND")
        self.assertEqual(self.run_heal(["rebuild_file_snapshots"], True)["results"][0]["status"], "nothing to do")


class GeneralTests(HealBase):
    def test_unknown_actions_are_reported_not_run(self):
        r = self.run_heal(["format_disk"], True)
        self.assertEqual(r["unknown"], ["format_disk"])
        self.assertEqual(r["results"], [])

    def test_no_findings_or_customer_rows_are_deleted_by_a_full_confirmed_run(self):
        (self.out / "normalized-findings.json").write_text(json.dumps([{"id": "F1"}]), encoding="utf-8")
        (self.out / "x.lock").write_text(f"99999999 {file_lock._HOSTNAME} t\n", encoding="utf-8")
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.finding_assignments).values(finding_id="ORPHAN", assignee_email="a@x", status="open", assigned_by="b", assigned_at="t", updated_at="t"))
        self.run_heal(None, True)
        self.assertEqual(json.loads((self.out / "normalized-findings.json").read_text()), [{"id": "F1"}])
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(text("SELECT COUNT(*) FROM finding_assignments")).scalar(), 1)   # orphans are reported, never deleted

    def test_orphans_appear_as_manual_steps(self):
        (self.out / "normalized-findings.json").write_text(json.dumps([{"id": "F1"}]), encoding="utf-8")
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.finding_assignments).values(finding_id="ORPHAN", assignee_email="a@x", status="open", assigned_by="b", assigned_at="t", updated_at="t"))
        r = self.run_heal(None, False)
        self.assertTrue(any(m["id"] == "orphan_assignments" for m in r["manual"]))


class AlertTests(HealBase):
    def test_alert_once_per_distinct_problem_set_and_recovery(self):
        sent = []
        bad = {"status": "warn", "checked_at": "t", "counts": {}, "code_state": None, "problems": ["Lock files"]}
        self.assertEqual(service.alert_if_new(bad, engine=self.engine, send=lambda s, b: sent.append(s)), "alert")
        self.assertIsNone(service.alert_if_new(bad, engine=self.engine, send=lambda s, b: sent.append(s)))
        worse = {**bad, "problems": ["Lock files", "Disk space"]}
        self.assertEqual(service.alert_if_new(worse, engine=self.engine, send=lambda s, b: sent.append(s)), "alert")
        self.assertEqual(len(sent), 2)
        good = {**bad, "problems": [], "status": "ok"}
        self.assertEqual(service.alert_if_new(good, engine=self.engine), "recovered")
        self.assertIsNone(service.alert_if_new(good, engine=self.engine))
        self.assertEqual(service.alert_if_new(bad, engine=self.engine), "alert")    # a recurrence alerts again

    def test_tick_is_off_with_the_env_switch_and_throttled_to_the_hour(self):
        os.environ["QUANTA_INTEGRITY_CHECKS"] = "false"
        try:
            self.assertIsNone(service.run_tick(engine=self.engine, root=self.root, force=True))
        finally:
            os.environ.pop("QUANTA_INTEGRITY_CHECKS")
        first = service.run_tick(engine=self.engine, root=self.root, force=True)
        self.assertIn("status", first)
        self.assertIsNone(service.run_tick(engine=self.engine, root=self.root))


if __name__ == "__main__":
    unittest.main()
