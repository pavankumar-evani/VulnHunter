"""Integrity checks: schema, orphans, findings file, locks, snapshots, disk, clock, keys, licence."""
import collections
import datetime
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, insert, text

from remediation.integrity import checks
from remediation.utils import db as db_module

NOW = datetime.datetime(2026, 10, 6, 12, 0, tzinfo=datetime.timezone.utc)
Usage = collections.namedtuple("Usage", "total used free")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "remediation" / "output").mkdir(parents=True)
        self.engine = create_engine(f"sqlite:///{self.root / 'q.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def findings(self, ids, bak=False, raw=None):
        p = self.root / "remediation" / "output" / "normalized-findings.json"
        p.write_text(raw if raw is not None else json.dumps([{"id": i} for i in ids]), encoding="utf-8")
        if bak:
            p.with_name(p.name + ".bak").write_text(json.dumps([{"id": i} for i in ids]), encoding="utf-8")
        return p

    def by_id(self, results, cid):
        return next(c for c in results if c["id"] == cid)


class SchemaTests(Base):
    def test_clean_database_passes_database_tables_and_schema_checks(self):
        self.assertEqual(checks.check_database(self.engine)["level"], "ok")
        res = checks.check_schema(self.engine)
        self.assertEqual(self.by_id(res, "tables")["level"], "ok")
        self.assertEqual(self.by_id(res, "schema_version")["level"], "ok")

    def test_missing_table_fails_and_names_the_heal_action(self):
        with self.engine.begin() as conn:
            conn.execute(text("DROP TABLE teams"))
        c = self.by_id(checks.check_schema(self.engine), "tables")
        self.assertEqual(c["level"], "fail")
        self.assertEqual(c["fix"], "recreate_missing_tables")
        self.assertIn("teams", c["missing"])

    def test_pending_and_future_migrations_are_warned(self):
        with self.engine.begin() as conn:
            conn.execute(text("DELETE FROM schema_migrations WHERE version = 5"))
        c = self.by_id(checks.check_schema(self.engine), "schema_version")
        self.assertEqual(c["level"], "warn")
        self.assertIn("migrate", c["manual"])
        with self.engine.begin() as conn:
            conn.execute(text("INSERT INTO schema_migrations (version, name, applied_at) VALUES (5, 'x', 'x'), (999, 'future', 'x')"))
        c = self.by_id(checks.check_schema(self.engine), "schema_version")
        self.assertIn("newer release", c["detail"])

    def test_unreachable_database_is_a_failure(self):
        bad = create_engine("sqlite:///" + str(self.root / "no" / "such" / "dir" / "x.db"))
        self.assertEqual(checks.check_database(bad)["level"], "fail")


class FindingsFileTests(Base):
    def test_missing_file_is_info_not_ok(self):
        self.assertEqual(checks.check_findings_file(self.root)["level"], "info")

    def test_valid_with_and_without_bak(self):
        self.findings(["F1"], bak=False)
        self.assertEqual(checks.check_findings_file(self.root)["level"], "info")
        self.findings(["F1"], bak=True)
        self.assertEqual(checks.check_findings_file(self.root)["level"], "ok")

    def test_invalid_json_with_good_bak_is_fixable(self):
        self.findings(["F1"], bak=True)
        self.findings(None, raw='[{"id": "F1"')
        c = checks.check_findings_file(self.root)
        self.assertEqual((c["level"], c["fix"]), ("fail", "restore_findings_from_bak"))

    def test_invalid_json_without_bak_is_manual(self):
        self.findings(None, raw="not json")
        c = checks.check_findings_file(self.root)
        self.assertEqual(c["level"], "fail")
        self.assertIsNone(c["fix"])
        self.assertTrue(c["manual"])

    def test_wrong_shape_is_a_failure(self):
        self.findings(None, raw='{"a": 1}')
        self.assertEqual(checks.check_findings_file(self.root)["level"], "fail")


class OrphanTests(Base):
    def _assign(self, fid):
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.finding_assignments).values(finding_id=fid, assignee_email="a@x", assigned_team=None, status="open", notes=None,
                                                                      assigned_by="b@x", assigned_at="t", updated_at="t"))

    def _approval(self, aid, fid, status):
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.remediation_approvals).values(id=aid, finding_id=fid, requested_by="r@x", created_on="t", status=status))

    def test_orphan_assignment_detected_and_not_deleted(self):
        self.findings(["F1"])
        self._assign("F1")
        self._assign("GONE-9")
        res = checks.check_orphans(self.engine, self.root)
        c = self.by_id(res, "orphan_assignments")
        self.assertEqual(c["level"], "warn")
        self.assertEqual(c["items"], ["GONE-9"])
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(text("SELECT COUNT(*) FROM finding_assignments")).scalar(), 2)

    def test_approval_without_artifact_is_flagged_only_when_approved_or_triggered(self):
        self.findings(["F1", "F2", "F3"])
        (self.root / "remediation" / "output" / "F1-patch.yml").write_text("x", encoding="utf-8")
        self._approval("A1", "F1", "approved")
        self._approval("A2", "F2", "approved")
        self._approval("A3", "F3", "pending")
        c = self.by_id(checks.check_orphans(self.engine, self.root), "orphan_approvals")
        self.assertEqual(c["level"], "warn")
        self.assertEqual(c["items"], ["A2 (F2)"])

    def test_clean_references_are_ok(self):
        self.findings(["F1"])
        self._assign("F1")
        res = checks.check_orphans(self.engine, self.root)
        self.assertTrue(all(c["level"] == "ok" for c in res))

    def test_skipped_honestly_without_a_findings_file(self):
        res = checks.check_orphans(self.engine, self.root)
        self.assertEqual(res[0]["level"], "info")


class LockTests(Base):
    def _lock(self, name, content):
        p = self.root / "remediation" / "output" / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_dead_owner_is_stale_live_owner_is_held(self):
        from remediation.utils import file_lock
        dead = self._lock("a.json.lock", f"99999999 {file_lock._HOSTNAME} tok\n")
        live = self._lock("b.json.lock", f"{os.getpid()} {file_lock._HOSTNAME} tok\n")
        self.assertEqual(checks.lock_state(dead)[0], "stale")
        self.assertEqual(checks.lock_state(live)[0], "held")
        c = checks.check_locks(self.root)
        self.assertEqual(c["level"], "warn")
        self.assertEqual([i["path"] for i in c["items"]], ["remediation/output/a.json.lock"])
        self.assertEqual(c["fix"], "remove_stale_locks")

    def test_ownerless_lock_is_stale_only_when_old(self):
        p = self._lock("c.lock", "")
        self.assertEqual(checks.lock_state(p)[0], "held")
        old = time.time() - 4000
        os.utime(p, (old, old))
        self.assertEqual(checks.lock_state(p)[0], "stale")

    def test_no_locks_is_ok(self):
        self.assertEqual(checks.check_locks(self.root)["level"], "ok")


class HostChecksTests(Base):
    def test_disk_thresholds(self):
        gib = 2 ** 30
        self.assertEqual(checks.check_disk(self.engine, self.root, usage=lambda p: Usage(100 * gib, 10 * gib, 90 * gib))["level"], "ok")
        self.assertEqual(checks.check_disk(self.engine, self.root, usage=lambda p: Usage(100 * gib, 99 * gib, gib // 2))["level"], "warn")
        self.assertEqual(checks.check_disk(self.engine, self.root, usage=lambda p: Usage(100 * gib, 100 * gib, 10 * 2 ** 20))["level"], "fail")

    def test_clock_flags_future_dated_activity_on_sqlite(self):
        with self.engine.begin() as conn:
            conn.execute(text("INSERT INTO activity_log (actor, action, details, timestamp) VALUES ('a', 'x', '{}', :t)"), {"t": (NOW + datetime.timedelta(hours=3)).isoformat()})
        self.assertEqual(checks.check_clock(self.engine, NOW)["level"], "warn")

    def test_clock_on_sqlite_never_claims_a_measured_skew(self):
        c = checks.check_clock(self.engine, NOW)
        self.assertEqual(c["level"], "info")
        self.assertIn("cannot be measured", c["detail"])

    def test_api_key_expiry(self):
        def key(name, exp, revoked=None):
            with self.engine.begin() as conn:
                conn.execute(insert(db_module.api_keys).values(name=name, prefix=name, key_hash="h", scopes="x", created_at="t", expires_at=exp, revoked_at=revoked))
        key("old", (NOW - datetime.timedelta(days=2)).isoformat())
        key("soon", (NOW + datetime.timedelta(days=3)).isoformat())
        key("fine", (NOW + datetime.timedelta(days=300)).isoformat())
        key("revoked-old", (NOW - datetime.timedelta(days=9)).isoformat(), revoked="t")
        c = checks.check_api_keys(self.engine, NOW)
        self.assertEqual(c["level"], "warn")
        self.assertIn("old", c["detail"])
        self.assertIn("soon", c["detail"])
        self.assertNotIn("revoked-old", c["detail"])
        self.assertNotIn("fine", c["detail"])

    def test_licence_off_is_info_and_expired_enforced_is_fail(self):
        self.assertEqual(checks.check_licence(env={"QUANTA_LICENSE_MODE": "off"})["level"], "info")
        c = checks.check_licence(env={"QUANTA_LICENSE_MODE": "enforce"})   # enforced with no licence installed
        self.assertEqual(c["level"], "fail")
        c = checks.check_licence(env={"QUANTA_LICENSE_MODE": "warn"})
        self.assertEqual(c["level"], "warn")


class SnapshotTests(Base):
    def test_off_by_default_is_info(self):
        os.environ.pop("QUANTA_FILES_BACKEND", None)
        self.assertEqual(checks.check_snapshots(self.engine, self.root)["level"], "info")

    def test_divergence_and_missing_snapshots_warn(self):
        from remediation.utils import file_sync
        (self.root / "remediation" / "config").mkdir(parents=True)
        (self.root / "remediation" / "config" / "a.yaml").write_text("a: 1\n", encoding="utf-8")
        (self.root / "remediation" / "config" / "b.yaml").write_text("b: 1\n", encoding="utf-8")
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.file_snapshots).values(path="remediation/config/a.yaml", content="a: 2\n", sha="deadbeef", version=1, deleted=False, updated_at=1.0))
        os.environ["QUANTA_FILES_BACKEND"] = "db"
        try:
            c = checks.check_snapshots(self.engine, self.root)
        finally:
            os.environ.pop("QUANTA_FILES_BACKEND", None)
        self.assertEqual((c["level"], c["fix"]), ("warn", "rebuild_file_snapshots"))
        self.assertEqual(sorted(c["items"]), ["remediation/config/a.yaml", "remediation/config/b.yaml"])


class RunAllTests(Base):
    def test_summary_shape_and_status(self):
        self.findings(["F1"], bak=True)
        gib = 2 ** 30
        r = checks.run_all(self.engine, self.root, now=NOW, disk_usage=lambda p: Usage(100 * gib, 10 * gib, 90 * gib), env={"QUANTA_LICENSE_MODE": "off"})
        self.assertIn(r["status"], ("ok", "warn"))
        self.assertEqual(sum(r["counts"].values()), len(r["checks"]))
        self.assertEqual(r["checked_at"], "2026-10-06T12:00:00Z")

    def test_a_failing_check_makes_the_status_fail(self):
        self.findings(None, raw="garbage")
        r = checks.run_all(self.engine, self.root, now=NOW)
        self.assertEqual(r["status"], "fail")


if __name__ == "__main__":
    unittest.main()
