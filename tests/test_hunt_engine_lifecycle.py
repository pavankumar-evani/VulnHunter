"""Hunt engine: refresh idempotence, lifecycle, dismissal memory, learning loop, accept->hunt compatibility, promotion, migration."""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine, inspect  # noqa: E402

from remediation.hunting import store as hunt_store, usecase_store  # noqa: E402
from remediation.hunting.engine import context, service, store  # noqa: E402
from remediation.utils import db as db_module, migrations  # noqa: E402
from tests.test_hunt_engine_core import NOW, alert, ctx, fnd, T1059  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.e)
        self.findings = [fnd(1, host="WEB-1"), fnd(2, host="WEB-2", cve="CVE-2", tech=(T1059,))]

    def tearDown(self):
        self.e.dispose()
        self.tmp.cleanup()

    def refresh(self, findings=None, **kw):
        c = ctx(findings=findings if findings is not None else self.findings, **kw)
        return service.refresh(c.findings, self.e, now=NOW, ctx=c)

    def first(self, generator="kev-exposure"):
        return next(h for h in store.all_rows(self.e) if h["generator"] == generator)


class RefreshTests(Base):
    def test_refresh_is_idempotent_and_dedupes(self):
        r1 = self.refresh()
        ids1 = sorted(h["id"] for h in store.all_rows(self.e))
        r2 = self.refresh()
        self.assertEqual(sorted(h["id"] for h in store.all_rows(self.e)), ids1)
        self.assertEqual((r2["new"], r2["reopened"], r2["expired"]), (0, 0, 0))
        self.assertGreaterEqual(r1["new"], 2)

    def test_a_hypothesis_no_longer_produced_is_hidden_not_deleted(self):
        self.refresh()
        self.refresh(findings=[self.findings[0]])
        gone = [h for h in store.all_rows(self.e) if not h["current"]]
        self.assertTrue(gone)
        listed = {h["id"] for h in service.listing(self.e)["suggestions"]}
        self.assertFalse(listed & {h["id"] for h in gone})

    def test_capacity_cap(self):
        fs = [fnd(i, host=f"H{i}", cve=f"CVE-{i}") for i in range(1, 12)]
        cfg = context.config()
        cfg["max_suggestions"] = 3
        c = ctx(findings=fs, cfg=cfg)
        service.refresh(fs, self.e, now=NOW, ctx=c)
        import remediation.hunting.engine.service as s
        orig = s.ctx_mod.config
        s.ctx_mod.config = lambda path=None: cfg
        try:
            out = service.listing(self.e)
        finally:
            s.ctx_mod.config = orig
        self.assertEqual((out["shown"], out["capped"]), (3, True))
        self.assertGreater(out["total"], 3)

    def test_gaps_are_recorded_with_the_refresh(self):
        self.refresh()
        self.assertTrue(service.listing(self.e)["gaps"])


class LifecycleTests(Base):
    def setUp(self):
        super().setUp()
        self.refresh()
        self.h = self.first()

    def test_accept_creates_a_compatible_hunt(self):
        a = service.accept(self.h["id"], "admin@t", engine=self.e)
        self.assertEqual(a["status"], "accepted")
        hunt = hunt_store.get_hunt(a["hunt_id"], self.e)
        self.assertEqual((hunt["status"], hunt["source"], hunt["source_ref"]), ("proposed", "hypothesis", self.h["id"]))
        self.assertTrue(hunt["queries"] and hunt["queries"][0]["language"] == "splunk-spl" and hunt["queries"][0]["result"] is None)
        self.assertIn("Why now", hunt["notes"])
        self.assertEqual(hunt_store.existing_refs(self.e), set())   # the legacy proposal flow is untouched
        with self.assertRaises(service.TransitionError):
            service.accept(self.h["id"], "admin@t", engine=self.e)

    def test_hunt_progress_moves_the_suggestion_forward(self):
        a = service.accept(self.h["id"], "admin@t", engine=self.e)
        hunt = hunt_store.get_hunt(a["hunt_id"], self.e)
        qs = hunt["queries"]
        qs[0]["result"] = "no-hits"
        hunt_store.update_hunt(a["hunt_id"], {"queries": qs, "status": "active"}, self.e)
        service.sync_with_hunts(self.e)
        self.assertEqual(store.get(self.h["id"], self.e)["status"], "evidence-recorded")
        hunt_store.update_hunt(a["hunt_id"], {"status": "closed", "outcome": "not-found"}, self.e)
        service.sync_with_hunts(self.e)
        got = store.get(self.h["id"], self.e)
        self.assertEqual((got["status"], got["outcome"]), ("concluded", "benign"))

    def test_conclude_closes_the_hunt_and_needs_notes(self):
        a = service.accept(self.h["id"], "admin@t", engine=self.e)
        with self.assertRaises(ValueError):
            service.conclude(self.h["id"], "benign", " ", "admin@t", engine=self.e)
        with self.assertRaises(ValueError):
            service.conclude(self.h["id"], "maybe", "x", "admin@t", engine=self.e)
        c = service.conclude(self.h["id"], "true-positive", "Found a webshell", "admin@t", engine=self.e)
        self.assertEqual((c["status"], c["outcome"]), ("concluded", "true-positive"))
        hunt = hunt_store.get_hunt(a["hunt_id"], self.e)
        self.assertEqual((hunt["status"], hunt["outcome"]), ("closed", "confirmed"))

    def test_invalid_transitions(self):
        with self.assertRaises(service.TransitionError):
            service.conclude(self.h["id"], "benign", "n", "a", engine=self.e)   # not accepted yet
        with self.assertRaises(service.TransitionError):
            service.promote(self.h["id"], "a", engine=self.e)
        with self.assertRaises(KeyError):
            service.accept("hyp-nope", "a", engine=self.e)
        service.dismiss(self.h["id"], "no-data", "no EDR", "a", engine=self.e)
        with self.assertRaises(service.TransitionError):
            service.accept(self.h["id"], "a", engine=self.e)

    def test_promote_creates_a_proposed_use_case_never_coverage(self):
        service.accept(self.h["id"], "admin@t", engine=self.e)
        service.conclude(self.h["id"], "true-positive", "real", "admin@t", engine=self.e)
        p = service.promote(self.h["id"], "admin@t", engine=self.e)
        self.assertEqual(p["status"], "promoted")
        uc = usecase_store.get(p["promoted_key"], self.e)
        self.assertEqual((uc["status"], uc["kind"]), ("proposed", "hunt-promotion"))
        self.assertTrue(uc["sigma"])
        self.assertTrue(hunt_store.get_hunt(p["hunt_id"], self.e)["detection_created"])
        self.assertEqual([e["kind"] for e in store.events(self.h["id"], self.e)][-3:], ["accepted", "concluded", "promoted"])


class MemoryTests(Base):
    def test_dismissal_sticks_until_evidence_materially_changes(self):
        self.refresh()
        h = self.first()
        with self.assertRaises(ValueError):
            service.dismiss(h["id"], "bad-reason", "", "a", engine=self.e)
        service.dismiss(h["id"], "not-relevant", "test box", "a", engine=self.e)
        self.refresh()
        self.assertEqual(store.get(h["id"], self.e)["status"], "dismissed")
        self.assertNotIn(h["id"], {x["id"] for x in service.listing(self.e)["suggestions"]})
        # a second finding on the same CVE (non-strong refs: stay dismissed below the threshold) ...
        more = self.findings + [fnd(3, host="WEB-1", kev=False)]
        self.refresh(findings=more)
        self.assertEqual(store.get(h["id"], self.e)["status"], "dismissed")
        # ... but a flood of new evidence, or a new strong item, reopens it
        flood = self.findings + [fnd(10 + i, host=f"X{i}", kev=False) for i in range(4)]
        r = self.refresh(findings=flood)
        self.assertEqual(r["reopened"], 1)
        again = store.get(h["id"], self.e)
        self.assertEqual(again["status"], "suggested")
        self.assertIn("reopened", [e["kind"] for e in store.events(h["id"], self.e)])

    def test_concluded_are_never_resuggested(self):
        self.refresh()
        h = self.first()
        service.accept(h["id"], "a", engine=self.e)
        service.conclude(h["id"], "benign", "clean", "a", engine=self.e)
        self.refresh(findings=self.findings + [fnd(20 + i, host=f"Y{i}") for i in range(5)])
        self.assertEqual(store.get(h["id"], self.e)["status"], "concluded")

    def test_learning_loop_lowers_then_suppresses_a_benign_pattern(self):
        self.refresh()
        base = self.first("coverage-gap" if any(x["generator"] == "coverage-gap" for x in store.all_rows(self.e)) else "kev-exposure")
        pattern = base["pattern_key"]
        for i in range(3):   # three earlier hunts of this pattern concluded benign
            rid = f"hyp-old{i}"
            with self.e.begin() as conn:
                conn.execute(db_module.hunt_hypotheses.insert().values(
                    id=rid, generator=base["generator"], hunt_type=base["hunt_type"], pattern_key=pattern, title="old", status="concluded", outcome="benign", outcome_notes="n", score=1, current=0,
                    evidence_refs_json="[]", data_json="{}", created_at="2026-01-01T00:00:00Z", updated_at="2026-01-01T00:00:00Z"))
        stats = store.pattern_stats(self.e)[pattern]
        self.assertEqual((stats["concluded"], stats["benign"]), (3, 3))
        self.refresh()
        after = store.get(base["id"], self.e)
        self.assertTrue(after["learned"]["suppressed"])
        self.assertLess(after["learned"]["points"], 0)
        self.assertIn("past outcomes", after["learned"]["note"])
        self.assertNotIn(base["id"], {x["id"] for x in service.listing(self.e)["suggestions"]})
        self.assertIn(base["id"], {x["id"] for x in service.listing(self.e, include_suppressed=True)["suggestions"]})

    def test_confirmed_hunt_raises_a_lessons_learned_sweep(self):
        fs = [fnd(1, host="A", tech=(T1059,), kev=False), fnd(2, host="B", tech=(T1059,), kev=False)]
        self.refresh(findings=fs, alerts=[alert(5, asset="A", disp="true-positive", technique="T1059")])
        self.assertTrue(any(h["generator"] == "lessons-learned" for h in store.all_rows(self.e)))


class MigrationTests(unittest.TestCase):
    def test_migration_creates_tables_and_is_idempotent(self):
        e = create_engine("sqlite:///:memory:")
        migrations.apply(e)
        self.assertTrue(inspect(e).has_table("hunt_hypotheses") and inspect(e).has_table("hunt_hypothesis_events"))
        self.assertEqual(migrations.apply(e), [])
        migrations._m007_hunt_hypotheses(e)   # safe to run again directly
        self.assertIn(7, migrations.applied(e))


if __name__ == "__main__":
    unittest.main()
