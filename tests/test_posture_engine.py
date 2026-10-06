"""The posture engine: scoring, the rule that unknown is never a pass, the ranked action list, failure handling, and the route."""
import datetime
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from remediation.posture import engine, model  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, 12, 0, tzinfo=datetime.timezone.utc)


def fw(fid, checks_fn, areas=(("a", "Area A"), ("b", "Area B"))):
    mod = types.ModuleType(f"remediation.posture.stub_{fid}")
    mod.FRAMEWORK = {"id": fid, "title": fid.title(), "summary": "s", "areas": list(areas), "refs": []}
    mod.run = checks_fn
    return mod


def chk(cid, status, **kw):
    kw.setdefault("area", "a")
    return model.check(cid, "x", kw.pop("area"), cid, status, **kw)


def assess(mods, problems=None):
    with patch.object(engine, "load_frameworks", return_value=(mods, dict(problems or {}))):
        return engine.assess(env={}, now=NOW)


class CheckModelTests(unittest.TestCase):
    def test_scores_follow_status(self):
        self.assertEqual(chk("c", "pass")["score"], 1.0)
        self.assertEqual(chk("c", "fail")["score"], 0.0)
        self.assertEqual(chk("c", "partial", score=0.4)["score"], 0.4)
        self.assertIsNone(chk("c", "unknown")["score"])
        self.assertIsNone(chk("c", "na")["score"])

    def test_bad_input_is_refused(self):
        for bad in (dict(status="maybe"), dict(status="pass", weight=9), dict(status="partial"), dict(status="partial", score=1.5),
                    dict(status="fail", change={"kind": "magic"})):
            with self.assertRaises(ValueError):
                model.check("c", "x", "a", "t", bad.pop("status"), **bad)

    def test_context_caches_and_records_an_unreadable_source(self):
        ctx = model.Context(env={"QUANTA_X": "yes"})
        calls = []
        self.assertEqual(ctx.get("k", lambda: calls.append(1) or 5), 5)
        self.assertEqual(ctx.get("k", lambda: calls.append(1) or 6), 5)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(ctx.get("bad", lambda: 1 / 0))
        self.assertIn("ZeroDivisionError", ctx.unavailable["bad"])
        self.assertTrue(ctx.flag("QUANTA_X"))
        self.assertFalse(ctx.flag("QUANTA_MISSING"))


class ScoringTests(unittest.TestCase):
    def test_weighted_score_counts_only_observable_checks(self):
        mod = fw("one", lambda ctx: [chk("p", "pass", weight=3), chk("f", "fail", weight=1), chk("u", "unknown", weight=5)])
        out = assess([mod])["frameworks"][0]
        self.assertEqual(out["score"], 75.0)                      # (3*1 + 1*0) / 4: the unknown check is not in it
        self.assertEqual(out["counts"], {"pass": 1, "partial": 0, "fail": 1, "unknown": 1, "na": 0})
        self.assertEqual(out["stage"], "Advanced")

    def test_an_all_unknown_framework_is_not_scored_and_says_why(self):
        mod = fw("blank", lambda ctx: [chk("u1", "unknown"), chk("u2", "unknown"), chk("n", "na")])
        out = assess([mod])
        f = out["frameworks"][0]
        self.assertIsNone(f["score"])
        self.assertIsNone(f["stage"])
        self.assertIn("Not enough", f["note"])
        self.assertIsNone(out["overall"]["score"])
        self.assertEqual(len(out["not_observable"]), 2)

    def test_too_little_observable_weight_refuses_a_score(self):
        # 1 observable check of weight 1 against 9 of unknown weight: 10% observable, under the 30% minimum
        mod = fw("thin", lambda ctx: [chk("p", "pass", weight=1)] + [chk(f"u{i}", "unknown", weight=3) for i in range(3)])
        f = assess([mod])["frameworks"][0]
        self.assertIsNone(f["score"])
        self.assertAlmostEqual(f["observable_share"], 0.1, places=2)

    def test_partial_uses_its_share_and_stages_follow_the_policy(self):
        mod = fw("p", lambda ctx: [chk("a", "partial", score=0.5, weight=2), chk("b", "pass", weight=2)])
        f = assess([mod])["frameworks"][0]
        self.assertEqual(f["score"], 75.0)
        for score, stage in ((10, "Traditional"), (40, "Initial"), (70, "Advanced"), (95, "Optimal")):
            self.assertEqual(engine.stage_for(score, engine.policy()), stage)

    def test_area_breakdown(self):
        mod = fw("ar", lambda ctx: [chk("a1", "pass", area="a"), chk("b1", "fail", area="b"), chk("b2", "unknown", area="b")])
        areas = {a["id"]: a for a in assess([mod])["frameworks"][0]["areas"]}
        self.assertEqual((areas["a"]["score"], areas["b"]["score"], areas["b"]["observable"], areas["b"]["checks"]), (100.0, 0.0, 1, 2))

    def test_overall_averages_only_scored_frameworks(self):
        good = fw("good", lambda ctx: [chk("g", "pass")])
        bad = fw("bad", lambda ctx: [chk("b", "fail")])
        blank = fw("blank", lambda ctx: [chk("u", "unknown")])
        o = assess([good, bad, blank])["overall"]
        self.assertEqual((o["score"], o["scored_frameworks"], o["frameworks"]), (50.0, 2, 3))


class ActionTests(unittest.TestCase):
    def test_actions_are_ranked_by_weight_times_the_gap(self):
        mod = fw("act", lambda ctx: [chk("small", "fail", weight=1), chk("big", "fail", weight=5), chk("half", "partial", score=0.5, weight=4), chk("ok", "pass")])
        ids = [a["check_id"] for a in assess([mod])["actions"]]
        self.assertEqual(ids, ["big", "half", "small"])           # 5, 2, 1

    def test_one_action_per_distinct_change(self):
        change = {"kind": "env", "where": "dashboard/app.py", "key": "QUANTA_PRODUCTION", "value": "true", "effect": "x"}
        a = fw("a", lambda ctx: [chk("one", "fail", weight=3, change=change)])
        b = fw("b", lambda ctx: [chk("two", "fail", weight=5, change=dict(change))])
        actions = assess([a, b])["actions"]
        self.assertEqual([x["check_id"] for x in actions], ["two"])   # the higher-impact check carries the shared setting

    def test_passing_unknown_and_na_checks_never_become_actions(self):
        mod = fw("quiet", lambda ctx: [chk("p", "pass"), chk("u", "unknown"), chk("n", "na")])
        out = assess([mod])
        self.assertEqual((out["actions"], out["all_actions"]), ([], 0))

    def test_the_list_is_capped_but_the_total_is_reported(self):
        mod = fw("many", lambda ctx: [chk(f"f{i:02d}", "fail", weight=3) for i in range(20)])
        out = assess([mod])
        self.assertEqual((len(out["actions"]), out["all_actions"]), (12, 20))


class RobustnessTests(unittest.TestCase):
    def test_a_framework_that_raises_is_reported_and_the_others_still_run(self):
        def boom(ctx):
            raise RuntimeError("source offline")
        out = assess([fw("ok", lambda ctx: [chk("p", "pass")]), fw("broken", boom)])
        self.assertEqual([f["id"] for f in out["frameworks"]], ["ok"])
        self.assertIn("RuntimeError", out["problems"]["broken"])

    def test_duplicate_check_ids_are_flagged(self):
        a = fw("a", lambda ctx: [chk("same", "pass")])
        b = fw("b", lambda ctx: [chk("same", "fail")])
        self.assertIn("same", assess([a, b])["problems"]["duplicate-check-ids"])

    def test_an_unreadable_source_is_listed_and_does_not_stop_the_review(self):
        def uses_bad_source(ctx):
            data = ctx.get("firewall", lambda: 1 / 0)
            return [chk("fw", "unknown" if data is None else "pass")]
        out = assess([fw("src", uses_bad_source)])
        self.assertIn("firewall", out["unavailable_sources"])

    def test_the_same_data_gives_the_same_review(self):
        mod = fw("det", lambda ctx: [chk("a", "fail", weight=4), chk("b", "partial", score=0.3), chk("c", "unknown")])
        self.assertEqual(json.dumps(assess([mod]), sort_keys=True), json.dumps(assess([mod]), sort_keys=True))

    def test_a_missing_or_broken_policy_file_falls_back_to_defaults(self):
        with patch.object(engine, "POLICY_PATH", Path("does-not-exist.yaml")):
            pol = engine.policy()
        self.assertEqual(pol["min_observable_share"], 0.30)
        self.assertEqual(pol["thresholds"]["stale_days"], 90)

    def test_the_shipped_policy_loads_and_has_the_thresholds_checks_read(self):
        pol = engine.policy()
        for key in ("stale_days", "kev_open_days", "critical_open_days", "min_sbom_age_days", "coverage_good", "coverage_partial", "max_admins"):
            self.assertIn(key, pol["thresholds"])


class RegistryTests(unittest.TestCase):
    def test_a_missing_framework_module_is_reported_as_not_installed(self):
        from remediation import posture
        with patch.object(posture, "FRAMEWORK_MODULES", ("zero_trust", "no_such_framework")):
            mods, problems = posture.load_frameworks()
        self.assertEqual(problems.get("no_such_framework"), "not installed")


class PostureApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_appsec_api import ApiBase

        class Base(ApiBase):
            def runTest(self):  # pragma: no cover - a TestCase needs one method to be instantiated for its setUp
                pass
        cls.Base = Base

    def setUp(self):
        self.t = self.Base()
        self.t.setUp()

    def tearDown(self):
        self.t.tearDown()

    def test_it_is_for_administrators_only(self):
        self.t.client.cookies.clear()
        self.assertEqual(self.t.client.get("/api/posture").status_code, 401)
        self.t.login("user@t.local")
        self.assertEqual(self.t.client.get("/api/posture").status_code, 403)

    def test_an_administrator_gets_the_review_and_no_secret_leaks(self):
        self.t.login("admin@t.local")
        with patch.dict("os.environ", {"QUANTA_SESSION_SECRET": "SUPER-SECRET-VALUE-123", "QUANTA_ENCRYPTION_KEY": "ANOTHER-SECRET-VALUE-456"}):
            r = self.t.client.get("/api/posture")
        self.assertEqual(r.status_code, 200, r.text[:300])
        d = r.json()
        self.assertEqual(set(d), {"frameworks", "overall", "actions", "all_actions", "not_observable", "unavailable_sources", "problems", "policy"})
        self.assertNotIn("SUPER-SECRET-VALUE-123", r.text)
        self.assertNotIn("ANOTHER-SECRET-VALUE-456", r.text)
        ids = [c["id"] for f in d["frameworks"] for c in f["checks"]]
        self.assertEqual(len(ids), len(set(ids)), "check ids must be unique across frameworks")
        for f in d["frameworks"]:
            for c in f["checks"]:
                self.assertIn(c["status"], model.STATUSES)
                if c["status"] == "fail":
                    self.assertTrue(c["evidence"], f"{c['id']}: a gap must show the data that proves it")


if __name__ == "__main__":
    unittest.main()
