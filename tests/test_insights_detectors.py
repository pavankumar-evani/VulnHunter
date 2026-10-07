"""Insights: the statistics, every detector (positive, negative, insufficient data / missing source), stable ids, scoring, learning, dedupe and correlation."""
import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.insights import detectors, model, scoring, service, stats  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, 12, 0, tzinfo=datetime.timezone.utc)
TODAY = NOW.date()
CFG = service.load_config()


def day(n):
    """ISO date n days before today."""
    return (TODAY - datetime.timedelta(days=n)).isoformat()


def snap(**over):
    base = {"now": NOW, "findings": [], "assets": [], "exceptions": [], "approvals": [], "activity": [], "alerts": [], "hunts": [], "cases": [], "connections": [],
            "api_keys": [], "ai_events": [], "grc_evidence": [], "grc_mappings": {}, "controls": [], "license": {}, "baseline": {"assets": None, "controls": None}}
    base.update(over)
    return base


def finding(fid, sev="Low", asset="a-1", first_seen=None, kev=False, **kw):
    f = {"id": fid, "title": f"t {fid}", "severity": sev, "asset": {"name": asset, "type": kw.pop("atype", "unix-server")}, "first_seen": first_seen or day(90),
         "last_seen": kw.pop("last_seen", day(0)), "kev": {"listed": kev}}
    f.update(kw)
    return f


def fillers(n=25):
    return [finding(f"F{i}", asset=f"base-{i % 12}") for i in range(n)]


def run(name, s, **cfg_over):
    cfg = {"detectors": {name: {**CFG["detectors"][name], **cfg_over}}, "drift": CFG["drift"]}
    d = detectors.BY_NAME[name]
    ins, gaps, errors = detectors.run_all(s, {**cfg, "detectors": {**{n: {"enabled": False} for n in detectors.BY_NAME}, name: cfg["detectors"][name]}})
    assert not errors, errors
    return ins, gaps, d


class Stats(unittest.TestCase):
    def test_robust_z_flags_an_outlier_and_refuses_short_history(self):
        hist = [10, 11, 9, 10, 12, 10, 11, 9, 10]
        self.assertGreater(stats.robust_z(40, hist), 3.5)
        self.assertLess(abs(stats.robust_z(10, hist)), 1)
        self.assertIsNone(stats.robust_z(40, [10, 11, 9]))                 # not enough history

    def test_flat_series_does_not_divide_by_zero(self):
        self.assertAlmostEqual(stats.robust_z(5, [3] * 10), 2.0)

    def test_ewma_and_seasonal_naive(self):
        self.assertIsNone(stats.ewma([]))
        self.assertAlmostEqual(stats.ewma([10, 10, 10]), 10)
        weekly = [1, 2, 3, 4, 5, 6, 7] * 3
        self.assertEqual(stats.seasonal_naive(weekly), 1)
        self.assertIsNone(stats.seasonal_naive(weekly[:14]))
        self.assertEqual(stats.baseline_forecast([1, 2])[1], "not enough history")
        self.assertEqual(stats.baseline_forecast(weekly)[1].split(" ")[0], "seasonal-naive")
        self.assertEqual(stats.baseline_forecast([5] * 8)[1], "EWMA")

    def test_change_point_finds_a_level_shift_and_ignores_noise(self):
        cp = stats.change_point([1, 1, 1, 1, 0, 0, 0, 0])
        self.assertEqual((cp["index"], cp["before"], cp["after"]), (4, 1, 0))
        self.assertIsNone(stats.change_point([1, 0.9, 1, 0.95, 1, 0.9, 1, 0.95]))
        self.assertIsNone(stats.change_point([1, 2, 3]))                    # too short

    def test_confidence_grows_with_n_and_is_bounded(self):
        self.assertEqual(stats.confidence_from_n(0), 0.0)
        self.assertLess(stats.confidence_from_n(3), stats.confidence_from_n(30))
        self.assertLess(stats.confidence_from_n(10 ** 6), 1.0001)


class Model(unittest.TestCase):
    def test_id_is_stable_and_depends_on_detector_and_subject_only(self):
        a = model.stable_id("d", "asset:x")
        self.assertEqual(a, model.stable_id("d", "asset:x"))
        self.assertNotEqual(a, model.stable_id("d", "asset:y"))
        self.assertNotEqual(a, model.stable_id("e", "asset:x"))
        self.assertTrue(a.startswith("ins_"))

    def test_make_validates_and_clamps(self):
        i = model.make("d", "k", "anomaly", "soc", "t", "w", "y", impact=5, confidence=-1, roles={"admin": 2, "bogus": 1})
        self.assertEqual((i["impact"]["value"], i["confidence"]["value"], i["roles"]), (1.0, 0.0, {"admin": 1.0}))
        with self.assertRaises(ValueError):
            model.make("d", "k", "nope", "soc", "t", "w", "y")
        with self.assertRaises(ValueError):
            model.make("d", "k", "anomaly", "nope", "t", "w", "y")


class Detectors(unittest.TestCase):
    # ---- kev_week_over_week
    def test_kev_wow_positive_negative_insufficient(self):
        fs = fillers() + [finding(f"K{i}", "High", f"base-{i}", first_seen=day(2), kev=True) for i in range(4)] + [finding("KOLD", first_seen=day(9), kev=True)]
        ins, _, _ = run("kev_week_over_week", snap(findings=fs))
        self.assertEqual(len(ins), 1)
        self.assertIn("4 new known-exploited", ins[0]["title"])
        self.assertEqual(run("kev_week_over_week", snap(findings=fillers() + [finding("K1", first_seen=day(1), kev=True)]))[0], [])
        self.assertEqual(run("kev_week_over_week", snap(findings=fs[:5]))[0], [])           # below min_findings

    # ---- sla_trend
    def test_sla_trend(self):
        fs = [finding(f"C{i}", "Critical", f"base-{i}", sla={"breached": True, "days_remaining": -2}) for i in range(5)] + fillers()
        ins, _, _ = run("sla_trend", snap(findings=fs))
        self.assertEqual(len(ins), 1)
        self.assertEqual(ins[0]["kind"], "deadline")
        ok = [finding(f"C{i}", "Critical", f"base-{i}", sla={"breached": False, "days_remaining": 9}) for i in range(5)] + fillers()
        self.assertEqual(run("sla_trend", snap(findings=ok))[0], [])
        self.assertEqual(run("sla_trend", snap(findings=fs[:4]))[0], [])

    # ---- finding_burst
    def test_finding_burst(self):
        base = [finding(f"B{i}", asset=f"h-{i}") for i in range(12)]
        burst = [finding(f"N{i}", "High", "h-3", first_seen=day(1)) for i in range(8)]
        ins, _, _ = run("finding_burst", snap(findings=base + burst, assets=[{"name": "h-3", "team": "Blue"}]))
        self.assertEqual(len(ins), 1)
        self.assertEqual(ins[0]["entities"], ["asset:h-3"])
        self.assertEqual(ins[0]["teams"], ["Blue"])
        quiet = [finding(f"Q{i}", asset=f"h-{i}", first_seen=day(1)) for i in range(12)]
        self.assertEqual(run("finding_burst", snap(findings=quiet))[0], [])
        few, gaps, _ = run("finding_burst", snap(findings=burst))
        self.assertEqual(few, [])
        self.assertTrue(any("finding_burst" in g for g in gaps))

    # ---- exposure_change
    def test_exposure_change(self):
        fs = [finding("X1", "Critical", "web-1")]
        before = {"web-1": {"facing": "internal", "owner": "bob"}}
        cur = [{"name": "web-1", "facing": "internet", "owner": "bob"}]
        s = snap(findings=fs, assets=cur, baseline={"assets": before, "controls": None})
        ins, _, _ = run("exposure_change", s)
        self.assertEqual(len(ins), 1)
        self.assertIn("internet-facing", ins[0]["title"])
        lost = snap(findings=fs, assets=[{"name": "web-1", "facing": "internal", "owner": None}], baseline={"assets": before, "controls": None})
        self.assertIn("lost its owner", run("exposure_change", lost)[0][0]["title"])
        same = snap(findings=fs, assets=[{"name": "web-1", "facing": "internal", "owner": "bob"}], baseline={"assets": before, "controls": None})
        self.assertEqual(run("exposure_change", same)[0], [])
        none, gaps, _ = run("exposure_change", snap(findings=fs, assets=cur))
        self.assertEqual(none, [])
        self.assertTrue(any("no earlier asset snapshot" in g for g in gaps))
        low = snap(findings=[finding("X2", "Low", "web-1")], assets=cur, baseline={"assets": before, "controls": None})
        self.assertEqual(run("exposure_change", low)[0], [])            # only urgent findings make it matter

    # ---- unowned_critical
    def test_unowned_critical(self):
        fs = [finding("U1", "Critical", "orphan"), finding("U2", "Critical", "owned")]
        ins, _, _ = run("unowned_critical", snap(findings=fs, assets=[{"name": "owned", "owner": "al"}, {"name": "orphan"}]))
        self.assertEqual(len(ins), 1)
        self.assertEqual(ins[0]["kind"], "gap")
        self.assertEqual(run("unowned_critical", snap(findings=fs, assets=[{"name": "owned", "team": "t"}, {"name": "orphan", "team": "t"}]))[0], [])

    # ---- control_disappeared
    def test_control_disappeared(self):
        fs = [finding("C1", "High", "srv")]
        prev = [["srv", "edr", "EDR-X"]]
        ins, _, _ = run("control_disappeared", snap(findings=fs, controls=[], baseline={"assets": None, "controls": prev}))
        self.assertEqual(len(ins), 1)
        self.assertIn("removed", ins[0]["title"])
        present = [{"asset_name": "srv", "control_class": "edr", "name": "EDR-X", "last_seen": day(1)}]
        self.assertEqual(run("control_disappeared", snap(findings=fs, controls=present, baseline={"assets": None, "controls": prev}))[0], [])
        stale = [{"asset_name": "srv", "control_class": "edr", "name": "EDR-X", "last_seen": day(60)}]
        s_ins, gaps, _ = run("control_disappeared", snap(findings=fs, controls=stale))
        self.assertIn("not re-verified", s_ins[0]["title"])
        self.assertTrue(any("no earlier controls snapshot" in g for g in gaps))
        self.assertEqual(run("control_disappeared", snap(findings=[finding("C2", "Low", "srv")], controls=[], baseline={"assets": None, "controls": prev}))[0], [])

    # ---- exception_expiring
    def test_exception_expiring(self):
        fs = [finding("E1", "High", "a", kev=True), finding("E2", "High", "a", kev=False)]

        def exc(fid, days):
            return {"finding_id": fid, "expires_on": (TODAY + datetime.timedelta(days=days)).isoformat(), "status": "active", "computed_status": "active"}
        ins, _, _ = run("exception_expiring", snap(findings=fs, exceptions=[exc("E1", 5)]))
        self.assertEqual(len(ins), 1)
        self.assertEqual(run("exception_expiring", snap(findings=fs, exceptions=[exc("E1", 60)]))[0], [])
        self.assertEqual(run("exception_expiring", snap(findings=fs, exceptions=[exc("E2", 5)]))[0], [])
        expired = {**exc("E1", 5), "computed_status": "expired"}
        self.assertEqual(run("exception_expiring", snap(findings=fs, exceptions=[expired]))[0], [])

    # ---- approval_stalled
    def test_approval_stalled(self):
        a = {"finding_id": "F1", "status": "approved", "computed_status": "approved", "approved_at": day(10), "approved_by": "x", "triggered_at": None}
        self.assertEqual(len(run("approval_stalled", snap(approvals=[a]))[0]), 1)
        self.assertEqual(run("approval_stalled", snap(approvals=[{**a, "triggered_at": day(1)}]))[0], [])
        self.assertEqual(run("approval_stalled", snap(approvals=[{**a, "approved_at": day(2)}]))[0], [])
        self.assertEqual(run("approval_stalled", snap(approvals=[{**a, "computed_status": "pending"}]))[0], [])

    # ---- same_cve_many_apps
    def test_same_cve_many_apps(self):
        dep = {"package": "log4j-core", "fixed_version": "2.17.1"}
        three = [finding(f"L{i}", "Critical", f"app-{i}", cve="CVE-2021-44228", dependency=dep, atype="application") for i in range(3)]
        ins, _, _ = run("same_cve_many_apps", snap(findings=three))
        self.assertEqual(len(ins), 1)
        self.assertEqual(ins[0]["kind"], "opportunity")
        self.assertIn("2.17.1", ins[0]["what"])
        self.assertEqual(run("same_cve_many_apps", snap(findings=three[:2]))[0], [])

    # ---- source_quiet
    def test_source_quiet(self):
        conn = {"name": "tenable", "enabled": True, "schedule_minutes": 60, "last_run_at": day(5)}
        ins, _, _ = run("source_quiet", snap(findings=[finding("S1")], connections=[conn]))
        self.assertTrue(any("tenable" in i["title"] for i in ins))
        fresh = {**conn, "last_run_at": TODAY.isoformat()}
        self.assertEqual(run("source_quiet", snap(findings=[finding("S1")], connections=[fresh]))[0], [])
        self.assertEqual(run("source_quiet", snap(findings=[finding("S1")], connections=[{**conn, "enabled": False}]))[0], [])
        stale = run("source_quiet", snap(findings=[finding("S1", last_seen=day(20))], connections=[fresh]))[0]
        self.assertEqual(len(stale), 1)
        self.assertIn("No finding refreshed", stale[0]["title"])

    # ---- noisy_rules
    def test_noisy_rules(self):
        def al(i, disp):
            return {"id": i, "rule_name": "R1", "status": "closed", "disposition": disp, "received_at": day(1)}
        noisy = [al(i, "false-positive") for i in range(9)] + [al(99, "true-positive")]
        self.assertEqual(len(run("noisy_rules", snap(alerts=noisy))[0]), 1)
        good = [al(i, "true-positive") for i in range(10)]
        self.assertEqual(run("noisy_rules", snap(alerts=good))[0], [])
        self.assertEqual(run("noisy_rules", snap(alerts=noisy[:5]))[0], [])             # too few closed alerts
        self.assertEqual(run("noisy_rules", snap(alerts=[{**a, "status": "open"} for a in noisy]))[0], [])

    # ---- alert_volume_anomaly
    def test_alert_volume_anomaly(self):
        def alerts(counts):
            out, n = [], 0
            for d, c in counts.items():
                for _ in range(c):
                    n += 1
                    out.append({"id": n, "received_at": day(d)})
            return out
        history = {d: 9 + (d % 3) for d in range(2, 22)}
        spike = alerts({**history, 1: 70})
        ins, _, _ = run("alert_volume_anomaly", snap(alerts=spike))
        self.assertEqual(len(ins), 1)
        self.assertIn("70", ins[0]["title"])
        self.assertEqual(run("alert_volume_anomaly", snap(alerts=alerts({**history, 1: 10})))[0], [])
        short, gaps, _ = run("alert_volume_anomaly", snap(alerts=alerts({d: 10 for d in range(1, 6)})))
        self.assertEqual(short, [])
        self.assertTrue(any("not enough history" in g for g in gaps))
        drop = run("alert_volume_anomaly", snap(alerts=alerts({**history, 1: 0})))[0]
        self.assertEqual(drop, [])                                                       # a quiet day is not this detector's concern

    # ---- entity_repeat
    def test_entity_repeat(self):
        al = [{"id": i, "asset": "WEB-01", "received_at": day(2), "entities_json": "[]"} for i in range(2)]
        hunt = {"id": 1, "created_at": day(3), "assets_json": '["web-01"]'}
        ins, _, _ = run("entity_repeat", snap(alerts=al, hunts=[hunt], cases=[]))
        self.assertEqual(len(ins), 1)
        self.assertEqual(ins[0]["entities"], ["asset:web-01"])
        self.assertEqual(run("entity_repeat", snap(alerts=al, hunts=[], cases=[]))[0], [])
        old = [{**a, "received_at": day(60)} for a in al]
        self.assertEqual(run("entity_repeat", snap(alerts=old, hunts=[{**hunt, "created_at": day(60)}], cases=[]))[0], [])

    # ---- posture_drop
    def test_posture_drop(self):
        maps = {"patch-sla": {"fw1": ["C1"]}}

        def ev(results):
            return [{"test_id": "patch-sla", "result": r, "collected_at": day(len(results) - i)} for i, r in enumerate(results)]
        ins, _, _ = run("posture_drop", snap(grc_evidence=ev(["pass"] * 5 + ["fail"] * 3), grc_mappings=maps))
        self.assertEqual(len(ins), 1)
        self.assertIn("fw1", ins[0]["title"])
        self.assertEqual(run("posture_drop", snap(grc_evidence=ev(["pass"] * 8), grc_mappings=maps))[0], [])
        short, gaps, _ = run("posture_drop", snap(grc_evidence=ev(["pass", "fail", "fail"]), grc_mappings=maps))
        self.assertEqual(short, [])
        self.assertTrue(any("not enough history" in g for g in gaps))
        na = run("posture_drop", snap(grc_evidence=ev(["pass"] * 5 + ["na"] * 3), grc_mappings=maps))[0]
        self.assertEqual(na, [])                                                         # na is never a failure or a pass

    # ---- expiry
    def test_expiry(self):
        key = {"name": "ci", "prefix": "abc", "expires_at": (TODAY + datetime.timedelta(days=5)).isoformat(), "revoked_at": None}
        ins, _, _ = run("expiry", snap(api_keys=[key], license={"state": "valid"}))
        self.assertEqual(len(ins), 1)
        self.assertEqual(run("expiry", snap(api_keys=[{**key, "revoked_at": day(1)}], license={"state": "valid"}))[0], [])
        self.assertEqual(run("expiry", snap(api_keys=[{**key, "expires_at": (TODAY + datetime.timedelta(days=90)).isoformat()}], license={"state": "valid"}))[0], [])
        lic = run("expiry", snap(api_keys=[], license={"state": "expiring", "message": "The licence ends in 9 day(s)."}))[0]
        self.assertEqual(len(lic), 1)
        self.assertEqual(lic[0]["module"], "admin")
        expired_key = run("expiry", snap(api_keys=[{**key, "expires_at": day(3)}], license={}))[0]
        self.assertIn("has expired", expired_key[0]["title"])

    # ---- ai_cost_spike
    def test_ai_cost_spike(self):
        base = [{"ts": day(d), "cost_usd": 9 + (d % 3)} for d in range(2, 16)]
        ins, _, _ = run("ai_cost_spike", snap(ai_events=base + [{"ts": day(1), "cost_usd": 90}]))
        self.assertEqual(len(ins), 1)
        self.assertEqual(run("ai_cost_spike", snap(ai_events=base + [{"ts": day(1), "cost_usd": 11}]))[0], [])
        unknown = run("ai_cost_spike", snap(ai_events=base + [{"ts": day(1), "cost_usd": None}]))[0]
        self.assertEqual(unknown, [])                                                     # unknown cost is never counted as a spike or as zero
        few, gaps, _ = run("ai_cost_spike", snap(ai_events=base[:4]))
        self.assertEqual(few, [])
        self.assertTrue(any("not enough days" in g for g in gaps))

    # ---- policy_drift
    def test_policy_drift(self):
        def ev(action, details, d=1):
            return {"id": 1, "actor": "root@x", "action": action, "details": details, "timestamp": datetime.datetime.combine(TODAY - datetime.timedelta(days=d), datetime.time(9), datetime.timezone.utc).isoformat()}
        ins, _, _ = run("policy_drift", snap(activity=[ev("priority_rules.update", {})]))
        self.assertEqual(len(ins), 1)
        self.assertEqual(ins[0]["kind"], "drift")
        self.assertEqual(run("policy_drift", snap(activity=[ev("priority_rules.update", {"approved_by": "boss"})]))[0], [])
        self.assertEqual(run("policy_drift", snap(activity=[ev("priority_rules.update", {}, d=60)]))[0], [])
        self.assertEqual(run("policy_drift", snap(activity=[ev("hunt.create", {})]))[0], [])


class Engine(unittest.TestCase):
    def test_missing_source_is_a_gap_note_not_an_insight(self):
        s = snap(alerts=None, findings=None)
        ins, gaps, errors = detectors.run_all(s, CFG)
        self.assertFalse([i for i in ins if i["detector"] in ("noisy_rules", "alert_volume_anomaly", "kev_week_over_week")])
        self.assertTrue(any(g.startswith("noisy_rules: needs alerts") for g in gaps))
        self.assertEqual(errors, [])

    def test_a_crashing_detector_is_contained(self):
        s = snap(findings=[{"id": "x"}], approvals=[{"status": "approved", "computed_status": "approved", "approved_at": "bad", "triggered_at": None}])
        ins, gaps, errors = detectors.run_all(s, CFG)       # findings without asset/severity must not break the engine
        self.assertIsInstance(errors, list)

    def test_disabled_detector_does_not_run(self):
        cfg = {**CFG, "detectors": {**CFG["detectors"], "unowned_critical": {"enabled": False}}}
        s = snap(findings=[finding("U1", "Critical", "orphan")], assets=[{"name": "orphan"}])
        self.assertFalse([i for i in detectors.run_all(s, cfg)[0] if i["detector"] == "unowned_critical"])

    def test_ids_are_stable_across_runs_and_numbers(self):
        s1 = snap(findings=[finding("U1", "Critical", "orphan")], assets=[{"name": "orphan"}])
        s2 = snap(findings=[finding("U1", "Critical", "orphan"), finding("U9", "Critical", "orphan")], assets=[{"name": "orphan"}])
        a = [i["id"] for i in run("unowned_critical", s1)[0]]
        b = [i["id"] for i in run("unowned_critical", s2)[0]]
        self.assertEqual(a, b)

    def test_baselines_capture_only_available_sources(self):
        s = snap(assets=[{"name": "a", "facing": "internet", "owner": "o", "team": "t"}], controls=None)
        self.assertEqual(detectors.capture_baselines(s), {"assets": {"a": {"facing": "internet", "owner": "o", "team": "t"}}})


class Scoring(unittest.TestCase):
    def ins(self, **kw):
        d = dict(detector="d1", kind="anomaly", module="soc", title="t", what="w", why="y", impact=0.8, confidence=0.5, urgency=0.5, roles={"admin": 1.0, "exec": 0.2})
        d.update(kw)
        key = d.pop("key", "k")
        det = d.pop("detector")
        return model.make(det, key, d.pop("kind"), d.pop("module"), d.pop("title"), d.pop("what"), d.pop("why"), **d)

    def test_score_is_the_product_with_a_visible_breakdown(self):
        i = scoring.score(self.ins(), "admin", {})
        self.assertAlmostEqual(i["score"], 0.8 * 0.5 * 0.5 * 1.0 * 100, places=1)
        self.assertEqual(set(i["breakdown"]) >= {"impact", "confidence", "urgency", "role_relevance", "learned_weight", "formula"}, True)

    def test_role_relevance_changes_rank_and_unknown_role_gets_a_low_default(self):
        a, b = self.ins(key="a"), self.ins(key="b", roles={"exec": 1.0})
        self.assertGreater(scoring.score(dict(a), "admin", {})["score"], scoring.score(dict(b), "admin", {})["score"])
        self.assertGreater(scoring.score(dict(b), "exec", {})["score"], scoring.score(dict(a), "exec", {})["score"])
        self.assertEqual(scoring.score(dict(b), "admin", {})["breakdown"]["role_relevance"], scoring.DEFAULT_RELEVANCE)

    def test_learning_is_bounded_and_needs_enough_actions(self):
        w = scoring.learned_weights({"few": {"acted": 2, "dismissed": 0}, "good": {"acted": 50, "dismissed": 0}, "bad": {"acted": 0, "dismissed": 50}, "mixed": {"acted": 5, "dismissed": 5}}, CFG)
        self.assertEqual(w["few"], 1.0)
        self.assertEqual(w["good"], 1.4)
        self.assertEqual(w["bad"], 0.6)
        self.assertEqual(w["mixed"], 1.0)
        tight = {"learning": {**CFG["learning"], "strength": 5.0}}
        self.assertEqual(scoring.learned_weights({"x": {"acted": 10, "dismissed": 0}}, tight)["x"], 1.4)   # strength cannot escape the bounds

    def test_weight_changes_the_score(self):
        i = self.ins()
        base = scoring.score(dict(i), "admin", {})["score"]
        up = scoring.score(dict(i), "admin", {"d1": 1.4})["score"]
        self.assertAlmostEqual(up, round(base * 1.4, 1), delta=0.11)

    def test_near_duplicates_fold_to_the_best(self):
        a = scoring.score(self.ins(key="a", entities=["asset:x"], impact=0.9), "admin", {})
        b = scoring.score(self.ins(key="b", entities=["asset:x"], impact=0.3), "admin", {})
        c = scoring.score(self.ins(key="c", entities=["asset:y"]), "admin", {})
        out = scoring.fold_duplicates([a, b, c])
        self.assertEqual(len(out), 2)
        kept = [i for i in out if i["entities"] == ["asset:x"]][0]
        self.assertEqual(kept["id"], a["id"])
        self.assertEqual(kept["folded"], [b["id"]])

    def test_correlation_builds_a_compound_insight_from_shared_entities(self):
        members = [self.ins(detector=f"d{n}", key="k", entities=["asset:web-1"], module=m, impact=0.5 + n / 10) for n, m in enumerate(("soc", "infra", "remediation"))]
        out = scoring.correlate(members, CFG)
        self.assertEqual(len(out), 1)
        c = out[0]
        self.assertEqual(c["kind"], "correlation")
        self.assertEqual(sorted(c["members"]), sorted(m["id"] for m in members))
        self.assertGreater(c["impact"]["value"], max(m["impact"]["value"] for m in members) - 1e-9)
        self.assertEqual(c["id"], scoring.correlate(members, CFG)[0]["id"])            # stable
        self.assertEqual(scoring.correlate(members[:2], CFG), [])                       # below the minimum
        same_detector = [self.ins(detector="d", key=str(n), entities=["asset:z"]) for n in range(4)]
        self.assertEqual(scoring.correlate(same_detector, CFG), [])                     # needs two different detectors
        cves = [self.ins(detector=f"d{n}", key="k", entities=["cve:CVE-1"]) for n in range(4)]
        self.assertEqual(scoring.correlate(cves, CFG), [])                              # a CVE alone is not an asset-level correlation

    def test_cap_per_role(self):
        items = [self.ins(key=str(n), entities=[f"asset:{n}"]) for n in range(30)]
        self.assertEqual(len(scoring.rank_for_role(items, "admin", {}, 10)), 10)


if __name__ == "__main__":
    unittest.main()
