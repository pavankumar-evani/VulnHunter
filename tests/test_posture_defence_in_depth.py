"""Tests for the defence in depth posture framework (remediation/posture/defence_in_depth.py)."""
import datetime
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine  # noqa: E402

from remediation.controls import store as controls  # noqa: E402
from remediation.hunting import detection, store as hunting_store  # noqa: E402
from remediation.posture import defence_in_depth as did, engine as posture_engine, model  # noqa: E402
from remediation.soar import playbooks  # noqa: E402
from remediation.soc import cases  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
ACTOR = "pat.owner@corp.test"
TECH = [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "initial-access"}]


def finding(i, host, sev="High", typ="unix-server", techniques=None):
    return {"id": f"FIND-{i}", "title": f"Issue {i}", "severity": sev, "status": "open", "asset": {"name": host, "type": typ}, "attack_techniques": techniques or []}


def mkctx(engine, findings=(), now=NOW):
    ctx = model.Context(engine=engine, findings=list(findings), env={}, now=now)
    pol = posture_engine.policy()
    ctx.policy, ctx.thr = pol, pol["thresholds"]
    return ctx


class DefenceInDepthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def run_did(self, findings=(), now=NOW):
        return {c["id"]: c for c in did.run(mkctx(self.engine, findings, now))}

    def ctl(self, asset, cls, state="verified"):
        controls.upsert(asset, cls, f"{cls} on {asset}", state, "feed", ACTOR, engine=self.engine)

    def alert(self, ext, rule, disposition=None):
        a, _ = hunting_store.receive_alert({"external_id": ext, "title": f"Alert {ext}", "severity": "High", "rule_name": rule}, self.engine)
        if disposition:
            hunting_store.update_alert(a["id"], {"status": "closed", "disposition": disposition}, self.engine)

    # ---- (a)
    def test_empty_estate_has_no_answers(self):
        checks = self.run_did()
        self.assertEqual(len(checks), 14)
        self.assertEqual({c["status"] for c in checks.values()}, {"unknown"})

    # ---- (b)
    def test_layer_verified_partial_and_claimed_only(self):
        self.ctl("*", "network-filtering", "claimed")
        self.ctl("*", "exploit-protection", "claimed")
        c = self.run_did()["did-perimeter-controls"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("0 verified, 2 claimed only", c["evidence"][0])
        self.ctl("*", "network-filtering")
        c = self.run_did()["did-perimeter-controls"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["score"], 0.5)
        self.ctl("*", "exploit-protection")
        self.assertEqual(self.run_did()["did-perimeter-controls"]["status"], "pass")

    def test_layer_shows_findings_burden(self):
        self.ctl("*", "edr")
        fs = [finding(1, "srv-01.corp.test", "Critical"), finding(2, "srv-02.corp.test", "High"), finding(3, "srv-03.corp.test", "Low")]
        c = self.run_did(fs)["did-host-controls"]
        self.assertIn("2 open Critical or High findings on 2 host assets", " ".join(c["evidence"]))
        self.assertEqual(self.run_did(fs)["did-data-controls"]["status"], "fail")  # controls recorded, none for data

    def test_single_point_of_protection(self):
        for cls in ("edr", "patching", "os-hardening"):
            self.ctl("srv-*", cls)
        c = self.run_did()["did-single-point"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 6 control layers", c["evidence"][0])
        for layer_cls in ("network-filtering", "network-segmentation", "encryption", "mfa"):
            self.ctl("*", layer_cls)
            self.ctl("srv-*", layer_cls)
        # edr x3 plus two entries each elsewhere: 4+ layers, no layer holds more than half
        c = self.run_did()["did-single-point"]
        self.assertIn(c["status"], ("pass", "partial"))
        self.assertNotEqual(c["status"], "fail")
        self.assertEqual(c["evidence"][0].split(" ")[0], "5")

    def test_alert_intake_recency(self):
        self.alert("a1", "rule-a")
        real = datetime.datetime.now(datetime.timezone.utc)
        self.assertEqual(self.run_did(now=real)["did-mon-alerts"]["status"], "pass")
        self.assertEqual(self.run_did(now=real + datetime.timedelta(days=200))["did-mon-alerts"]["status"], "fail")

    def test_detection_health_good_and_bad(self):
        real = datetime.datetime.now(datetime.timezone.utc)
        detection.upsert_rule("good-rule", techniques=["T1190"], engine=self.engine)
        for i in range(5):
            self.alert(f"g{i}", "good-rule", "true-positive")
        self.assertEqual(self.run_did(now=real)["did-mon-detection-health"]["status"], "pass")
        detection.upsert_rule("noisy-rule", techniques=["T1059"], engine=self.engine)
        for i in range(5):
            self.alert(f"n{i}", "noisy-rule", "false-positive")
        c = self.run_did(now=real)["did-mon-detection-health"]
        self.assertEqual(c["status"], "partial")
        self.assertIn("1 of 2 judged rules", c["evidence"][0])
        self.assertIn("noisy-rule", " ".join(c["evidence"]))

    def test_detection_with_too_few_alerts_is_unknown(self):
        detection.upsert_rule("new-rule", techniques=["T1190"], engine=self.engine)
        self.alert("x1", "new-rule", "true-positive")
        self.assertEqual(self.run_did(now=datetime.datetime.now(datetime.timezone.utc))["did-mon-detection-health"]["status"], "unknown")

    def test_attack_coverage(self):
        detection.upsert_rule("web-rule", techniques=["T1190"], engine=self.engine)
        fs = [finding(1, "web-01.corp.test", techniques=TECH)]
        self.assertEqual(self.run_did(fs)["did-mon-attack-coverage"]["status"], "pass")
        fs.append(finding(2, "web-02.corp.test", techniques=[{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "execution"}]))
        c = self.run_did(fs)["did-mon-attack-coverage"]
        self.assertEqual(c["status"], "partial")
        self.assertIn("1 of 2 ATT&CK techniques", c["evidence"][0])
        self.assertIn("T1059", " ".join(c["evidence"]))

    def test_response_playbooks_cases_and_tiers(self):
        steps = [{"type": "add-note", "params": {"text": "hello"}}]
        playbooks.save("Off", "x", {"mode": "manual"}, steps, ACTOR, enabled=False, engine=self.engine)
        self.assertEqual(self.run_did()["did-resp-playbooks"]["status"], "fail")
        playbooks.save("On", "x", {"mode": "manual"}, steps, ACTOR, engine=self.engine)
        self.assertEqual(self.run_did()["did-resp-playbooks"]["status"], "pass")

        cases.open_case({"title": "Fresh case", "severity": "High", "assets": ["a.corp.test"]}, ACTOR, self.engine, now=NOW)
        self.assertEqual(self.run_did()["did-resp-cases"]["status"], "pass")
        cases.open_case({"title": "Old case", "severity": "High", "assets": ["b.corp.test"]}, ACTOR, self.engine, now=NOW - datetime.timedelta(days=10))
        c = self.run_did()["did-resp-cases"]
        self.assertEqual(c["status"], "partial")
        self.assertIn("1 of 2 cases", c["evidence"][0])

        cases.add_analyst("l1@corp.test", 1, self.engine)
        self.assertEqual(self.run_did()["did-resp-escalation"]["status"], "fail")
        cases.add_analyst("l2@corp.test", 2, self.engine)
        self.assertEqual(self.run_did()["did-resp-escalation"]["status"], "partial")
        cases.add_analyst("l3@corp.test", 3, self.engine)
        self.assertEqual(self.run_did()["did-resp-escalation"]["status"], "pass")

    # ---- (c)(d)(e)
    def seed_bad(self):
        self.ctl("*", "network-filtering", "claimed")
        self.ctl("srv-*", "edr")
        playbooks.save("Off", "x", {"mode": "manual"}, [{"type": "add-note", "params": {"text": "hello"}}], ACTOR, enabled=False, engine=self.engine)
        cases.open_case({"title": "Old case", "severity": "High", "assets": ["b.corp.test"]}, ACTOR, self.engine, now=NOW - datetime.timedelta(days=10))
        cases.add_analyst("l1@corp.test", 1, self.engine)
        detection.upsert_rule("web-rule", techniques=["T1190"], engine=self.engine)
        self.alert("a1", "web-rule")
        return [finding(1, "web-01.corp.test", techniques=[{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "execution"}])]

    def test_shape_ids_and_numbers(self):
        for fs in ((), self.seed_bad()):
            checks = did.run(mkctx(self.engine, fs, now=NOW + datetime.timedelta(days=200)))
            ids = [c["id"] for c in checks]
            self.assertEqual(len(ids), len(set(ids)))
            areas = {a for a, _ in did.FRAMEWORK["areas"]}
            self.assertEqual({c["area"] for c in checks}, areas)
            for c in checks:
                self.assertEqual(set(c), {"id", "framework", "area", "title", "status", "score", "weight", "evidence", "detail", "recommendation", "change", "refs", "data_used"})
                self.assertEqual(c["framework"], "defence-in-depth")
                self.assertTrue(c["recommendation"], c["id"])
                self.assertTrue(any(re.search(r"\d", e) for e in c["evidence"]), c["id"])

    def test_deterministic(self):
        fs = self.seed_bad()
        self.assertEqual(did.run(mkctx(self.engine, fs)), did.run(mkctx(self.engine, fs)))

    def test_changes_name_real_settings(self):
        fs = self.seed_bad()
        nav = (REPO_ROOT / "dashboard" / "static" / "js" / "nav.js").read_text(encoding="utf-8")
        seen = 0
        for c in did.run(mkctx(self.engine, fs, now=NOW + datetime.timedelta(days=200))):
            ch = c["change"]
            if not ch:
                continue
            seen += 1
            if ch["kind"] == "page":
                self.assertIn(f'"{ch["where"]}"', nav, c["id"])
            elif ch["kind"] == "yaml":
                self.assertIn(ch["key"], (REPO_ROOT / ch["where"]).read_text(encoding="utf-8"), c["id"])
        self.assertGreaterEqual(seen, 5)
        for classes in did.LAYER_CLASSES.values():  # every control type named is one the controls inventory accepts
            for cls in classes:
                self.assertIn(cls, controls.control_classes())


if __name__ == "__main__":
    unittest.main()
