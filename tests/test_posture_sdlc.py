"""Tests for the SSDF posture framework (remediation/posture/sdlc.py)."""
import datetime
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine, insert  # noqa: E402

from remediation.appsec import store as appsec_store  # noqa: E402
from remediation.posture import engine as posture_engine  # noqa: E402
from remediation.posture import sdlc  # noqa: E402
from remediation.posture.model import STATUSES, Context  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
ACTOR = "pat.owner@corp.test"
KEYS = {"id", "framework", "area", "title", "status", "score", "weight", "evidence", "detail", "recommendation", "change", "refs", "data_used"}
RECENT, OLD = "2026-09-28T10:00:00Z", "2026-03-01T10:00:00Z"

ALL_ON = {"rules": {r: {"title": r} for r in sdlc.GATE_RULES}, "environments": {"production": {r: "block" for r in sdlc.GATE_RULES}}, "default_environment": "production"}
ALL_OFF = {"rules": ALL_ON["rules"], "environments": {"production": {r: "off" for r in sdlc.GATE_RULES}}, "default_environment": "production"}


def make_ctx(engine, findings=()):
    c = Context(engine=engine, findings=list(findings), env={}, now=NOW)
    c.policy = posture_engine.policy()
    c.thr = c.policy["thresholds"]
    return c


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def run_check(self, cid, findings=()):
        checks = sdlc.run(make_ctx(self.engine, findings))
        return next(c for c in checks if c["id"] == cid)

    def scan(self, asset, scan_type, at=RECENT):
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.scan_runs), {"asset": asset, "scan_type": scan_type, "tool": "semgrep", "source": "ci", "findings": 0, "received_at": at, "received_by": ACTOR})

    def gate(self, app, decision, env="production", at=RECENT):
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.gate_runs), {"application": app, "environment": env, "decision": decision, "detail_json": json.dumps({"rules": [], "policy_version": "x"}),
                                                       "evaluated_by": ACTOR, "evaluated_at": at})


class EmptyAndShapeTests(Base):
    def test_empty_estate_has_no_pass_or_fail(self):
        checks = sdlc.run(make_ctx(self.engine))
        self.assertTrue(checks)
        self.assertEqual({c["status"] for c in checks} - {"unknown", "na"}, set())

    def test_every_check_is_well_formed_and_unique(self):
        self.scan("shop-web", "sast")
        checks = sdlc.run(make_ctx(self.engine, [{"id": "F1", "severity": "Critical", "scan_type": "sast", "first_seen": "2026-08-01", "asset": {"name": "shop-web"}}]))
        ids = [c["id"] for c in checks]
        self.assertEqual(len(ids), len(set(ids)))
        areas = {a for a, _ in sdlc.FRAMEWORK["areas"]}
        for c in checks:
            self.assertEqual(set(c), KEYS)
            self.assertIn(c["status"], STATUSES)
            self.assertIn(c["area"], areas)
            self.assertTrue(c["evidence"], c["id"])
            self.assertTrue(any(ch.isdigit() for e in c["evidence"] for ch in e), c["id"])

    def test_deterministic(self):
        self.scan("shop-web", "sast")
        self.gate("shop-web", "fail")
        a, b = sdlc.run(make_ctx(self.engine)), sdlc.run(make_ctx(self.engine))
        self.assertEqual(a, b)

    def test_changes_name_real_settings(self):
        self.scan("shop-web", "sast", OLD)
        self.gate("shop-web", "fail")
        findings = [{"id": "F1", "severity": "Critical", "scan_type": "sast", "first_seen": "2026-08-01", "asset": {"name": "shop-web"}}]
        nav = (REPO_ROOT / "dashboard/static/js/nav.js").read_text(encoding="utf-8")
        with mock.patch.object(sdlc.gates, "load", return_value=ALL_OFF):
            checks = sdlc.run(make_ctx(self.engine, findings))
        seen = 0
        for c in checks:
            ch = c["change"]
            if not ch:
                continue
            seen += 1
            if ch["kind"] == "yaml":
                path = ch["where"].split(" ")[0]
                self.assertIn(ch["key"], (REPO_ROOT / path).read_text(encoding="utf-8"))
            elif ch["kind"] == "page":
                self.assertIn(ch["where"], nav)
        self.assertGreater(seen, 3)


class ScanRecencyTests(Base):
    def test_sast_good_and_bad(self):
        self.scan("shop-web", "sast")
        self.assertEqual(self.run_check("sdlc-pw-sast-recent")["status"], "pass")
        self.scan("legacy-batch", "sast", OLD)
        self.scan("old-portal", "sast", OLD)
        c = self.run_check("sdlc-pw-sast-recent")
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 3", c["evidence"][0])
        self.assertIn("legacy-batch", c["evidence"][1])

    def test_sast_partial(self):
        self.scan("shop-web", "sast")
        self.scan("legacy-batch", "sast", OLD)
        c = self.run_check("sdlc-pw-sast-recent")
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["score"], 0.5)

    def test_secrets_missing_is_a_fail(self):
        self.scan("shop-web", "sast")
        self.assertEqual(self.run_check("sdlc-ps-secrets-scanning")["status"], "fail")
        self.scan("shop-web", "secrets")
        self.assertEqual(self.run_check("sdlc-ps-secrets-scanning")["status"], "pass")


class StageControlTests(Base):
    def test_test_stage_good_and_bad(self):
        self.scan("shop-web", "sast")
        bad = self.run_check("sdlc-pw-test-controls")
        self.assertEqual(bad["status"], "fail")
        for t in ("dast", "api-test", "coverage"):
            self.scan("shop-web", t)
        self.assertEqual(self.run_check("sdlc-pw-test-controls")["status"], "pass")

    def test_operate_stage_is_not_observable(self):
        self.scan("shop-web", "sast")
        c = self.run_check("sdlc-rv-operate-controls")
        self.assertEqual(c["status"], "unknown")

    def test_threat_models(self):
        self.scan("shop-web", "sast")
        self.assertEqual(self.run_check("sdlc-po-threat-models")["status"], "fail")
        from remediation.threatmodel import store as tm_store
        tm_store.create("Shop", "", {"components": [{"id": "web", "name": "Web", "type": "service"}], "data_flows": [], "trust_zones": []}, ACTOR, engine=self.engine)
        self.assertEqual(self.run_check("sdlc-po-threat-models")["status"], "pass")


class GateTests(Base):
    def test_gate_policy_good_and_bad(self):
        self.scan("shop-web", "sast")
        with mock.patch.object(sdlc.gates, "load", return_value=ALL_ON):
            self.assertEqual(self.run_check("sdlc-po-gate-policy")["status"], "pass")
        with mock.patch.object(sdlc.gates, "load", return_value=ALL_OFF):
            c = self.run_check("sdlc-po-gate-policy")
        self.assertEqual(c["status"], "fail")
        self.assertIn("0 of 6", c["evidence"][0])

    def test_gate_policy_needs_an_estate(self):
        with mock.patch.object(sdlc.gates, "load", return_value=ALL_ON):
            self.assertEqual(self.run_check("sdlc-po-gate-policy")["status"], "unknown")

    def test_gate_used(self):
        appsec_store.upsert_application("orders", {}, ACTOR, self.engine)
        appsec_store.upsert_application("billing", {}, ACTOR, self.engine)
        self.assertEqual(self.run_check("sdlc-pw-gate-used")["status"], "fail")
        self.gate("orders", "pass")
        self.gate("billing", "pass")
        self.assertEqual(self.run_check("sdlc-pw-gate-used")["status"], "pass")

    def test_gate_latest(self):
        self.gate("orders", "pass")
        self.assertEqual(self.run_check("sdlc-pw-gate-latest")["status"], "pass")
        self.gate("orders", "fail")
        c = self.run_check("sdlc-pw-gate-latest")
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 1", c["evidence"][0])

    def test_override_is_never_a_pass(self):
        self.gate("orders", "pass")
        self.assertEqual(self.run_check("sdlc-pw-gate-override")["status"], "unknown")


class RespondTests(Base):
    def finding(self, i, sev, first_seen, scan_type="sast"):
        return {"id": f"FIND-{i}", "title": "Finding", "severity": sev, "scan_type": scan_type, "first_seen": first_seen, "asset": {"name": "shop-web"}}

    def test_critical_code_open(self):
        self.scan("shop-web", "sast")
        self.assertEqual(self.run_check("sdlc-rv-critical-code-open")["status"], "pass")
        self.assertEqual(self.run_check("sdlc-rv-critical-code-open", [self.finding(1, "Critical", "2026-10-01")])["status"], "partial")
        c = self.run_check("sdlc-rv-critical-code-open", [self.finding(1, "Critical", "2026-08-01")])
        self.assertEqual(c["status"], "fail")
        self.assertIn("FIND-1", c["evidence"][-1])

    def test_pipeline_findings(self):
        self.assertEqual(self.run_check("sdlc-ps-pipeline-findings")["status"], "unknown")
        self.scan("shop-web", "cicd")
        self.assertEqual(self.run_check("sdlc-ps-pipeline-findings")["status"], "pass")
        bad = {"id": "FIND-9", "severity": "Critical", "scan_type": "cicd", "rule_id": "GHA002", "asset": {"name": "shop-web"}}
        self.assertEqual(self.run_check("sdlc-ps-pipeline-findings", [bad])["status"], "fail")

    def test_queue_age(self):
        self.assertEqual(self.run_check("sdlc-rv-fix-queue-age")["status"], "unknown")
        findings = [self.finding(1, "High", "2026-09-01")]
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.remediation_factory), {"finding_id": "FIND-1", "state": "queued", "notes": "", "queued_by": ACTOR, "queued_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z"})
        self.assertEqual(self.run_check("sdlc-rv-fix-queue-age", findings)["status"], "pass")
        with self.engine.begin() as conn:
            conn.execute(db_module.remediation_factory.update().values(queued_at="2026-06-01T00:00:00Z"))
        c = self.run_check("sdlc-rv-fix-queue-age", findings)
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 1", c["evidence"][0])

    def test_fix_speed(self):
        self.assertEqual(self.run_check("sdlc-rv-fix-speed")["status"], "unknown")
        findings = [self.finding(1, "High", "2026-09-30")]

        def prop(opened):
            with self.engine.begin() as conn:
                conn.execute(insert(db_module.fix_proposals), {"application": "shop-web", "kind": "dependency-upgrade", "finding_ids": json.dumps(["FIND-1"]), "title": "t", "summary_json": "{}",
                                                               "files_json": "[]", "pr_title": "", "pr_body": "", "status": "pr-opened", "created_by": ACTOR, "created_at": "2026-09-30T00:00:00Z",
                                                               "opened_at": opened})
        prop("2026-10-02T00:00:00Z")
        self.assertEqual(self.run_check("sdlc-rv-fix-speed", findings)["status"], "pass")
        with self.engine.begin() as conn:
            conn.execute(db_module.fix_proposals.delete())
        prop("2027-02-01T00:00:00Z")
        self.assertEqual(self.run_check("sdlc-rv-fix-speed", findings)["status"], "fail")


if __name__ == "__main__":
    unittest.main()
