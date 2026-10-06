"""Tests for the open source dependency posture framework (remediation/posture/open_source.py)."""
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from sqlalchemy import create_engine, insert  # noqa: E402

from appsec_fixtures import SBOM, dep_finding  # noqa: E402
from remediation.appsec import store  # noqa: E402
from remediation.posture import engine as posture_engine  # noqa: E402
from remediation.posture import open_source  # noqa: E402
from remediation.posture.model import STATUSES, Context  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
ACTOR = "pat.owner@corp.test"
KEYS = {"id", "framework", "area", "title", "status", "score", "weight", "evidence", "detail", "recommendation", "change", "refs", "data_used"}
LOG4J = ("log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228")
JACKSON = ("jackson-databind", "2.12.4", "2.13.0", "CVE-2020-36518")


def make_ctx(engine, findings=()):
    c = Context(engine=engine, findings=list(findings), env={}, now=NOW)
    c.policy = posture_engine.policy()
    c.thr = c.policy["thresholds"]
    return c


def finding(i, spec, **kw):
    kw.setdefault("first_seen", "2026-10-01")
    return dep_finding(i, *spec, **kw)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def run_check(self, cid, findings=()):
        return next(c for c in open_source.run(make_ctx(self.engine, findings)) if c["id"] == cid)

    def sca_scan(self):
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.scan_runs), {"asset": "orders", "scan_type": "sca", "tool": "grype", "source": "ci", "findings": 0, "received_at": "2026-10-01T00:00:00Z", "received_by": ACTOR})

    def app(self, name, sbom=SBOM):
        store.upsert_application(name, {}, ACTOR, self.engine)
        store.set_sbom(name, sbom, "ci", ACTOR, self.engine)

    def proposal(self, ids, status="pr-opened"):
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.fix_proposals), {"application": "orders", "kind": "dependency-upgrade", "finding_ids": json.dumps(ids), "title": "t", "summary_json": "{}", "files_json": "[]",
                                                           "pr_title": "", "pr_body": "", "status": status, "created_by": ACTOR, "created_at": "2026-10-01T00:00:00Z"})


class EmptyAndShapeTests(Base):
    def test_empty_estate_has_no_pass_or_fail(self):
        checks = open_source.run(make_ctx(self.engine))
        self.assertEqual(len(checks), 12)
        self.assertEqual({c["status"] for c in checks} - {"unknown", "na"}, set())

    def test_shape_unique_ids_and_numbers(self):
        self.app("orders")
        f = [finding(1, LOG4J, sev="Critical", kev=True, epss=0.9), finding(2, JACKSON, sev="High")]
        checks = open_source.run(make_ctx(self.engine, f))
        ids = [c["id"] for c in checks]
        self.assertEqual(len(ids), len(set(ids)))
        areas = {a for a, _ in open_source.FRAMEWORK["areas"]}
        self.assertEqual(areas, {c["area"] for c in checks})
        for c in checks:
            self.assertEqual(set(c), KEYS)
            self.assertIn(c["status"], STATUSES)
            self.assertEqual(c["framework"], "open-source")
            self.assertTrue(any(ch.isdigit() for e in c["evidence"] for ch in e), c["id"])

    def test_deterministic(self):
        self.app("orders")
        f = [finding(1, LOG4J, sev="Critical", kev=True), finding(2, JACKSON, sev="High", epss=0.7)]
        self.assertEqual(open_source.run(make_ctx(self.engine, f)), open_source.run(make_ctx(self.engine, f)))

    def test_changes_name_real_pages(self):
        nav = (REPO_ROOT / "dashboard/static/js/nav.js").read_text(encoding="utf-8")
        self.app("orders")
        f = [finding(1, LOG4J, sev="Critical", kev=True, first_seen="2026-08-01", epss=0.9), finding(2, LOG4J[:3] + ("CVE-2021-45046",), sev="High", first_seen="2026-08-01")]
        seen = 0
        for c in open_source.run(make_ctx(self.engine, f)):
            if c["change"]:
                seen += 1
                self.assertEqual(c["change"]["kind"], "page")
                self.assertIn(c["change"]["where"], nav)
        self.assertGreater(seen, 3)

    def test_unobservable_checks_never_pass(self):
        self.sca_scan()
        self.app("orders")
        for cid in ("os-hyg-eol", "os-disclosure-feed"):
            self.assertEqual(self.run_check(cid)["status"], "unknown")
        c = self.run_check("os-disclosure-feed")
        self.assertIn("once it is available", c["recommendation"])
        self.assertIn("coordinated disclosure feed", c["recommendation"])


class ExposureTests(Base):
    def test_severity_good_partial_bad(self):
        self.sca_scan()
        self.assertEqual(self.run_check("os-exp-severity")["status"], "pass")
        self.assertEqual(self.run_check("os-exp-severity", [finding(1, JACKSON, sev="Medium")])["status"], "pass")
        c = self.run_check("os-exp-severity", [finding(1, JACKSON, sev="High")])
        self.assertEqual((c["status"], c["score"]), ("partial", 0.5))
        c = self.run_check("os-exp-severity", [finding(1, LOG4J, sev="Critical"), finding(2, JACKSON, sev="High")])
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 Critical, 1 High", c["evidence"][0])

    def test_direct_transitive(self):
        self.app("orders")
        self.assertEqual(self.run_check("os-exp-direct-transitive", [finding(1, JACKSON)])["status"], "pass")
        c = self.run_check("os-exp-direct-transitive", [finding(1, JACKSON), finding(2, LOG4J)])
        self.assertEqual((c["status"], c["score"]), ("partial", 0.5))
        self.assertIn("1 of 2", c["evidence"][0])

    def test_direct_transitive_unknown_without_graph(self):
        self.assertEqual(self.run_check("os-exp-direct-transitive", [finding(1, JACKSON)])["status"], "unknown")

    def test_concentration(self):
        self.app("orders")
        self.app("billing")
        solo = [finding(1, LOG4J, app="orders"), finding(2, JACKSON, app="billing")]
        self.assertEqual(self.run_check("os-exp-concentration", solo)["status"], "pass")
        shared = [finding(1, LOG4J, app="orders"), finding(2, LOG4J, app="billing"), finding(3, JACKSON, app="billing")]
        c = self.run_check("os-exp-concentration", shared)
        self.assertEqual((c["status"], c["score"]), ("partial", 0.5))
        self.assertIn("1 of 2", c["evidence"][0])


class ExploitationTests(Base):
    def test_kev_good_partial_bad(self):
        self.sca_scan()
        self.assertEqual(self.run_check("os-expl-kev", [finding(1, LOG4J)])["status"], "pass")
        self.assertEqual(self.run_check("os-expl-kev", [finding(1, LOG4J, kev=True, first_seen="2026-10-04")])["status"], "partial")
        c = self.run_check("os-expl-kev", [finding(1, LOG4J, kev=True, first_seen="2026-08-04")])
        self.assertEqual(c["status"], "fail")
        self.assertIn("FIND-1", c["evidence"][-1])

    def test_epss(self):
        self.sca_scan()
        self.assertEqual(self.run_check("os-expl-epss", [finding(1, LOG4J)])["status"], "pass")
        c = self.run_check("os-expl-epss", [finding(1, LOG4J, epss=0.95)])
        self.assertEqual(c["status"], "fail")
        no_epss = finding(1, LOG4J)
        no_epss["epss"] = None
        self.assertEqual(self.run_check("os-expl-epss", [no_epss])["status"], "unknown")


class RemediationTests(Base):
    def test_fix_available(self):
        self.sca_scan()
        self.assertEqual(self.run_check("os-rem-fix-available", [finding(1, LOG4J), finding(2, JACKSON)])["status"], "pass")
        none_fixed = [finding(1, ("left-pad", "1.0.0", None, "CVE-2020-0001")), finding(2, ("is-odd", "1.0.0", None, "CVE-2020-0002")), finding(3, JACKSON)]
        c = self.run_check("os-rem-fix-available", none_fixed)
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 3", c["evidence"][0])

    def test_overdue(self):
        self.sca_scan()
        self.assertEqual(self.run_check("os-rem-overdue", [finding(1, LOG4J, sev="High", first_seen="2026-10-01")])["status"], "pass")
        c = self.run_check("os-rem-overdue", [finding(1, LOG4J, sev="High", first_seen="2026-07-01")])
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 1", c["evidence"][0])
        nodate = finding(1, LOG4J, sev="High")
        nodate["first_seen"] = None
        self.assertEqual(self.run_check("os-rem-overdue", [nodate])["status"], "fail")

    def test_multi_upgrade(self):
        self.sca_scan()
        two = [finding(1, LOG4J), finding(2, LOG4J[:3] + ("CVE-2021-45046",))]
        self.assertEqual(self.run_check("os-rem-multi-upgrade", [finding(1, LOG4J)])["status"], "na")
        c = self.run_check("os-rem-multi-upgrade", two)
        self.assertEqual(c["status"], "fail")
        self.assertIn("log4j-core closes 2 findings", c["evidence"][1])
        self.proposal(["FIND-1", "FIND-2"])
        self.assertEqual(self.run_check("os-rem-multi-upgrade", two)["status"], "pass")


class HygieneTests(Base):
    def test_sbom_present(self):
        self.app("orders")
        f = [finding(1, LOG4J, app="orders")]
        self.assertEqual(self.run_check("os-hyg-sbom-present", f)["status"], "pass")
        f += [finding(2, JACKSON, app="ghost-a"), finding(3, JACKSON, app="ghost-b")]
        c = self.run_check("os-hyg-sbom-present", f)
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 3", c["evidence"][0])

    def test_sbom_match(self):
        self.app("orders")
        self.assertEqual(self.run_check("os-hyg-sbom-match", [finding(1, LOG4J), finding(2, JACKSON)])["status"], "pass")
        odd = [finding(1, LOG4J), finding(2, ("not-in-sbom", "1.0", "2.0", "CVE-2020-0003")), finding(3, ("also-missing", "1.0", "2.0", "CVE-2020-0004"))]
        c = self.run_check("os-hyg-sbom-match", odd)
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 3", c["evidence"][0])

    def test_sbom_match_needs_an_sbom(self):
        self.assertEqual(self.run_check("os-hyg-sbom-match", [finding(1, LOG4J)])["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
