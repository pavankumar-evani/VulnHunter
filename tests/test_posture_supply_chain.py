"""Tests for the software supply chain posture framework (remediation/posture/supply_chain.py)."""
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from sqlalchemy import create_engine, insert, update  # noqa: E402

from appsec_fixtures import SBOM, dep_finding  # noqa: E402
from remediation.appsec import store  # noqa: E402
from remediation.posture import engine as posture_engine  # noqa: E402
from remediation.posture import supply_chain  # noqa: E402
from remediation.posture.model import STATUSES, Context  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
ACTOR = "pat.owner@corp.test"
KEYS = {"id", "framework", "area", "title", "status", "score", "weight", "evidence", "detail", "recommendation", "change", "refs", "data_used"}
RECENT, OLD = "2026-09-28T10:00:00Z", "2026-03-01T10:00:00Z"
FLAT_ROOT_ONLY = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "app", "name": "solo", "version": "1.0.0"}},
                  "components": [{"bom-ref": "yaml", "name": "pyyaml", "version": "5.3", "purl": "pkg:pypi/pyyaml@5.3"}],
                  "dependencies": [{"ref": "app", "dependsOn": ["yaml"]}]}
GATE = {"rules": {"sbom": {"title": "sbom"}}, "environments": {"production": {"sbom": "block"}}, "default_environment": "production"}


def make_ctx(engine, findings=(), env=None):
    c = Context(engine=engine, findings=list(findings), env=env if env is not None else {}, now=NOW)
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

    def run_check(self, cid, findings=(), env=None):
        return next(c for c in supply_chain.run(make_ctx(self.engine, findings, env)) if c["id"] == cid)

    def app(self, name, sbom=SBOM, at=RECENT, notes=None):
        store.upsert_application(name, {"environment": "production"}, ACTOR, self.engine)
        if sbom is not None:
            store.set_sbom(name, sbom, "ci", ACTOR, self.engine, notes=notes)
            with self.engine.begin() as conn:
                conn.execute(update(db_module.app_sboms).where(db_module.app_sboms.c.application == name).values(uploaded_at=at))

    def proposal(self, app, finding_ids, status="pr-opened", opened="2026-10-01T00:00:00Z", merged=None, approved_by=None):
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.fix_proposals), {"application": app, "kind": "dependency-upgrade", "finding_ids": json.dumps(finding_ids), "title": "Upgrade", "summary_json": "{}",
                                                           "files_json": "[]", "pr_title": "", "pr_body": "", "status": status, "created_by": ACTOR, "created_at": "2026-09-30T00:00:00Z",
                                                           "opened_at": opened, "merged_at": merged, "approved_by": approved_by})

    def cicd_run(self, asset):
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.scan_runs), {"asset": asset, "scan_type": "cicd", "tool": "quanta", "source": "ci", "findings": 0, "received_at": RECENT, "received_by": ACTOR})


def ci_finding(i, rule, sev, repo):
    return {"id": f"FIND-{i}", "title": rule, "severity": sev, "scan_type": "cicd", "rule_id": rule, "asset": {"name": repo}}


class EmptyAndShapeTests(Base):
    def test_empty_estate_has_no_pass_or_fail(self):
        checks = supply_chain.run(make_ctx(self.engine))
        self.assertTrue(checks)
        self.assertEqual({c["status"] for c in checks} - {"unknown", "na"}, set())

    def test_shape_unique_ids_and_numbers(self):
        self.app("orders")
        self.app("legacy", FLAT_ROOT_ONLY, OLD)
        self.proposal("orders", ["FIND-1"], "merged", merged="2026-10-02T00:00:00Z", approved_by=ACTOR)
        f = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228"), ci_finding(2, "GHA001", "Medium", "orders")]
        with mock.patch.object(supply_chain.gates, "load", return_value=GATE):
            checks = supply_chain.run(make_ctx(self.engine, f))
        ids = [c["id"] for c in checks]
        self.assertEqual(len(ids), len(set(ids)))
        areas = {a for a, _ in supply_chain.FRAMEWORK["areas"]}
        for c in checks:
            self.assertEqual(set(c), KEYS)
            self.assertIn(c["status"], STATUSES)
            self.assertIn(c["area"], areas)
            self.assertEqual(c["framework"], "supply-chain")
            self.assertTrue(any(ch.isdigit() for e in c["evidence"] for ch in e), c["id"])
        self.assertEqual({a for a in areas}, {c["area"] for c in checks})

    def test_deterministic(self):
        self.app("orders")
        self.app("legacy", FLAT_ROOT_ONLY, OLD)
        self.assertEqual(supply_chain.run(make_ctx(self.engine)), supply_chain.run(make_ctx(self.engine)))

    def test_changes_name_real_settings(self):
        self.app("legacy", FLAT_ROOT_ONLY, OLD)
        self.proposal("legacy", ["FIND-1"], approved_by=ACTOR)
        f = [dep_finding(1, "pyyaml", "5.3", "5.4", "CVE-2020-14343", app="legacy"), ci_finding(2, "GHA002", "Critical", "legacy")]
        nav = (REPO_ROOT / "dashboard/static/js/nav.js").read_text(encoding="utf-8")
        gate_off = {"rules": GATE["rules"], "environments": {"production": {"sbom": "off"}}, "default_environment": "production"}
        with mock.patch.object(supply_chain.gates, "load", return_value=gate_off):
            checks = supply_chain.run(make_ctx(self.engine, f, env={"QUANTA_GITOPS_SYNC": "false"}))
        kinds = set()
        for c in checks:
            ch = c["change"]
            if not ch:
                continue
            kinds.add(ch["kind"])
            if ch["kind"] == "yaml":
                self.assertIn(ch["key"], (REPO_ROOT / ch["where"].split(" ")[0]).read_text(encoding="utf-8"))
            elif ch["kind"] == "page":
                self.assertIn(ch["where"], nav)
            elif ch["kind"] == "env":
                self.assertIn(ch["key"], (REPO_ROOT / "dashboard/appsec_api.py").read_text(encoding="utf-8"))
        self.assertTrue({"yaml", "page", "env"} <= kinds)


class InventoryTests(Base):
    def test_sbom_coverage(self):
        self.app("orders")
        self.app("billing", None)
        c = self.run_check("sc-inv-sbom-coverage")
        self.assertEqual((c["status"], c["score"]), ("partial", 0.5))
        self.assertIn("1 of 2", c["evidence"][0])
        self.app("billing")
        self.assertEqual(self.run_check("sc-inv-sbom-coverage")["status"], "pass")
        self.app("a", None)
        self.app("b", None)
        self.app("c", None)
        self.assertEqual(self.run_check("sc-inv-sbom-coverage")["status"], "fail")

    def test_sbom_fresh(self):
        self.app("orders")
        self.assertEqual(self.run_check("sc-inv-sbom-fresh")["status"], "pass")
        self.app("billing", at=OLD)
        self.app("legacy", at=OLD)
        c = self.run_check("sc-inv-sbom-fresh")
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 3", c["evidence"][0])
        self.assertIn("billing", c["evidence"][1])

    def test_unregistered(self):
        self.assertEqual(self.run_check("sc-inv-registered")["status"], "unknown")
        self.app("orders")
        f = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", app="orders")]
        self.assertEqual(self.run_check("sc-inv-registered", f)["status"], "pass")
        f.append(dep_finding(2, "pyyaml", "5.3", "5.4", "CVE-2020-14343", app="ghost-app"))
        self.assertEqual(self.run_check("sc-inv-registered", f)["status"], "partial")


class IntegrityTests(Base):
    def test_transitive(self):
        self.app("orders")
        self.assertEqual(self.run_check("sc-int-transitive")["status"], "pass")
        self.app("solo", FLAT_ROOT_ONLY, notes=["Only declared dependencies were available for at least one file, so transitive dependencies are not in this SBOM."])
        self.assertEqual(self.run_check("sc-int-transitive")["status"], "partial")

    def test_manifest_only_is_partial_not_pass(self):
        self.app("solo", FLAT_ROOT_ONLY)
        c = self.run_check("sc-int-transitive")
        self.assertEqual((c["status"], c["score"]), ("partial", 0.5))

    def test_pinned_actions(self):
        self.assertEqual(self.run_check("sc-int-pinned-actions")["status"], "unknown")
        self.cicd_run("orders-ci")
        self.cicd_run("billing-ci")
        self.assertEqual(self.run_check("sc-int-pinned-actions")["status"], "pass")
        c = self.run_check("sc-int-pinned-actions", [ci_finding(1, "GHA001", "Medium", "orders-ci")])
        self.assertEqual((c["status"], c["score"]), ("partial", 0.5))
        c = self.run_check("sc-int-pinned-actions", [ci_finding(1, "GHA001", "Medium", "orders-ci"), ci_finding(2, "GL001", "Medium", "billing-ci")])
        self.assertEqual(c["status"], "fail")
        self.assertIn("2 of 2", c["evidence"][0])

    def test_token_permissions(self):
        self.cicd_run("orders-ci")
        self.assertEqual(self.run_check("sc-int-token-permissions")["status"], "pass")
        self.assertEqual(self.run_check("sc-int-token-permissions", [ci_finding(1, "GHA004", "Medium", "orders-ci")])["status"], "fail")

    def test_dangerous_workflow_any_is_fail(self):
        self.cicd_run("orders-ci")
        for n in ("b", "c", "d"):
            self.cicd_run(n)
        self.assertEqual(self.run_check("sc-int-dangerous-workflow")["status"], "pass")
        self.assertEqual(self.run_check("sc-int-dangerous-workflow", [ci_finding(1, "GHA002", "Critical", "orders-ci")])["status"], "fail")


class ProvenanceTests(Base):
    def test_slsa_and_signing_never_pass(self):
        self.app("orders")
        for cid in ("sc-prov-build-level", "sc-prov-signed-releases"):
            c = self.run_check(cid)
            self.assertEqual(c["status"], "unknown")
            self.assertIn("SLSA", c["recommendation"])

    def test_stated_state_is_not_evidence(self):
        from remediation.devsecops import controls
        controls.set_state("orders", "artifact-provenance", "implemented", "per the platform team", ACTOR, self.engine)
        c = self.run_check("sc-prov-signed-releases")
        self.assertEqual(c["status"], "unknown")
        self.assertIn("stated by a person", c["evidence"][0])

    def test_gate_sbom(self):
        self.app("orders")
        with mock.patch.object(supply_chain.gates, "load", return_value=GATE):
            self.assertEqual(self.run_check("sc-prov-gate-sbom")["status"], "pass")
        off = {"rules": GATE["rules"], "environments": {"production": {"sbom": "off"}}, "default_environment": "production"}
        with mock.patch.object(supply_chain.gates, "load", return_value=off):
            self.assertEqual(self.run_check("sc-prov-gate-sbom")["status"], "fail")

    def test_gate_sbom_needs_an_estate(self):
        with mock.patch.object(supply_chain.gates, "load", return_value=GATE):
            self.assertEqual(self.run_check("sc-prov-gate-sbom")["status"], "unknown")


class DeliveryTests(Base):
    def test_unproposed(self):
        self.app("orders")
        f = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228"), dep_finding(2, "jackson-databind", "2.12.4", "2.13.0", "CVE-2020-36518")]
        c = self.run_check("sc-del-unproposed", f)
        self.assertEqual(c["status"], "fail")
        self.assertIn("0 of 2", c["evidence"][0])
        self.proposal("orders", ["FIND-1", "FIND-2"])
        self.assertEqual(self.run_check("sc-del-unproposed", f)["status"], "pass")

    def test_unproposed_without_a_fixed_version_is_na(self):
        f = [dep_finding(1, "left-pad", "1.0.0", None, "CVE-2020-0001")]
        self.assertEqual(self.run_check("sc-del-unproposed", f)["status"], "na")

    def test_throughput(self):
        self.assertEqual(self.run_check("sc-del-fix-throughput")["status"], "unknown")
        self.proposal("orders", ["FIND-1"], "merged", merged="2026-10-02T00:00:00Z")
        self.assertEqual(self.run_check("sc-del-fix-throughput")["status"], "pass")
        for i in range(3):
            self.proposal("orders", [f"FIND-{i + 5}"], "closed")
        c = self.run_check("sc-del-fix-throughput")
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 4", c["evidence"][0])

    def test_verified(self):
        self.proposal("orders", ["FIND-1"], "merged", merged="2026-10-02T00:00:00Z")
        self.assertEqual(self.run_check("sc-del-verified", [])["status"], "pass")  # the finding is gone from the latest scan
        still = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", last_seen="2026-10-04")]
        c = self.run_check("sc-del-verified", still)
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 still reported", c["evidence"][0])
        waiting = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", last_seen="2026-09-30")]
        self.assertEqual(self.run_check("sc-del-verified", waiting)["status"], "unknown")

    def test_backlog(self):
        self.assertEqual(self.run_check("sc-del-pr-backlog")["status"], "unknown")
        self.proposal("orders", ["FIND-1"], opened="2026-10-03T00:00:00Z")
        self.assertEqual(self.run_check("sc-del-pr-backlog")["status"], "pass")
        self.proposal("orders", ["FIND-2"], opened="2026-07-01T00:00:00Z")
        self.assertEqual(self.run_check("sc-del-pr-backlog")["status"], "partial")

    def test_sync_flag(self):
        self.app("orders")
        self.assertEqual(self.run_check("sc-del-pr-sync")["status"], "pass")
        c = self.run_check("sc-del-pr-sync", env={"QUANTA_GITOPS_SYNC": "false"})
        self.assertEqual(c["status"], "fail")
        self.assertEqual(c["change"]["key"], "QUANTA_GITOPS_SYNC")

    def test_distinct_approver(self):
        self.proposal("orders", ["FIND-1"], approved_by=ACTOR)
        c = self.run_check("sc-del-distinct-approver")
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 of 1", c["evidence"][0])
        self.proposal("orders", ["FIND-2"])
        with self.engine.begin() as conn:
            conn.execute(db_module.fix_proposals.update().values(approved_by="sam.lead@corp.test"))
        policy = {"approval": {"require_distinct_approver": True}}
        with mock.patch.object(supply_chain.gitops_policy, "load", return_value=policy):
            self.assertEqual(self.run_check("sc-del-distinct-approver")["status"], "pass")


if __name__ == "__main__":
    unittest.main()
