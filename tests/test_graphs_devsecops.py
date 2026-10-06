"""Tests for the portfolio supply-chain graph (remediation/graphs/devsecops.py)."""
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
from remediation.graphs import devsecops  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

SOLO_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "app", "name": "solo", "version": "1.0.0"}},
             "components": [{"bom-ref": "yaml", "name": "pyyaml", "version": "5.3", "purl": "pkg:pypi/pyyaml@5.3"},
                            {"bom-ref": "req", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}],
             "dependencies": [{"ref": "app", "dependsOn": ["yaml", "req"]}]}


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def add(self, name, sbom=SBOM):
        store.upsert_application(name, {"environment": "production", "team": "web"}, "pat.owner@corp.test", self.engine)
        store.set_sbom(name, sbom, "ci", "pat.owner@corp.test", self.engine)

    def ids(self, g, kind):
        return {n["id"] for n in g["nodes"] if n["kind"] == kind}

    def test_empty_state_note(self):
        g = devsecops.build(engine=self.engine, findings=[])
        self.assertEqual(g["nodes"], [])
        self.assertIn("Register applications", g["note"])

    def test_apps_without_sbom_note(self):
        store.upsert_application("orders", {}, "pat.owner@corp.test", self.engine)
        g = devsecops.build(engine=self.engine)
        self.assertIn("SBOM", g["note"])
        self.assertEqual(self.ids(g, "application"), {"app:orders"})

    def test_shared_vulnerable_package_links_both_apps(self):
        self.add("orders")
        self.add("billing")
        findings = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", sev="Critical", app="orders"),
                    dep_finding(2, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", sev="High", app="billing")]
        g = devsecops.build(engine=self.engine, findings=findings)
        pkg = next(n for n in g["nodes"] if n["kind"] == "package" and n["label"].endswith("log4j-core"))
        self.assertEqual(pkg["weight"], 2)
        self.assertEqual(pkg["sev"], "critical")
        uses = {(e["source"], e["target"]) for e in g["edges"] if e["kind"] == "uses"}
        self.assertIn(("app:orders", pkg["id"]), uses)
        self.assertIn(("app:billing", pkg["id"]), uses)
        by_id = {n["id"]: n for n in g["nodes"]}
        self.assertEqual(by_id["app:orders"]["sev"], "critical")
        self.assertEqual(by_id["app:billing"]["sev"], "high")
        # the direct parent of the transitive vulnerable package is linked to it
        self.assertTrue(any(e["kind"] == "depends_on" and e["target"] == pkg["id"] for e in g["edges"]))

    def test_vulnerable_package_in_one_app_appears_but_clean_ones_do_not(self):
        self.add("solo", SOLO_SBOM)
        findings = [dep_finding(3, "pyyaml", "5.3", "5.4", "CVE-2020-14343", sev="Medium", app="solo")]
        findings[0]["dependency"]["ecosystem"] = "pypi"
        g = devsecops.build(engine=self.engine, findings=findings)
        labels = {n["label"] for n in g["nodes"] if n["kind"] == "package"}
        self.assertEqual(labels, {"pyyaml"})
        self.assertEqual(self.ids(g, "application"), {"app:solo"})

    def test_proposal_links_package_and_application(self):
        self.add("solo", SOLO_SBOM)
        findings = [dep_finding(3, "pyyaml", "5.3", "5.4", "CVE-2020-14343", app="solo")]
        findings[0]["dependency"]["ecosystem"] = "pypi"
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.fix_proposals), {
                "application": "solo", "kind": "dependency-upgrade", "finding_ids": json.dumps(["FIND-3"]), "title": "Upgrade pyyaml to 5.4",
                "summary_json": json.dumps({"package": "pyyaml", "from": "5.3", "to": "5.4"}), "files_json": "[]", "pr_title": "", "pr_body": "",
                "status": "draft", "created_by": "pat.owner@corp.test", "created_at": "2026-10-01T00:00:00Z"})
        g = devsecops.build(engine=self.engine, findings=findings)
        prop = [n for n in g["nodes"] if n["kind"] == "proposal"]
        self.assertEqual(len(prop), 1)
        self.assertEqual(prop[0]["meta"]["status"], "draft")
        kinds = {(e["kind"], e["target"]) for e in g["edges"] if e["source"] == prop[0]["id"]}
        self.assertIn(("for", "app:solo"), kinds)
        self.assertTrue(any(k == "fixes" for k, _ in kinds))

    def test_deterministic(self):
        self.add("orders")
        self.add("billing")
        findings = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", app="orders")]
        self.assertEqual(devsecops.build(engine=self.engine, findings=findings), devsecops.build(engine=self.engine, findings=findings))


if __name__ == "__main__":
    unittest.main()
