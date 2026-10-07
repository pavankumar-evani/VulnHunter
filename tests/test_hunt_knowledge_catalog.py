"""Hunting knowledge catalog: the builder (offline, on a tiny STIX fixture), the shipped files' schema and joins, the loader, search, matrices, renamed ids. No network."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.hunting.knowledge import catalog  # noqa: E402

_spec = importlib.util.spec_from_file_location("build_hunt_knowledge", REPO_ROOT / "scripts" / "build_hunt_knowledge.py")
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)


def stix():
    def ref(i):
        return [{"source_name": "mitre-attack", "external_id": i}]
    objs = [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "name": "Enterprise ATT&CK", "x_mitre_version": "99.1", "modified": "2026-01-01T00:00:00Z", "x_mitre_attack_spec_version": "3.3.0"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Execution", "x_mitre_shortname": "execution", "external_references": ref("TA0002"), "description": "Run code."},
        {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "tactic_refs": ["x-mitre-tactic--1"]},
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Command Interpreter", "external_references": ref("T9001"), "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
         "x_mitre_platforms": ["Windows"], "description": "Adversaries may abuse interpreters.(Citation: X) See [the docs](https://example.org). Second sentence here.\n\nSecond paragraph that is dropped."},
        {"type": "attack-pattern", "id": "attack-pattern--2", "name": "PowerShell", "external_references": ref("T9001.001"), "kill_chain_phases": [{"phase_name": "execution"}], "x_mitre_is_subtechnique": True,
         "x_mitre_platforms": ["Windows"], "description": "PowerShell."},
        {"type": "attack-pattern", "id": "attack-pattern--3", "name": "Old Name", "external_references": ref("T9002"), "revoked": True, "description": "x"},
        {"type": "attack-pattern", "id": "attack-pattern--4", "name": "Deprecated", "external_references": ref("T9003"), "x_mitre_deprecated": True, "description": "x"},
        {"type": "x-mitre-data-component", "id": "x-mitre-data-component--1", "name": "Process Creation"},
        {"type": "x-mitre-analytic", "id": "x-mitre-analytic--1", "description": "Look for encoded commands.", "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "x-mitre-data-component--1"}]},
        {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--1", "name": "Interpreter abuse", "x_mitre_analytic_refs": ["x-mitre-analytic--1"]},
        {"type": "course-of-action", "id": "course-of-action--1", "name": "Execution Prevention", "external_references": ref("M9001"), "description": "Prevent."},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "GroupOne", "aliases": ["GroupOne", "Alias1"], "external_references": ref("G9001"), "description": "A group."},
        {"type": "malware", "id": "malware--1", "name": "Implant", "x_mitre_aliases": ["Implant", "ImpAlias"], "external_references": ref("S9001"), "x_mitre_platforms": ["Windows"], "description": "An implant."},
        {"type": "tool", "id": "tool--1", "name": "Scanner", "external_references": ref("S9002"), "description": "A tool."},
    ]
    rel = [("detects", "x-mitre-detection-strategy--1", "attack-pattern--1"), ("mitigates", "course-of-action--1", "attack-pattern--1"), ("uses", "intrusion-set--1", "attack-pattern--1"),
           ("uses", "intrusion-set--1", "malware--1"), ("uses", "malware--1", "attack-pattern--2"), ("uses", "tool--1", "attack-pattern--1"), ("revoked-by", "attack-pattern--3", "attack-pattern--1")]
    for i, (k, s, t) in enumerate(rel):
        objs.append({"type": "relationship", "id": f"relationship--{i}", "relationship_type": k, "source_ref": s, "target_ref": t})
    return {"type": "bundle", "objects": objs}


ATLAS = {"id": "ATLAS", "name": "Test ATLAS", "version": "9.9.9", "matrices": [{"id": "m", "name": "m", "tactics": [{"id": "AML.TA0005", "name": "Execution", "description": "x"}],
         "techniques": [{"id": "AML.T0900", "name": "Prompt thing", "tactics": ["AML.TA0005"], "description": "Bad prompts."}, {"id": "AML.T0900.000", "name": "Direct", "subtechnique-of": "AML.T0900", "tactics": ["AML.TA0005"], "description": "d"}],
         "mitigations": [{"id": "AML.M0900", "name": "Guard", "description": "g", "techniques": [{"id": "AML.T0900", "use": "u"}]}]}],
         "case-studies": [{"id": "AML.CS0900", "name": "A case", "summary": "s", "incident-date": "2024-01-01", "procedure": [{"tactic": "AML.TA0005", "technique": "AML.T0900", "description": "d"}]}]}


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        out, manifest = builder.build({"enterprise": stix(), "atlas": ATLAS}, retrieved="2026-10-07")
        builder.write(out, manifest, Path(self.tmp.name))
        catalog.reload()
        self.c = catalog.Catalog(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_trim_keeps_first_paragraph_and_drops_citations_and_links(self):
        t = builder.trim("Adversaries may abuse interpreters.(Citation: X) See [the docs](https://example.org). Second.\n\nGone.", 300)
        self.assertEqual(t, "Adversaries may abuse interpreters. See the docs. Second.")
        self.assertLessEqual(len(builder.trim("word " * 200, 100)), 104)

    def test_revoked_and_deprecated_are_dropped_and_old_ids_resolve(self):
        self.assertIsNone(self.c.technique("T9002", detail=False))
        self.assertIsNone(self.c.technique("T9003", detail=False))
        self.assertEqual(self.c.resolve("T9002"), "T9001")      # the revoked id points at its successor
        self.assertIsNone(self.c.resolve("T0000"))

    def test_joins_detection_and_mitigations(self):
        t = self.c.technique("T9001")
        self.assertEqual(t["mitigations"], ["M9001"])
        self.assertEqual(t["data_sources"], ["Process Creation"])
        self.assertTrue(t["detection"][0].startswith("Interpreter abuse: Look for encoded commands"))
        self.assertEqual([g["id"] for g in t["groups"]], ["G9001"])
        self.assertEqual({s["id"] for s in t["software"]}, {"S9002"})
        self.assertEqual([s["id"] for s in t["subtechniques"]], ["T9001.001"])
        grp = self.c.group("Alias1")
        self.assertEqual(grp["id"], "G9001")
        self.assertEqual(grp["software"], ["S9001"])
        sw = self.c.software_item("ImpAlias")
        self.assertEqual(sw["techniques"], ["T9001.001"])
        self.assertEqual([g["id"] for g in sw["groups"]], ["G9001"])

    def test_atlas_techniques_tactics_mitigations_and_case_studies(self):
        t = self.c.technique("AML.T0900")
        self.assertEqual(t["framework"], "atlas")
        self.assertEqual(t["mitigations"], ["AML.M0900"])
        self.assertEqual(t["case_studies"], ["AML.CS0900"])
        self.assertEqual([s["id"] for s in t["subtechniques"]], ["AML.T0900.000"])
        m = self.c.matrix("atlas")
        self.assertEqual(m["tactics"][0]["techniques"][0]["id"], "AML.T0900")
        self.assertEqual(m["version"] if "version" in m else "9.9.9", "9.9.9")

    def test_manifest_records_sources_versions_and_date(self):
        mf = json.loads((Path(self.tmp.name) / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(mf["retrieved"], "2026-10-07")
        self.assertEqual(mf["sources"]["enterprise"]["version"], "99.1")
        self.assertTrue(mf["sources"]["enterprise"]["url"].startswith("https://"))
        self.assertEqual(mf["sources"]["atlas"]["version"], "9.9.9")
        self.assertFalse(mf["seed"])

    def test_a_missing_catalog_is_empty_and_says_so_never_filled(self):
        with tempfile.TemporaryDirectory() as d:
            c = catalog.Catalog(d)
            self.assertFalse(c.available)
            self.assertEqual((c.techniques, c.groups, c.software), ({}, {}, {}))
            self.assertEqual(c.search("anything"), [])

    def test_offline_cli_refuses_to_write_a_partial_catalog(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
            rc = builder.main(["--from-dir", src, "--out", out])
            self.assertEqual(rc, 2)
            self.assertEqual(list(Path(out).iterdir()), [])


class ShippedCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        catalog.reload()
        cls.c = catalog.get()

    def test_shipped_files_are_present_and_small(self):
        data = REPO_ROOT / "remediation" / "hunting" / "knowledge" / "data"
        total = sum(p.stat().st_size for p in data.iterdir())
        self.assertLess(total, 2 * 1024 * 1024)
        self.assertTrue(self.c.available)
        mf = json.loads((data / "manifest.json").read_text(encoding="utf-8"))
        for fw in ("enterprise", "mobile", "ics", "atlas"):
            self.assertIn(fw, mf["sources"])
            self.assertTrue(mf["sources"][fw]["version"])
        self.assertFalse(mf["seed"])

    def test_every_framework_has_a_matrix_with_techniques(self):
        names = {f["id"] for f in self.c.frameworks()}
        self.assertEqual(names, {"enterprise", "mobile", "ics", "atlas"})
        for fw in names:
            m = self.c.matrix(fw)
            self.assertTrue(m["tactics"])
            self.assertGreater(m["counts"]["techniques"], 20)
            self.assertTrue(any(col["techniques"] for col in m["tactics"]))

    def test_record_schema(self):
        for t in list(self.c.techniques.values())[:2000]:
            for k in ("id", "name", "framework", "tactics", "description"):
                self.assertIn(k, t, t["id"])
            self.assertTrue(catalog.is_technique_id(t["id"]), t["id"])
        for g in self.c.groups.values():
            self.assertTrue(g["id"].startswith("G") and g["name"] and isinstance(g["techniques"], list))
        for s in self.c.software.values():
            self.assertIn(s["type"], ("malware", "tool"))
        self.assertGreater(len(self.c.groups), 100)
        self.assertGreater(len(self.c.software), 500)
        self.assertGreater(len(self.c.case_studies), 20)

    def test_group_and_software_techniques_resolve_to_catalog_techniques(self):
        missing = 0
        total = 0
        for g in self.c.groups.values():
            for t in g["techniques"]:
                total += 1
                missing += 0 if self.c.exists(t) else 1
        self.assertGreater(total, 1000)
        self.assertLess(missing / total, 0.02)   # a group may cite a technique outside the domains shipped; the joins are otherwise intact

    def test_parent_ids_and_related_leads_handle_atlas_and_sub_techniques(self):
        self.assertEqual(catalog.parent_id("t1059.001"), "T1059")
        self.assertEqual(catalog.parent_id("AML.T0051.001"), "AML.T0051")
        self.assertEqual(catalog.parent_id("AML.T0051"), "AML.T0051")      # never the bare "AML" prefix
        self.assertTrue(catalog.related("T1558.003", ["T1558.003"]))
        self.assertTrue(catalog.related("T1558", ["T1558.003"]))
        self.assertTrue(catalog.related("T1558.003", ["T1558"]))
        self.assertFalse(catalog.related("T1558.002", ["T1558.003"]))      # a different sub-technique is not the same behaviour
        self.assertFalse(catalog.related("AML.T0053", ["AML.T0051"]))

    def test_known_lookups_search_and_renamed_ids(self):
        self.assertEqual(self.c.technique("t1558.003", detail=False)["name"], "Kerberoasting")
        self.assertEqual(self.c.search("kerberoasting")[0]["id"], "T1558.003")
        self.assertEqual(self.c.search("T1059.001")[0]["kind"], "technique")
        self.assertTrue(any(h["kind"] == "group" for h in self.c.search("Cozy Bear")))
        self.assertEqual(self.c.group("cozy bear")["id"], "G0016")
        self.assertEqual(self.c.software_item("Cobalt Strike")["type"], "malware")
        self.assertEqual(self.c.search(""), [])
        self.assertEqual(self.c.resolve("T1562.001"), "T1685")      # ATT&CK v19 moved Impair Defenses to Defense Impairment; older tags still resolve
        d = self.c.technique("AML.T0051")
        self.assertEqual(d["framework"], "atlas")
        self.assertTrue(d["mitigation_details"])
        self.assertIn("atlas.mitre.org", d["url"])
        self.assertIn("attack.mitre.org", self.c.technique("T1059.001")["url"])


if __name__ == "__main__":
    unittest.main()
