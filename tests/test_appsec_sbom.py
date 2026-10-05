"""
Tests for application SBOM handling: version ordering, CycloneDX and SPDX parsing, and SBOM generation from dependency files.
"""
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.appsec import manifest_gen, sbom_parse, versions  # noqa: E402
from remediation.appsec.sbom_parse import SbomError  # noqa: E402


class VersionTests(unittest.TestCase):
    def test_ordering_and_highest(self):
        self.assertEqual(versions.compare("2.17.1", "2.9.0"), 1)
        self.assertEqual(versions.compare("1.0", "1.0.0"), 0)
        self.assertEqual(versions.compare("2.0.0-rc1", "2.0.0"), -1)
        self.assertEqual(versions.compare("v1.2.3", "1.2.4"), -1)
        self.assertIsNone(versions.compare("latest", "1.0"))
        self.assertEqual(versions.highest(["2.9.9", "2.17.1", "2.10.0", None, "n/a"]), "2.17.1")
        self.assertIsNone(versions.highest(["n/a"]))

    def test_major_crossing(self):
        self.assertTrue(versions.crosses_major("1.9.9", "2.0.0"))
        self.assertFalse(versions.crosses_major("2.1.0", "2.17.1"))
        self.assertFalse(versions.crosses_major("unknown", "2.0"))


CDX = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"type": "application", "bom-ref": "app", "name": "shop", "version": "1.0"}},
       "components": [{"bom-ref": "a", "name": "alpha", "version": "1.0", "purl": "pkg:maven/org.x/alpha@1.0", "group": "org.x", "licenses": [{"license": {"id": "MIT"}}],
                       "components": [{"bom-ref": "n", "name": "nested", "version": "0.1"}]},
                      {"bom-ref": "b", "name": "beta", "version": "2.0", "purl": "pkg:npm/%40s/beta@2.0"}],
       "dependencies": [{"ref": "app", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b", "missing"]}]}


class ParseTests(unittest.TestCase):
    def test_cyclonedx_flattens_nested_and_drops_dangling_edges(self):
        g = sbom_parse.parse(json.dumps(CDX))
        self.assertEqual(g["format"], "cyclonedx-1.5")
        self.assertEqual(g["root"]["name"], "shop")
        self.assertEqual({c["name"] for c in g["components"]}, {"alpha", "beta", "nested"})
        self.assertEqual(sorted(g["edges"]), [["a", "b"], ["app", "a"]])
        a = next(c for c in g["components"] if c["name"] == "alpha")
        self.assertEqual((a["ecosystem"], a["licenses"]), ("maven", ["MIT"]))
        self.assertTrue(g["has_graph"])

    def test_flat_cyclonedx_has_no_graph(self):
        g = sbom_parse.parse({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "x", "version": "1"}]})
        self.assertFalse(g["has_graph"])
        self.assertIsNone(g["root"])

    def test_spdx_relationships_become_edges(self):
        doc = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
               "packages": [{"SPDXID": "SPDXRef-App", "name": "shop", "versionInfo": "1"},
                            {"SPDXID": "SPDXRef-A", "name": "a", "versionInfo": "1.0", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/a@1.0"}]},
                            {"SPDXID": "SPDXRef-B", "name": "b", "versionInfo": "2.0", "licenseConcluded": "NOASSERTION"}],
               "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-App"},
                                 {"spdxElementId": "SPDXRef-App", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-A"},
                                 {"spdxElementId": "SPDXRef-B", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-A"}]}
        g = sbom_parse.parse(doc)
        self.assertEqual(g["format"], "spdx-2.3")
        self.assertEqual(g["root"]["name"], "shop")
        self.assertEqual(sorted(g["edges"]), [["SPDXRef-A", "SPDXRef-B"], ["SPDXRef-App", "SPDXRef-A"]])
        self.assertEqual(next(c for c in g["components"] if c["name"] == "a")["ecosystem"], "pypi")
        self.assertEqual(next(c for c in g["components"] if c["name"] == "b")["licenses"], [])

    def test_refuses_what_it_cannot_read(self):
        for bad in ("not json", "[1]", json.dumps({"hello": 1})):
            with self.assertRaises(SbomError):
                sbom_parse.parse(bad)

    def test_purl_parts(self):
        self.assertEqual(sbom_parse.purl_parts("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"), ("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"))
        self.assertEqual(sbom_parse.purl_parts("nonsense"), (None, None, None, None))


LOCK = {"name": "web", "version": "2.0.0", "lockfileVersion": 3, "packages": {
    "": {"name": "web", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "1.0.0"}},
    "node_modules/a": {"version": "1.2.3", "dependencies": {"b": "^2"}},
    "node_modules/b": {"version": "2.0.0", "dependencies": {"c": "*"}},
    "node_modules/a/node_modules/c": {"version": "0.1.0"},
    "node_modules/d": {"version": "1.0.0", "dev": True}}}


class GenerateTests(unittest.TestCase):
    def test_requirements_pins_and_ranges(self):
        doc, notes = manifest_gen.generate("shop", {"requirements.txt": "Flask==2.0.1\nrequests>=2.20  # comment\nDjango_Rest[extra]==3.1\n-r other.txt\n"})
        g = sbom_parse.parse(doc)
        by = {c["name"]: c for c in g["components"]}
        self.assertEqual(by["flask"]["version"], "2.0.1")
        self.assertEqual(by["requests"]["version"], "2.20")
        self.assertIn("django-rest", by)
        self.assertEqual(len(g["edges"]), 3)  # the application depends on each declared package
        self.assertTrue(any("transitive" in n for n in notes))
        self.assertEqual(doc["metadata"]["properties"][0]["value"], "declared-only")

    def test_package_lock_gives_the_whole_tree(self):
        doc, notes = manifest_gen.generate("web", {"package-lock.json": json.dumps(LOCK)})
        g = sbom_parse.parse(doc)
        by = {c["name"]: c for c in g["components"]}
        self.assertEqual(set(by), {"a", "b", "c", "d"})
        self.assertTrue(by["a"]["direct_hint"])
        self.assertFalse(by["b"]["direct_hint"])
        self.assertEqual(by["d"]["scope"], "optional")
        refs = {c["name"]: c["ref"] for c in g["components"]}
        edges = {tuple(e) for e in g["edges"]}
        self.assertIn((refs["a"], refs["b"]), edges)
        self.assertIn(("app:web", refs["a"]), edges)
        self.assertEqual(notes, [])
        self.assertEqual(doc["metadata"]["properties"][0]["value"], "full")

    def test_package_json_scoped_names_and_unpinned_git(self):
        doc, notes = manifest_gen.generate("web", {"package.json": json.dumps({"dependencies": {"@scope/pkg": "^1.4.0", "gitdep": "git+https://x/y.git"}})})
        g = sbom_parse.parse(doc)
        by = {c["name"]: c for c in g["components"]}
        self.assertEqual(by["@scope/pkg"]["version"], "1.4.0")
        self.assertIn("pkg:npm/%40scope/pkg@1.4.0", by["@scope/pkg"]["purl"])
        self.assertIsNone(by["gitdep"]["version"])
        self.assertTrue(any("no concrete version" in n for n in notes))

    def test_pom_resolves_properties_and_managed_versions(self):
        pom = """<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><log4j.v>2.14.1</log4j.v></properties>
        <dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>managed</artifactId><version>3.0</version></dependency></dependencies></dependencyManagement>
        <dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.v}</version></dependency>
        <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
        <dependency><groupId>g</groupId><artifactId>t</artifactId><version>1</version><scope>test</scope></dependency></dependencies></project>"""
        g = sbom_parse.parse(manifest_gen.generate("svc", {"pom.xml": pom})[0])
        by = {c["name"]: c for c in g["components"]}
        self.assertEqual(by["log4j-core"]["version"], "2.14.1")
        self.assertEqual(by["managed"]["version"], "3.0")
        self.assertEqual(by["t"]["scope"], "optional")

    def test_pom_with_entities_is_refused(self):
        with self.assertRaises(SbomError):
            manifest_gen.generate("svc", {"pom.xml": '<!DOCTYPE x [<!ENTITY a "b">]><project/>'})

    def test_go_mod_marks_indirect(self):
        gm = "module m\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgolang.org/x/text v0.3.0 // indirect\n)\nrequire github.com/c/d v0.1.0\n"
        g = sbom_parse.parse(manifest_gen.generate("svc", {"go.mod": gm})[0])
        by = {c["name"]: c for c in g["components"]}
        self.assertTrue(by["github.com/a/b"]["direct_hint"])
        self.assertFalse(by["golang.org/x/text"]["direct_hint"])
        self.assertEqual(len(g["components"]), 3)

    def test_unsupported_and_broken_files_are_named(self):
        with self.assertRaises(SbomError) as cx:
            manifest_gen.generate("x", {"Gemfile.lock": "x"})
        self.assertIn("Gemfile.lock", str(cx.exception))
        with self.assertRaises(SbomError):
            manifest_gen.generate("x", {"package.json": "{not json"})
        with self.assertRaises(SbomError):
            manifest_gen.generate("x", {})

    def test_requirements_variants_are_picked_up(self):
        doc, _ = manifest_gen.generate("x", {"deploy/requirements-dev.txt": "pytest==7.0.0\n"})
        self.assertEqual(sbom_parse.parse(doc)["components"][0]["name"], "pytest")


if __name__ == "__main__":
    unittest.main()
