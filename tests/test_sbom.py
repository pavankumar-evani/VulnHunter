"""
Tests for remediation/enrichment/sbom.py - CycloneDX SBOM parsing and dependency
blast-radius calculation. Uses small in-memory CycloneDX-shaped dicts (not the real
shipped remediation/sample-data/sbom.json for the unit-level tests, though one test
confirms that real sample file parses and behaves as documented).
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment import sbom  # noqa: E402


def _sbom(components, dependencies):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components, "dependencies": dependencies}


class FindComponent(unittest.TestCase):
    def test_case_insensitive_match(self):
        doc = _sbom([{"bom-ref": "r1", "name": "Log4j-Core", "version": "2.14.1"}], [])
        self.assertIsNotNone(sbom.find_component(doc, "log4j-core"))

    def test_no_match_returns_none(self):
        doc = _sbom([{"bom-ref": "r1", "name": "log4j-core", "version": "2.14.1"}], [])
        self.assertIsNone(sbom.find_component(doc, "jackson-databind"))

    def test_empty_package_name_returns_none(self):
        doc = _sbom([{"bom-ref": "r1", "name": "log4j-core"}], [])
        self.assertIsNone(sbom.find_component(doc, None))
        self.assertIsNone(sbom.find_component(doc, ""))


class ComponentInfo(unittest.TestCase):
    def test_extracts_ecosystem_from_purl(self):
        component = {"name": "log4j-core", "version": "2.14.1",
                     "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
        info = sbom.component_info(component)
        self.assertEqual(info, {"package": "log4j-core", "ecosystem": "maven", "version": "2.14.1"})

    def test_no_purl_gives_none_ecosystem(self):
        info = sbom.component_info({"name": "some-lib", "version": "1.0.0"})
        self.assertIsNone(info["ecosystem"])

    def test_none_component_gives_none(self):
        self.assertIsNone(sbom.component_info(None))


class ComputeBlastRadius(unittest.TestCase):
    def _sample_sbom(self):
        components = [
            {"bom-ref": "r-app", "name": "order-processing-service", "version": "3.4.0"},
            {"bom-ref": "r-web", "name": "spring-boot-starter-web", "version": "2.5.4"},
            {"bom-ref": "r-logging", "name": "spring-boot-starter-logging", "version": "2.5.4"},
            {"bom-ref": "r-log4j", "name": "log4j-core", "version": "2.14.1"},
            {"bom-ref": "r-jackson", "name": "jackson-databind", "version": "2.12.4"},
        ]
        dependencies = [
            {"ref": "r-app", "dependsOn": ["r-web", "r-jackson"]},
            {"ref": "r-web", "dependsOn": ["r-logging"]},
            {"ref": "r-logging", "dependsOn": ["r-log4j"]},
            {"ref": "r-jackson", "dependsOn": []},
            {"ref": "r-log4j", "dependsOn": []},
        ]
        return _sbom(components, dependencies)

    def test_transitive_blast_radius(self):
        radius = sbom.compute_blast_radius(self._sample_sbom(), "log4j-core")
        self.assertEqual(radius, ["order-processing-service", "spring-boot-starter-logging", "spring-boot-starter-web"])

    def test_unrelated_component_excluded(self):
        radius = sbom.compute_blast_radius(self._sample_sbom(), "log4j-core")
        self.assertNotIn("jackson-databind", radius)

    def test_root_component_with_no_dependents_has_empty_radius(self):
        # order-processing-service is the root of this graph - nothing depends ON it,
        # even though it depends on plenty else, so its own blast radius is empty.
        radius = sbom.compute_blast_radius(self._sample_sbom(), "order-processing-service")
        self.assertEqual(radius, [])

    def test_package_not_in_sbom_gives_empty_radius(self):
        radius = sbom.compute_blast_radius(self._sample_sbom(), "totally-unknown-package")
        self.assertEqual(radius, [])


class RealSampleSbomFile(unittest.TestCase):
    def test_real_sample_file_parses_and_matches_documented_blast_radius(self):
        doc = sbom.load_sbom(REPO_ROOT / "remediation" / "sample-data" / "sbom.json")
        component = sbom.find_component(doc, "log4j-core")
        self.assertIsNotNone(component)
        info = sbom.component_info(component)
        self.assertEqual(info["package"], "log4j-core")
        self.assertEqual(info["ecosystem"], "maven")
        radius = sbom.compute_blast_radius(doc, "log4j-core")
        self.assertIn("order-processing-service", radius)
        self.assertNotIn("jackson-databind", radius)


if __name__ == "__main__":
    unittest.main()
