"""
Tests for remediation/enrichment/kev_epss.py.

Most tests mock HTTP for CI determinism/speed, same pattern as test_connectors.py. The
one exception is LiveSmokeTest, which calls the REAL public CISA KEV feed and FIRST.org
EPSS API - both are free, no-auth, and stable (a government catalog and a FIRST.org
community project), so this is a legitimate integration check rather than a flaky
dependency. It asserts against a well-known, extremely stable historical fact (PrintNightmare,
CVE-2021-34527, has been KEV-listed since 2021 and will not stop being so) rather than
anything that could plausibly change. If the network is unavailable, it skips itself
rather than failing the build.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.kev_epss import (  # noqa: E402
    fetch_cisa_kev, fetch_epss_scores, enrich_findings, enrich_file,
)


def fake_response(json_data):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class KevFetching(unittest.TestCase):
    def test_fetch_cisa_kev_maps_documented_shape(self):
        session = MagicMock()
        session.get.return_value = fake_response({
            "vulnerabilities": [
                {"cveID": "CVE-2021-34527", "dateAdded": "2021-11-03",
                 "vulnerabilityName": "Microsoft Windows Print Spooler RCE",
                 "knownRansomwareCampaignUse": "Known", "dueDate": "2021-11-17"},
            ]
        })
        kev = fetch_cisa_kev(session=session)
        self.assertIn("CVE-2021-34527", kev)
        self.assertEqual(kev["CVE-2021-34527"]["known_ransomware_campaign_use"], "Known")

    def test_fetch_cisa_kev_skips_entries_with_no_cve_id(self):
        session = MagicMock()
        session.get.return_value = fake_response({"vulnerabilities": [{"dateAdded": "x"}]})
        kev = fetch_cisa_kev(session=session)
        self.assertEqual(kev, {})


class EpssFetching(unittest.TestCase):
    def test_fetch_epss_scores_maps_documented_shape(self):
        session = MagicMock()
        session.get.return_value = fake_response({
            "data": [{"cve": "CVE-2021-34527", "epss": "0.997590000", "percentile": "0.999550000"}]
        })
        scores = fetch_epss_scores(["CVE-2021-34527"], session=session)
        self.assertAlmostEqual(scores["CVE-2021-34527"]["score"], 0.99759)
        self.assertAlmostEqual(scores["CVE-2021-34527"]["percentile"], 0.99955)

    def test_fetch_epss_scores_batches_large_cve_lists(self):
        session = MagicMock()
        session.get.return_value = fake_response({"data": []})
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(150)]  # > EPSS_BATCH_SIZE (100)
        fetch_epss_scores(cve_ids, session=session)
        self.assertEqual(session.get.call_count, 2)  # 100 + 50

    def test_fetch_epss_scores_deduplicates_input(self):
        session = MagicMock()
        session.get.return_value = fake_response({"data": []})
        fetch_epss_scores(["CVE-2021-34527", "CVE-2021-34527"], session=session)
        params = session.get.call_args.kwargs["params"]
        self.assertEqual(params["cve"], "CVE-2021-34527")  # deduped, not comma-doubled


class EnrichmentAssembly(unittest.TestCase):
    def test_findings_without_cve_get_null_enrichment(self):
        findings = [{"id": "FIND-1", "cve": None}]
        enriched = enrich_findings(findings, kev_data={}, epss_data={})
        self.assertIsNone(enriched[0]["kev"])
        self.assertIsNone(enriched[0]["epss"])

    def test_kev_listed_finding_gets_full_kev_record(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2021-34527"}]
        kev_data = {"CVE-2021-34527": {"date_added": "2021-11-03", "known_ransomware_campaign_use": "Known"}}
        enriched = enrich_findings(findings, kev_data=kev_data, epss_data={})
        self.assertTrue(enriched[0]["kev"]["listed"])
        self.assertEqual(enriched[0]["kev"]["known_ransomware_campaign_use"], "Known")

    def test_non_kev_listed_finding_gets_listed_false(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2099-99999"}]
        enriched = enrich_findings(findings, kev_data={}, epss_data={})
        self.assertEqual(enriched[0]["kev"], {"listed": False})

    def test_epss_missing_for_a_cve_is_none_not_a_crash(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2099-99999"}]
        enriched = enrich_findings(findings, kev_data={}, epss_data={})
        self.assertIsNone(enriched[0]["epss"])

    def test_original_finding_fields_are_preserved(self):
        findings = [{"id": "FIND-1", "cve": "CVE-2021-34527", "title": "PrintNightmare"}]
        enriched = enrich_findings(findings, kev_data={}, epss_data={})
        self.assertEqual(enriched[0]["title"], "PrintNightmare")
        self.assertEqual(enriched[0]["id"], "FIND-1")


class EnrichFileIO(unittest.TestCase):
    def test_enrich_file_writes_enriched_json(self):
        """Exercises enrich_file() end-to-end, including its own internal calls to
        fetch_cisa_kev/fetch_epss_scores - mocking the injected session's responses
        rather than bypassing enrich_file's real logic."""
        import tempfile
        findings = [{"id": "FIND-1", "cve": "CVE-2021-34527"}]

        session = MagicMock()
        session.get.side_effect = [
            fake_response({"vulnerabilities": [
                {"cveID": "CVE-2021-34527", "dateAdded": "2021-11-03",
                 "vulnerabilityName": "PrintNightmare", "knownRansomwareCampaignUse": "Known"},
            ]}),
            fake_response({"data": [
                {"cve": "CVE-2021-34527", "epss": "0.99759", "percentile": "0.99955"},
            ]}),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = Path(tmpdir) / "findings.json"
            in_path.write_text(json.dumps(findings), encoding="utf-8")
            out_path = Path(tmpdir) / "out.json"

            enrich_file(in_path, output_path=out_path, session=session)

            result = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertTrue(result[0]["kev"]["listed"])
            self.assertAlmostEqual(result[0]["epss"]["score"], 0.99759)

    def test_enrich_file_defaults_to_overwriting_input(self):
        import tempfile
        findings = [{"id": "FIND-1", "cve": None}]
        session = MagicMock()  # cve is None -> no HTTP calls should even be made

        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = Path(tmpdir) / "findings.json"
            in_path.write_text(json.dumps(findings), encoding="utf-8")

            returned_path = enrich_file(in_path, session=session)

            self.assertEqual(returned_path, in_path)
            result = json.loads(in_path.read_text(encoding="utf-8"))
            self.assertIsNone(result[0]["kev"])
            session.get.assert_not_called()


class LiveSmokeTest(unittest.TestCase):
    """Hits the real public endpoints. Skips itself (doesn't fail) if the network is
    unavailable - see the module docstring for why this is a deliberate exception to
    "never call real APIs in tests"."""

    def test_printnightmare_is_kev_listed_and_high_epss_live(self):
        try:
            kev = fetch_cisa_kev()
            epss = fetch_epss_scores(["CVE-2021-34527"])
        except Exception as exc:  # noqa: BLE001 - any network failure should skip, not fail
            self.skipTest(f"live network check unavailable: {exc}")
            return
        self.assertIn("CVE-2021-34527", kev, "PrintNightmare should be KEV-listed (has been since 2021)")
        self.assertGreater(
            epss.get("CVE-2021-34527", {}).get("score", 0), 0.9,
            "PrintNightmare should have a very high EPSS score",
        )


if __name__ == "__main__":
    unittest.main()
