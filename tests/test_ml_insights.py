"""
Tests for remediation/enrichment/ml_insights.py - the real, unsupervised scikit-learn
models (IsolationForest anomaly detection, KMeans clustering, TF-IDF similarity search).
Unlike test_pattern_recognition.py (which tests a keyword heuristic), these tests fit
real models against small synthetic fixtures - deterministic via random_state=42, so a
planted outlier/duplicate is expected to be found every run, not just "usually."
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment import ml_insights  # noqa: E402


def _asset_row(name, asset_type="unix-server", **overrides):
    row = {
        "name": name,
        "type": asset_type,
        "finding_count": 1,
        "critical_count": 0,
        "highest_severity": "Low",
        "kev_count": 0,
    }
    row.update(overrides)
    return row


def _finding(finding_id, asset_name, asset_type="unix-server", **overrides):
    f = {
        "id": finding_id,
        "asset": {"name": asset_name, "type": asset_type},
        "title": "Generic finding",
        "description": "",
        "severity": "Low",
        "cvss": None,
        "kev": None,
        "epss": None,
    }
    f.update(overrides)
    return f


class BuildAssetFeatureMatrix(unittest.TestCase):
    def test_shape_matches_asset_count_and_feature_names(self):
        rows = [_asset_row("A"), _asset_row("B"), _asset_row("C")]
        findings = [_finding("FIND-1", "A", cvss=7.0, epss={"score": 0.4})]
        matrix = ml_insights.build_asset_feature_matrix(rows, findings)
        self.assertEqual(matrix.shape, (3, len(ml_insights.ASSET_FEATURE_NAMES)))

    def test_max_cvss_and_epss_come_from_that_assets_own_findings(self):
        rows = [_asset_row("A")]
        findings = [
            _finding("FIND-1", "A", cvss=3.0, epss={"score": 0.1}),
            _finding("FIND-2", "A", cvss=9.0, epss={"score": 0.8}),
            _finding("FIND-3", "OTHER-ASSET", cvss=10.0, epss={"score": 0.99}),
        ]
        matrix = ml_insights.build_asset_feature_matrix(rows, findings)
        max_cvss_idx = ml_insights.ASSET_FEATURE_NAMES.index("max_cvss")
        max_epss_idx = ml_insights.ASSET_FEATURE_NAMES.index("max_epss")
        self.assertEqual(matrix[0][max_cvss_idx], 9.0)  # not OTHER-ASSET's 10.0
        self.assertEqual(matrix[0][max_epss_idx], 0.8)


class DetectAssetAnomalies(unittest.TestCase):
    def test_planted_outlier_is_flagged_with_a_reason(self):
        # 14 normal unix-server assets (finding_count 1-2, no criticals/KEV) plus one
        # wildly different asset - well above _MIN_ASSETS_FOR_ANOMALY_DETECTION (10) so
        # IsolationForest actually fits, contamination=0.05 keeps the flagged set small.
        rows = [_asset_row(f"NORMAL-{i}", finding_count=(i % 2) + 1) for i in range(14)]
        rows.append(_asset_row("OUTLIER", finding_count=500, critical_count=50, kev_count=10, highest_severity="Critical"))
        findings = [_finding(f"FIND-{i}", r["name"]) for i, r in enumerate(rows)]

        results = ml_insights.detect_asset_anomalies(rows, findings)
        by_name = {r["name"]: r for r in results}

        self.assertTrue(by_name["OUTLIER"]["is_anomaly"])
        self.assertGreater(len(by_name["OUTLIER"]["reasons"]), 0)
        self.assertIn("unix-server", by_name["OUTLIER"]["reasons"][0])
        # The outlier's score should be the most negative (most anomalous) of the group.
        scores = {name: r["anomaly_score"] for name, r in by_name.items()}
        self.assertEqual(min(scores, key=scores.get), "OUTLIER")

    def test_type_group_below_minimum_is_skipped_honestly(self):
        # Only 3 assets of this type - well under _MIN_ASSETS_FOR_ANOMALY_DETECTION (10).
        rows = [_asset_row(f"RARE-{i}", asset_type="printer") for i in range(3)]
        findings = [_finding(f"FIND-{i}", r["name"], asset_type="printer") for i, r in enumerate(rows)]

        results = ml_insights.detect_asset_anomalies(rows, findings)
        for r in results:
            self.assertIsNone(r["anomaly_score"])
            self.assertFalse(r["is_anomaly"])
            self.assertEqual(r["reasons"], [])

    def test_anomaly_detection_is_scoped_per_asset_type(self):
        # A "high" finding_count for a printer (5) is nothing unusual for a
        # cloud-infrastructure asset - each type group must be judged against its own
        # peers, not a single pooled population.
        printer_rows = [_asset_row(f"PRT-{i}", asset_type="printer", finding_count=1) for i in range(12)]
        printer_rows.append(_asset_row("PRT-OUTLIER", asset_type="printer", finding_count=5, critical_count=3))
        cloud_rows = [_asset_row(f"CLD-{i}", asset_type="cloud-infrastructure", finding_count=5) for i in range(12)]
        rows = printer_rows + cloud_rows
        findings = [_finding(f"FIND-{i}", r["name"], asset_type=r["type"]) for i, r in enumerate(rows)]

        results = ml_insights.detect_asset_anomalies(rows, findings)
        by_name = {r["name"]: r for r in results}
        self.assertTrue(by_name["PRT-OUTLIER"]["is_anomaly"])
        # None of the uniform cloud-infrastructure rows should be flagged against a
        # population that's entirely identical to them.
        self.assertFalse(any(by_name[f"CLD-{i}"]["is_anomaly"] for i in range(12)))

    def test_does_not_mutate_input(self):
        rows = [_asset_row(f"A-{i}") for i in range(12)]
        findings = [_finding(f"FIND-{i}", r["name"]) for i, r in enumerate(rows)]
        rows_before = [dict(r) for r in rows]
        findings_before = [dict(f) for f in findings]
        ml_insights.detect_asset_anomalies(rows, findings)
        self.assertEqual(rows, rows_before)
        self.assertEqual(findings, findings_before)

    def test_every_flagged_anomaly_always_gets_at_least_one_reason(self):
        # Regression guard for a real edge case found against the live demo dataset:
        # CLOUD-0026's strongest deviation (max_epss) was z=+0.996 - just barely under
        # the old "both candidate reasons need |z| >= 1.0" cutoff, so a genuinely flagged
        # anomaly (is_anomaly=True) came back with reasons=[], an empty explanation for
        # a real result. The single most-deviating feature must always be reported,
        # regardless of its magnitude, since it's the real reason the model flagged it.
        rows = [_asset_row(f"NORMAL-{i}", finding_count=(i % 2) + 1) for i in range(19)]
        rows.append(_asset_row("MILD-OUTLIER", finding_count=3))
        findings = [_finding(f"FIND-{i}", r["name"]) for i, r in enumerate(rows)]

        results = ml_insights.detect_asset_anomalies(rows, findings)
        for r in results:
            if r["is_anomaly"]:
                self.assertGreater(len(r["reasons"]), 0, r["name"])


class ClusterFindings(unittest.TestCase):
    def test_every_finding_gets_a_cluster_and_sizes_sum_to_total(self):
        findings = [_finding(f"FIND-{i}", f"ASSET-{i}", severity="Critical" if i % 3 == 0 else "Low",
                              cvss=9.0 if i % 3 == 0 else 2.0) for i in range(30)]
        tagged, summaries = ml_insights.cluster_findings(findings, n_clusters=4)

        self.assertEqual(len(tagged), len(findings))
        self.assertTrue(all("risk_cluster" in f for f in tagged))
        self.assertEqual(sum(s["size"] for s in summaries), len(findings))

    def test_below_minimum_returns_empty(self):
        # Fewer than _MIN_FINDINGS_FOR_CLUSTERING (20).
        findings = [_finding(f"FIND-{i}", f"ASSET-{i}") for i in range(5)]
        tagged, summaries = ml_insights.cluster_findings(findings)
        self.assertEqual(tagged, [])
        self.assertEqual(summaries, [])

    def test_cluster_summary_profile_reflects_actual_members(self):
        # 20 low-severity findings, 10 critical - KMeans should discover a cluster whose
        # summary genuinely reflects the critical group's real profile, not a fabricated
        # predefined label.
        findings = [_finding(f"FIND-{i}", f"ASSET-{i}", severity="Low", cvss=2.0) for i in range(20)]
        findings += [_finding(f"FIND-crit-{i}", f"CRIT-ASSET-{i}", severity="Critical", cvss=9.8,
                               kev={"listed": True}) for i in range(10)]
        _tagged, summaries = ml_insights.cluster_findings(findings, n_clusters=2)

        self.assertEqual(len(summaries), 2)
        critical_cluster = next(s for s in summaries if s["dominant_severity"] == "Critical")
        self.assertEqual(critical_cluster["size"], 10)
        self.assertEqual(critical_cluster["kev_count"], 10)
        self.assertGreater(critical_cluster["avg_cvss"], 9.0)

    def test_does_not_mutate_input(self):
        findings = [_finding(f"FIND-{i}", f"ASSET-{i}") for i in range(25)]
        findings_before = [dict(f) for f in findings]
        ml_insights.cluster_findings(findings)
        self.assertEqual(findings, findings_before)


class FindSimilarFindings(unittest.TestCase):
    def test_planted_near_duplicate_ranks_first(self):
        findings = [
            _finding("FIND-1", "A", title="Apache Log4j2 Remote Code Execution",
                     description="JNDI lookup allows remote code execution via crafted log messages"),
            _finding("FIND-2", "B", title="Apache Log4j2 remote code execution vulnerability",
                     description="JNDI lookups allow remote code execution through crafted log messages"),
            _finding("FIND-3", "C", title="Unrelated SQL injection in login form",
                     description="User-controlled input concatenated directly into a SQL query"),
            _finding("FIND-4", "D", title="Unrelated buffer overflow in printer firmware",
                     description="Crafted print job triggers a stack buffer overflow"),
        ]
        results = ml_insights.find_similar_findings(findings, "FIND-1")
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["id"], "FIND-2")
        self.assertGreater(results[0]["similarity"], 0.5)
        # The query finding itself is never included in its own results.
        self.assertNotIn("FIND-1", [r["id"] for r in results])

    def test_unknown_finding_id_returns_empty(self):
        findings = [_finding("FIND-1", "A"), _finding("FIND-2", "B")]
        self.assertEqual(ml_insights.find_similar_findings(findings, "FIND-NOPE"), [])

    def test_completely_dissimilar_text_is_excluded_not_padded_in(self):
        findings = [
            _finding("FIND-1", "A", title="Apache Log4j2 Remote Code Execution", description="JNDI RCE"),
            _finding("FIND-2", "B", title="Zzyzyx Qwerp Frobnicator", description="Totally unrelated content"),
        ]
        # No shared vocabulary at all -> cosine similarity 0 -> excluded, not force-included.
        self.assertEqual(ml_insights.find_similar_findings(findings, "FIND-1"), [])

    def test_does_not_mutate_input(self):
        findings = [
            _finding("FIND-1", "A", title="Apache Log4j2 RCE", description="JNDI lookup RCE"),
            _finding("FIND-2", "B", title="Apache Log4j2 RCE issue", description="JNDI lookup RCE issue"),
        ]
        findings_before = [dict(f) for f in findings]
        ml_insights.find_similar_findings(findings, "FIND-1")
        self.assertEqual(findings, findings_before)


if __name__ == "__main__":
    unittest.main()
