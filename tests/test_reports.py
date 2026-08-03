"""
Tests for dashboard/reports.py. Two layers, matching this project's usual pattern:
a stub-data unit test class (deterministic, isolated from the real artifacts) and a
real-artifact integration class (against the actual dashboard_data module) so a
regression in either the report logic or the real data shape gets caught.
"""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))

import reports  # noqa: E402


class _StubDataModule:
    """A minimal stand-in for dashboard/data.py's read-only interface, with numbers
    reports.py has no way to guess - if these don't match what's returned, the report
    generator has a real bug, not a fixture problem."""

    def load_remediation_findings(self):
        return [{"id": "FIND-1"}, {"id": "FIND-2"}]

    def load_vulnhunt_data(self):
        return {"available": True, "total": 9, "auto_fixable": 6}

    def load_remediation_plan(self):
        return {"available": True, "risk_tier_counts": {"auto-approvable": 1, "manual-only": 1}}

    def load_playbooks(self):
        return [{"filename": "FIND-1.yml"}]

    def load_live_queue(self):
        return [
            {"id": "FIND-1", "title": "Critical thing", "priority": "Critical", "asset": {"name": "WIN-DC01"}, "sla": {}},
            {"id": "FIND-2", "title": "Medium thing", "priority": "Medium", "asset": {"name": "LNX-DB03"}, "sla": {}},
        ]

    def sla_summary(self, findings):  # noqa: ARG002 - stub ignores input, returns fixed values
        return {"breached": 1, "at_risk": 0, "on_track": 1}

    def count_kev_listed(self, findings):  # noqa: ARG002
        return 1

    def count_high_epss(self, findings):  # noqa: ARG002
        return 1

    def asset_type_breakdown(self, findings):  # noqa: ARG002
        return {"windows-server": 1, "unix-server": 1}


class GenerateReportData(unittest.TestCase):
    def setUp(self):
        self.stub = _StubDataModule()

    def test_rejects_invalid_period(self):
        with self.assertRaises(ValueError):
            reports.generate_report_data("fortnightly", self.stub)

    def test_accepts_every_documented_period(self):
        for period in reports.VALID_PERIODS:
            data = reports.generate_report_data(period, self.stub)
            self.assertEqual(data["period"], period)

    def test_pulls_sla_summary_from_the_data_module(self):
        data = reports.generate_report_data("weekly", self.stub)
        self.assertEqual(data["sla"], {"breached": 1, "at_risk": 0, "on_track": 1})

    def test_pulls_kev_and_epss_counts(self):
        data = reports.generate_report_data("weekly", self.stub)
        self.assertEqual(data["kev_count"], 1)
        self.assertEqual(data["high_epss_count"], 1)

    def test_pulls_vulnhunt_and_remediation_totals(self):
        data = reports.generate_report_data("weekly", self.stub)
        self.assertEqual(data["vulnhunt_total"], 9)
        self.assertEqual(data["vulnhunt_auto_fixable"], 6)
        self.assertEqual(data["remediation_total"], 2)
        self.assertEqual(data["playbook_count"], 1)

    def test_top_priority_findings_are_capped_at_five(self):
        many = [
            {"id": f"FIND-{i}", "title": "t", "priority": "Critical", "asset": {"name": "a"}, "sla": {}}
            for i in range(20)
        ]
        stub = SimpleNamespace(
            load_remediation_findings=lambda: [],
            load_vulnhunt_data=lambda: {"available": False},
            load_remediation_plan=lambda: {"available": False, "risk_tier_counts": {}},
            load_playbooks=lambda: [],
            load_live_queue=lambda: many,
            sla_summary=lambda findings: {"breached": 0, "at_risk": 0, "on_track": 0},
            count_kev_listed=lambda findings: 0,
            count_high_epss=lambda findings: 0,
            asset_type_breakdown=lambda findings: {},
        )
        data = reports.generate_report_data("daily", stub)
        self.assertEqual(len(data["top_priority_findings"]), 5)

    def test_generated_at_is_present_and_looks_like_an_iso_timestamp(self):
        data = reports.generate_report_data("weekly", self.stub)
        self.assertRegex(data["generated_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class RenderReportHtml(unittest.TestCase):
    def setUp(self):
        self.data = reports.generate_report_data("monthly", _StubDataModule())

    def test_renders_valid_looking_html_document(self):
        html_out = reports.render_report_html(self.data)
        self.assertTrue(html_out.startswith("<!doctype html>"))
        self.assertIn("</html>", html_out)

    def test_includes_the_period_in_the_title(self):
        html_out = reports.render_report_html(self.data)
        self.assertIn("Monthly Security Report", html_out)

    def test_includes_the_no_persistence_caveat(self):
        html_out = reports.render_report_html(self.data)
        self.assertIn("no persistence layer", html_out)

    def test_includes_kpi_numbers(self):
        html_out = reports.render_report_html(self.data)
        self.assertIn(">1<", html_out)  # breached / kev_count / high_epss all stubbed to 1

    def test_escapes_html_in_finding_titles(self):
        """A finding title containing HTML must never be injected unescaped - this
        report is served directly as text/html, so this is a real XSS-shaped risk if
        a finding title ever contained a script tag."""
        data = dict(self.data)
        data["top_priority_findings"] = [
            {"id": "FIND-1", "title": "<script>alert(1)</script>", "priority": "Critical", "asset": "a"},
        ]
        html_out = reports.render_report_html(data)
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)


class RealArtifactIntegration(unittest.TestCase):
    """Runs the real report generator against dashboard/data.py and the repo's actual
    generated artifacts - catches drift between reports.py's assumptions and what
    dashboard_data really returns, the same real-artifact rule the rest of this suite
    follows."""

    def setUp(self):
        sys.path.insert(0, str(REPO_ROOT / "cli"))
        sys.path.insert(0, str(REPO_ROOT))
        import data as dashboard_data
        self.dashboard_data = dashboard_data

    def test_generate_report_data_against_real_artifacts(self):
        data = reports.generate_report_data("weekly", self.dashboard_data)
        self.assertEqual(data["remediation_total"], 14)
        self.assertEqual(data["vulnhunt_total"], 9)
        self.assertLessEqual(len(data["top_priority_findings"]), 5)

    def test_render_report_html_against_real_artifacts(self):
        data = reports.generate_report_data("yearly", self.dashboard_data)
        html_out = reports.render_report_html(data)
        self.assertIn("Yearly Security Report", html_out)


if __name__ == "__main__":
    unittest.main()
