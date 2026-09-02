"""
Tests for remediation/notifications/report_scheduler.py - pure cadence-math
(is_due/due_subscriptions) plus the orchestrator (check_and_send_due_reports) against
fake data_module/reports_module/email_sender stand-ins (never the real pipeline/SMTP -
mirrors tests/test_reports.py's own _StubDataModule pattern).
"""
import datetime
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.notifications import report_scheduler  # noqa: E402

NOW = datetime.datetime(2026, 8, 5, tzinfo=datetime.timezone.utc)


class IsDue(unittest.TestCase):
    def test_never_sent_is_due(self):
        self.assertTrue(report_scheduler.is_due({"cadence": "weekly"}, None, NOW))

    def test_not_due_before_cadence_elapses(self):
        last = (NOW - datetime.timedelta(days=1)).isoformat()
        self.assertFalse(report_scheduler.is_due({"cadence": "weekly"}, last, NOW))

    def test_due_once_cadence_elapses(self):
        last = (NOW - datetime.timedelta(days=7)).isoformat()
        self.assertTrue(report_scheduler.is_due({"cadence": "weekly"}, last, NOW))

    def test_unknown_cadence_is_never_due(self):
        self.assertFalse(report_scheduler.is_due({"cadence": "fortnightly"}, None, NOW))

    def test_every_documented_cadence_has_a_day_count(self):
        for cadence in ("weekly", "monthly", "quarterly", "half-yearly", "yearly"):
            self.assertIn(cadence, report_scheduler.CADENCE_DAYS)

    def test_naive_last_sent_at_is_treated_as_utc(self):
        last = (NOW - datetime.timedelta(days=8)).replace(tzinfo=None).isoformat()
        self.assertTrue(report_scheduler.is_due({"cadence": "weekly"}, last, NOW))


class DueSubscriptions(unittest.TestCase):
    def test_disabled_subscription_is_never_due(self):
        rules = {"subscriptions": [{"id": "s1", "cadence": "weekly", "enabled": False}]}
        self.assertEqual(report_scheduler.due_subscriptions(rules, {}, NOW), [])

    def test_enabled_and_due_subscription_is_returned(self):
        rules = {"subscriptions": [{"id": "s1", "cadence": "weekly", "enabled": True}]}
        due = report_scheduler.due_subscriptions(rules, {}, NOW)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0]["id"], "s1")

    def test_enabled_but_not_due_subscription_is_excluded(self):
        state = {"s1": (NOW - datetime.timedelta(days=1)).isoformat()}
        rules = {"subscriptions": [{"id": "s1", "cadence": "weekly", "enabled": True}]}
        self.assertEqual(report_scheduler.due_subscriptions(rules, state, NOW), [])


class _FakeReportsModule:
    def generate_report_data(self, period, data_module, scope="all", team=None):  # noqa: ARG002
        return {"period": period, "scope": scope, "team": team}

    def report_title(self, report):
        return f"Report {report['period']}"

    def render_report_text(self, report):  # noqa: ARG002
        return "text body"

    def render_report_html(self, report):  # noqa: ARG002
        return "<p>html body</p>"


class _FakeDataModule:
    def __init__(self, rules):
        self._rules = rules

    def load_report_schedule_rules(self):
        return self._rules


class _FakeEmailSender:
    def __init__(self, configured=True, raise_on_send=None):
        self.configured = configured
        self.raise_on_send = raise_on_send
        self.sent = []

    def is_configured(self):
        return self.configured

    def send_email(self, to_addrs, subject, body_text, body_html=None):  # noqa: ARG002
        if self.raise_on_send:
            raise self.raise_on_send
        self.sent.append((to_addrs, subject))


class CheckAndSendDueReports(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmpdir.name) / 'test.db'}")
        self.lock_path = Path(self.tmpdir.name) / "test.lock"

    def tearDown(self):
        self.engine.dispose()
        self.tmpdir.cleanup()

    def _check(self, data_module, sender, now):
        return report_scheduler.check_and_send_due_reports(
            data_module, _FakeReportsModule(), sender, now=now, engine=self.engine, lock_path=self.lock_path,
        )

    def test_no_due_subscriptions_returns_empty(self):
        data_module = _FakeDataModule({"subscriptions": []})
        results = self._check(data_module, _FakeEmailSender(), NOW)
        self.assertEqual(results, [])

    def test_due_subscription_sends_and_records_state(self):
        rules = {"subscriptions": [{"id": "s1", "cadence": "weekly", "scope": "all", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules)
        sender = _FakeEmailSender()
        results = self._check(data_module, sender, NOW)
        self.assertEqual(results, [{"id": "s1", "status": "sent", "recipients": ["a@example.com"]}])
        self.assertEqual(sender.sent, [(["a@example.com"], "Report weekly")])
        state = report_scheduler.load_state(self.engine)
        self.assertEqual(state["s1"], NOW.isoformat(timespec="seconds"))

    def test_due_subscription_is_skipped_not_fabricated_when_smtp_unconfigured(self):
        rules = {"subscriptions": [{"id": "s1", "cadence": "weekly", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules)
        sender = _FakeEmailSender(configured=False)
        results = self._check(data_module, sender, NOW)
        self.assertEqual(results, [{"id": "s1", "status": "skipped", "reason": "SMTP not configured"}])
        self.assertEqual(sender.sent, [])
        # State untouched - retried on the next check, not silently marked done.
        self.assertEqual(report_scheduler.load_state(self.engine), {})

    def test_a_second_check_does_not_resend_the_same_subscription(self):
        rules = {"subscriptions": [{"id": "s1", "cadence": "weekly", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules)
        sender = _FakeEmailSender()
        self._check(data_module, sender, NOW)
        results = self._check(data_module, sender, NOW + datetime.timedelta(hours=1))
        self.assertEqual(results, [])
        self.assertEqual(len(sender.sent), 1)

    def test_send_failure_is_reported_per_subscription_not_fatal(self):
        rules = {"subscriptions": [{"id": "s1", "cadence": "weekly", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules)
        sender = _FakeEmailSender(raise_on_send=RuntimeError("smtp exploded"))
        results = self._check(data_module, sender, NOW)
        self.assertEqual(results, [{"id": "s1", "status": "error", "reason": "smtp exploded"}])

    def test_concurrent_checks_never_double_send_the_same_subscription(self):
        """Regression guard for the confirmed race this migration closes."""
        import threading

        rules = {"subscriptions": [{"id": "s1", "cadence": "weekly", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules)
        sender = _FakeEmailSender()
        barrier = threading.Barrier(2)
        results = []

        def run():
            barrier.wait()
            results.append(self._check(data_module, sender, NOW))

        threads = [threading.Thread(target=run) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(sender.sent), 1)
        sent_count = sum(1 for r in results if r == [{"id": "s1", "status": "sent", "recipients": ["a@example.com"]}])
        self.assertEqual(sent_count, 1)


if __name__ == "__main__":
    unittest.main()
