"""
Tests for remediation/notifications/alert_checker.py - per-finding matcher logic
(matching_findings/new_matching_findings, pure and directly testable) plus the
orchestrator (check_and_send_alerts) against a fake data_module/email_sender and a
patched asset_inventory.load_ownership() (never the real asset_ownership.json).
"""
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.notifications import alert_checker  # noqa: E402

CRITICAL_FINDING = {"id": "FIND-1", "severity": "Critical", "scan_type": "infra-vm", "asset": {"name": "WIN-DC01"}}
MEDIUM_FINDING = {"id": "FIND-2", "severity": "Medium", "scan_type": "infra-vm", "asset": {"name": "WEB-01"}}
ZERO_DAY_FINDING = {
    "id": "FIND-3", "severity": "High", "scan_type": "dast", "asset": {"name": "WEB-01"},
    "kev": {"listed": True}, "exploit_criteria_matches": [{"id": "any-kev"}],
}
KEV_ONLY_FINDING = {
    "id": "FIND-4", "severity": "High", "scan_type": "dast", "asset": {"name": "WEB-01"},
    "kev": {"listed": True}, "exploit_criteria_matches": [],
}
THREAT_INTEL_FINDING = {
    "id": "FIND-5", "severity": "Medium", "scan_type": "infra-vm", "asset": {"name": "WIN-DC01"},
    "attack_techniques": [{"technique_id": "T1021"}],  # a real technique with a documented group correlation
}
OWNERSHIP = {"WIN-DC01": {"team": "Identity & Domain Services"}}


class MatchingFindings(unittest.TestCase):
    def test_critical_alert_type_matches_only_critical_severity(self):
        sub = {"alert_type": "critical", "scope": "all", "team": None}
        matched = alert_checker.matching_findings(sub, [CRITICAL_FINDING, MEDIUM_FINDING], {})
        self.assertEqual([f["id"] for f in matched], ["FIND-1"])

    def test_zero_day_requires_both_kev_and_exploit_criteria_match(self):
        sub = {"alert_type": "zero_day", "scope": "all", "team": None}
        matched = alert_checker.matching_findings(sub, [ZERO_DAY_FINDING, KEV_ONLY_FINDING], {})
        self.assertEqual([f["id"] for f in matched], ["FIND-3"])

    def test_threat_intel_requires_a_real_technique_group_correlation(self):
        sub = {"alert_type": "threat_intel", "scope": "all", "team": None}
        matched = alert_checker.matching_findings(sub, [THREAT_INTEL_FINDING, MEDIUM_FINDING], {})
        self.assertEqual([f["id"] for f in matched], ["FIND-5"])

    def test_scope_filters_by_scan_type(self):
        sub = {"alert_type": "critical", "scope": "dast", "team": None}
        matched = alert_checker.matching_findings(sub, [CRITICAL_FINDING], {})
        self.assertEqual(matched, [])  # CRITICAL_FINDING is infra-vm, not dast

    def test_team_filters_by_asset_ownership(self):
        sub = {"alert_type": "critical", "scope": "all", "team": "Identity & Domain Services"}
        matched = alert_checker.matching_findings(sub, [CRITICAL_FINDING], OWNERSHIP)
        self.assertEqual(len(matched), 1)
        sub_other_team = {"alert_type": "critical", "scope": "all", "team": "Some Other Team"}
        self.assertEqual(alert_checker.matching_findings(sub_other_team, [CRITICAL_FINDING], OWNERSHIP), [])

    def test_unknown_alert_type_matches_nothing(self):
        sub = {"alert_type": "carrier-pigeon", "scope": "all", "team": None}
        self.assertEqual(alert_checker.matching_findings(sub, [CRITICAL_FINDING], {}), [])


class NewMatchingFindings(unittest.TestCase):
    def test_returns_all_matches_when_state_is_empty(self):
        sub = {"id": "s1", "alert_type": "critical", "scope": "all", "team": None}
        new = alert_checker.new_matching_findings(sub, [CRITICAL_FINDING], {}, {})
        self.assertEqual([f["id"] for f in new], ["FIND-1"])

    def test_excludes_already_alerted_findings(self):
        sub = {"id": "s1", "alert_type": "critical", "scope": "all", "team": None}
        state = {"s1": ["FIND-1"]}
        new = alert_checker.new_matching_findings(sub, [CRITICAL_FINDING], {}, state)
        self.assertEqual(new, [])

    def test_state_is_scoped_per_subscription(self):
        sub = {"id": "s1", "alert_type": "critical", "scope": "all", "team": None}
        state = {"other-sub": ["FIND-1"]}  # a different subscription's own history
        new = alert_checker.new_matching_findings(sub, [CRITICAL_FINDING], {}, state)
        self.assertEqual([f["id"] for f in new], ["FIND-1"])


class _FakeDataModule:
    def __init__(self, rules, findings):
        self._rules = rules
        self._findings = findings

    def load_alert_rules(self):
        return self._rules

    def load_live_queue(self):
        return self._findings


class _FakeEmailSender:
    def __init__(self, configured=True):
        self.configured = configured
        self.sent = []

    def is_configured(self):
        return self.configured

    def send_email(self, to_addrs, subject, body_text, body_html=None):  # noqa: ARG002
        self.sent.append((to_addrs, subject))


class CheckAndSendAlerts(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmpdir.name) / 'test.db'}")
        self.lock_path = Path(self.tmpdir.name) / "test.lock"
        self.ownership_patcher = patch.object(alert_checker.asset_inventory, "load_ownership", return_value={})
        self.ownership_patcher.start()

    def tearDown(self):
        self.ownership_patcher.stop()
        self.engine.dispose()
        self.tmpdir.cleanup()

    def _check(self, data_module, sender):
        return alert_checker.check_and_send_alerts(data_module, sender, engine=self.engine, lock_path=self.lock_path)

    def test_no_matches_returns_empty(self):
        rules = {"subscriptions": [{"id": "s1", "alert_type": "critical", "scope": "all", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules, [MEDIUM_FINDING])
        results = self._check(data_module, _FakeEmailSender())
        self.assertEqual(results, [])

    def test_new_match_sends_and_records_state(self):
        rules = {"subscriptions": [{"id": "s1", "alert_type": "critical", "scope": "all", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules, [CRITICAL_FINDING])
        sender = _FakeEmailSender()
        results = self._check(data_module, sender)
        self.assertEqual(results, [{"id": "s1", "status": "sent", "new_count": 1}])
        self.assertEqual(len(sender.sent), 1)
        state = alert_checker.load_state(self.engine)
        self.assertEqual(state["s1"], ["FIND-1"])

    def test_same_finding_is_not_re_alerted_on_next_check(self):
        rules = {"subscriptions": [{"id": "s1", "alert_type": "critical", "scope": "all", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules, [CRITICAL_FINDING])
        sender = _FakeEmailSender()
        self._check(data_module, sender)
        results = self._check(data_module, sender)
        self.assertEqual(results, [])
        self.assertEqual(len(sender.sent), 1)

    def test_new_match_is_skipped_not_fabricated_when_smtp_unconfigured(self):
        rules = {"subscriptions": [{"id": "s1", "alert_type": "critical", "scope": "all", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules, [CRITICAL_FINDING])
        sender = _FakeEmailSender(configured=False)
        results = self._check(data_module, sender)
        self.assertEqual(results, [{"id": "s1", "status": "skipped", "reason": "SMTP not configured", "new_count": 1}])
        self.assertEqual(alert_checker.load_state(self.engine), {})

    def test_disabled_subscription_is_never_checked(self):
        rules = {"subscriptions": [{"id": "s1", "alert_type": "critical", "scope": "all", "recipients": ["a@example.com"], "enabled": False}]}
        data_module = _FakeDataModule(rules, [CRITICAL_FINDING])
        results = self._check(data_module, _FakeEmailSender())
        self.assertEqual(results, [])

    def test_concurrent_checks_never_double_send_the_same_finding(self):
        """Regression guard for the confirmed race this migration closes: two
        overlapping calls (simulating the background timer and the "run checks now"
        button firing at the same time) must serialize, not both see a stale
        not-yet-alerted state and both send."""
        import threading

        rules = {"subscriptions": [{"id": "s1", "alert_type": "critical", "scope": "all", "recipients": ["a@example.com"], "enabled": True}]}
        data_module = _FakeDataModule(rules, [CRITICAL_FINDING])
        sender = _FakeEmailSender()
        barrier = threading.Barrier(2)
        results = []

        def run():
            barrier.wait()
            results.append(self._check(data_module, sender))

        threads = [threading.Thread(target=run) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(sender.sent), 1)
        sent_count = sum(1 for r in results if r == [{"id": "s1", "status": "sent", "new_count": 1}])
        self.assertEqual(sent_count, 1)


if __name__ == "__main__":
    unittest.main()
