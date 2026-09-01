"""
Tests for remediation/enrichment/activity_insights.py - real unsupervised anomaly
detection over this app's own activity log, plus its honest below-the-floor and
zero-data behavior. Deterministic via random_state=42, same convention as
test_ml_insights.py.
"""
import datetime
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment import activity_insights  # noqa: E402

BASE = datetime.datetime(2026, 8, 1, 10, 0, tzinfo=datetime.timezone.utc)


def _entry(id_, actor, action, target=None, details=None, hour=10, minute=0):
    return {
        "id": id_,
        "actor": actor,
        "action": action,
        "target": target,
        "details": details or {},
        "timestamp": BASE.replace(hour=hour, minute=minute).isoformat(),
    }


class SummarizeActivity(unittest.TestCase):
    def test_empty_log_summarizes_honestly(self):
        summary = activity_insights.summarize_activity([])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["by_action"], {})
        self.assertEqual(summary["by_actor"], {})
        self.assertIsNone(summary["most_recent_timestamp"])

    def test_counts_by_action_and_actor(self):
        entries = [
            _entry(1, "a@x.com", "asset.set_owner"),
            _entry(2, "a@x.com", "asset.set_owner"),
            _entry(3, "b@x.com", "exception.create"),
        ]
        summary = activity_insights.summarize_activity(entries)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_action"]["asset.set_owner"], 2)
        self.assertEqual(summary["by_actor"]["a@x.com"], 2)

    def test_most_recent_timestamp_is_the_first_entry(self):
        # list_activity() (activity_log.py) already returns newest-first - this
        # function trusts that ordering rather than re-sorting.
        entries = [_entry(2, "a@x.com", "x", hour=12), _entry(1, "a@x.com", "x", hour=10)]
        summary = activity_insights.summarize_activity(entries)
        self.assertEqual(summary["most_recent_timestamp"], entries[0]["timestamp"])


class DetectUnusualActors(unittest.TestCase):
    def test_below_minimum_actions_returns_empty(self):
        entries = [_entry(i, "a@x.com", "asset.set_owner") for i in range(5)]
        self.assertEqual(activity_insights.detect_unusual_actors(entries), [])

    def test_below_minimum_actors_returns_empty_even_with_enough_actions(self):
        # 40 real actions, but all from a single actor - still too few distinct
        # actors to describe a real cross-actor distribution.
        entries = [_entry(i, "solo@x.com", "asset.set_owner") for i in range(40)]
        self.assertEqual(activity_insights.detect_unusual_actors(entries), [])

    def test_off_hours_actor_is_flagged_with_a_real_reason(self):
        entries = []
        for i in range(25):
            entries.append(_entry(i, "normal@x.com", "asset.set_owner", hour=10, minute=i))
        for i in range(8):
            entries.append(_entry(100 + i, "oddone@x.com", "asset.set_owner", hour=2, minute=i))
        for i in range(3):
            entries.append(_entry(200 + i, "third@x.com", "exception.create", hour=11))

        results = activity_insights.detect_unusual_actors(entries)
        by_actor = {r["actor"]: r for r in results}
        self.assertTrue(by_actor["oddone@x.com"]["is_anomaly"])
        self.assertGreater(len(by_actor["oddone@x.com"]["reasons"]), 0)
        self.assertEqual(by_actor["oddone@x.com"]["off_hours_fraction"], 1.0)
        # Sorted most-anomalous (most negative score) first.
        scores = [r["anomaly_score"] for r in results]
        self.assertEqual(scores, sorted(scores))

    def test_self_approval_fraction_is_computed_from_real_request_and_approve_pairs(self):
        entries = [_entry(i, "normal@x.com", "asset.set_owner", hour=10, minute=i) for i in range(25)]
        entries += [_entry(50 + i, "other@x.com", "asset.set_owner", hour=11, minute=i) for i in range(8)]
        entries.append(_entry(200, "selfapprover@x.com", "approval.request", details={"finding_id": "FIND-1"}))
        entries.append(_entry(201, "selfapprover@x.com", "approval.approve", details={"finding_id": "FIND-1"}))

        results = activity_insights.detect_unusual_actors(entries)
        by_actor = {r["actor"]: r for r in results}
        self.assertEqual(by_actor["selfapprover@x.com"]["self_approval_fraction"], 1.0)
        self.assertEqual(by_actor["normal@x.com"]["self_approval_fraction"], 0.0)

    def test_does_not_mutate_input(self):
        entries = [_entry(i, "a@x.com", "asset.set_owner") for i in range(20)]
        entries += [_entry(50 + i, "b@x.com", "asset.set_owner") for i in range(20)]
        entries += [_entry(100 + i, "c@x.com", "asset.set_owner") for i in range(20)]
        entries_before = [dict(e) for e in entries]
        activity_insights.detect_unusual_actors(entries)
        self.assertEqual(entries, entries_before)


if __name__ == "__main__":
    unittest.main()
