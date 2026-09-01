"""
Tests for remediation/audit/ai_usage_log.py - the real per-call AI usage/cost log and
its server-side daily-limit check.
"""
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.audit import ai_usage_log  # noqa: E402


class ExtractUsage(unittest.TestCase):
    def test_extracts_snake_case_top_level_usage(self):
        response = {
            "total_cost_usd": 0.0123,
            "usage": {"input_tokens": 500, "output_tokens": 120},
        }
        model, usage, cost, ok = ai_usage_log.extract_usage(response)
        self.assertTrue(ok)
        self.assertEqual(cost, 0.0123)
        self.assertEqual(usage["input_tokens"], 500)
        self.assertEqual(usage["output_tokens"], 120)

    def test_extracts_camel_case_model_usage(self):
        response = {
            "model_usage": {
                "claude-sonnet-5": {
                    "inputTokens": 800, "outputTokens": 200,
                    "cacheReadInputTokens": 50, "cacheCreationInputTokens": 10,
                    "costUSD": 0.05,
                },
            },
        }
        model, usage, cost, ok = ai_usage_log.extract_usage(response)
        self.assertTrue(ok)
        self.assertEqual(model, "claude-sonnet-5")
        self.assertEqual(usage["input_tokens"], 800)
        self.assertEqual(usage["cache_read_input_tokens"], 50)

    def test_missing_fields_are_none_not_zero(self):
        model, usage, cost, ok = ai_usage_log.extract_usage({"result": "hi", "is_error": False})
        self.assertFalse(ok)
        self.assertIsNone(cost)
        self.assertTrue(all(v is None for v in usage.values()))

    def test_non_dict_response_is_handled_without_crashing(self):
        model, usage, cost, ok = ai_usage_log.extract_usage("not even json")
        self.assertFalse(ok)
        self.assertIsNone(model)


class UsageLogStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "ai_usage_log.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_record_and_list_round_trip(self):
        ai_usage_log.record_usage(
            "alice@example.com", "ai-assist", "claude-sonnet-5",
            {"input_tokens": 100, "output_tokens": 50, "cache_creation_input_tokens": None, "cache_read_input_tokens": None},
            0.01, True, path=self.path,
        )
        entries = ai_usage_log.list_usage(path=self.path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["actor"], "alice@example.com")
        self.assertEqual(entries[0]["total_tokens"], 150)

    def test_unknown_extraction_records_none_total_not_zero(self):
        ai_usage_log.record_usage(
            "bob@example.com", "vulnhunt", None,
            {"input_tokens": None, "output_tokens": None, "cache_creation_input_tokens": None, "cache_read_input_tokens": None},
            None, False, path=self.path,
        )
        entries = ai_usage_log.list_usage(path=self.path)
        self.assertIsNone(entries[0]["total_tokens"])

    def test_usage_by_user_aggregates_and_counts_unknown_separately(self):
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 100, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, path=self.path)
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 200, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.02, True, path=self.path)
        ai_usage_log.record_usage("alice@example.com", "vulnhunt", None, {"input_tokens": None, "output_tokens": None, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, None, False, path=self.path)
        by_user = ai_usage_log.usage_by_user(path=self.path)
        self.assertEqual(by_user["alice@example.com"]["call_count"], 3)
        self.assertEqual(by_user["alice@example.com"]["total_tokens"], 300)
        self.assertAlmostEqual(by_user["alice@example.com"]["total_cost_usd"], 0.03)
        self.assertEqual(by_user["alice@example.com"]["unknown_cost_calls"], 1)

    def test_tokens_used_today_excludes_earlier_days(self):
        yesterday = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        today = datetime.datetime.now(datetime.timezone.utc)
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 999, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.1, True, path=self.path, as_of=yesterday)
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 100, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, path=self.path, as_of=today)
        self.assertEqual(ai_usage_log.tokens_used_today("alice@example.com", path=self.path, as_of=today), 100)


class WouldExceedLimit(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "ai_usage_log.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_no_limit_configured_never_exceeds(self):
        exceeded, limit, used = ai_usage_log.would_exceed_limit("alice@example.com", {}, path=self.path)
        self.assertFalse(exceeded)
        self.assertIsNone(limit)

    def test_global_limit_enforced_once_reached(self):
        config = {"daily_token_limit_per_user": 100}
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 100, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, path=self.path)
        exceeded, limit, used = ai_usage_log.would_exceed_limit("alice@example.com", config, path=self.path)
        self.assertTrue(exceeded)
        self.assertEqual(used, 100)

    def test_per_user_override_takes_precedence_over_global(self):
        config = {"daily_token_limit_per_user": 100, "per_user_overrides": {"alice@example.com": 1000}}
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 500, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, path=self.path)
        exceeded, limit, used = ai_usage_log.would_exceed_limit("alice@example.com", config, path=self.path)
        self.assertFalse(exceeded)  # under alice's own 1000 override, even though over the 100 global default
        self.assertEqual(limit, 1000)

    def test_unrelated_user_not_affected_by_someone_elses_usage(self):
        config = {"daily_token_limit_per_user": 100}
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 500, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, path=self.path)
        exceeded, limit, used = ai_usage_log.would_exceed_limit("bob@example.com", config, path=self.path)
        self.assertFalse(exceeded)
        self.assertEqual(used, 0)


if __name__ == "__main__":
    unittest.main()
