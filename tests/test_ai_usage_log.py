"""
Tests for remediation/audit/ai_usage_log.py - the real per-call AI usage/cost log and
its server-side daily-limit check. Storage tests use a fresh in-memory SQLite engine
(never the real, shared remediation/vulnhunter.db).
"""
import datetime
import sys
import unittest
from pathlib import Path

from sqlalchemy import create_engine

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
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def test_record_and_list_round_trip(self):
        ai_usage_log.record_usage(
            "alice@example.com", "ai-assist", "claude-sonnet-5",
            {"input_tokens": 100, "output_tokens": 50, "cache_creation_input_tokens": None, "cache_read_input_tokens": None},
            0.01, True, engine=self.engine,
        )
        entries = ai_usage_log.list_usage(engine=self.engine)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["actor"], "alice@example.com")
        self.assertEqual(entries[0]["total_tokens"], 150)

    def test_unknown_extraction_records_none_total_not_zero(self):
        ai_usage_log.record_usage(
            "bob@example.com", "vulnhunt", None,
            {"input_tokens": None, "output_tokens": None, "cache_creation_input_tokens": None, "cache_read_input_tokens": None},
            None, False, engine=self.engine,
        )
        entries = ai_usage_log.list_usage(engine=self.engine)
        self.assertIsNone(entries[0]["total_tokens"])

    def test_usage_by_user_aggregates_and_counts_unknown_separately(self):
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 100, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, engine=self.engine)
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 200, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.02, True, engine=self.engine)
        ai_usage_log.record_usage("alice@example.com", "vulnhunt", None, {"input_tokens": None, "output_tokens": None, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, None, False, engine=self.engine)
        by_user = ai_usage_log.usage_by_user(engine=self.engine)
        self.assertEqual(by_user["alice@example.com"]["call_count"], 3)
        self.assertEqual(by_user["alice@example.com"]["total_tokens"], 300)
        self.assertAlmostEqual(by_user["alice@example.com"]["total_cost_usd"], 0.03)
        self.assertEqual(by_user["alice@example.com"]["unknown_cost_calls"], 1)

    def test_concurrent_record_usage_calls_never_lose_a_real_call(self):
        """Real threads, real on-disk SQLite file (not :memory:, which isn't shared
        across connections) - proves a plain INSERT relying on a real DB autoincrement
        id is enough on its own: unlike the old JSON version, record_usage() no longer
        takes a FileLock (see its own docstring for why), so this test is what actually
        backs that design decision, not just the reasoning behind it."""
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine(f"sqlite:///{Path(tmpdir) / 'test.db'}")

            def record_one(n):
                ai_usage_log.record_usage(
                    f"user{n}@example.com", "ai-assist", "claude-sonnet-5",
                    {"input_tokens": 10, "output_tokens": 5, "cache_creation_input_tokens": None, "cache_read_input_tokens": None},
                    0.001, True, engine=engine,
                )

            threads = [threading.Thread(target=record_one, args=(n,)) for n in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            entries = ai_usage_log.list_usage(engine=engine)
            self.assertEqual(len(entries), 20)
            self.assertEqual(len({e["id"] for e in entries}), 20)  # every id genuinely unique
            # Windows won't delete a file a pooled connection still has open - dispose
            # releases every connection in the pool before the tmpdir cleanup below.
            engine.dispose()

    def test_tokens_used_today_excludes_earlier_days(self):
        yesterday = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        today = datetime.datetime.now(datetime.timezone.utc)
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 999, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.1, True, engine=self.engine, as_of=yesterday)
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 100, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, engine=self.engine, as_of=today)
        self.assertEqual(ai_usage_log.tokens_used_today("alice@example.com", engine=self.engine, as_of=today), 100)


class WouldExceedLimit(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def test_no_limit_configured_never_exceeds(self):
        exceeded, limit, used = ai_usage_log.would_exceed_limit("alice@example.com", {}, engine=self.engine)
        self.assertFalse(exceeded)
        self.assertIsNone(limit)

    def test_global_limit_enforced_once_reached(self):
        config = {"daily_token_limit_per_user": 100}
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 100, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, engine=self.engine)
        exceeded, limit, used = ai_usage_log.would_exceed_limit("alice@example.com", config, engine=self.engine)
        self.assertTrue(exceeded)
        self.assertEqual(used, 100)

    def test_per_user_override_takes_precedence_over_global(self):
        config = {"daily_token_limit_per_user": 100, "per_user_overrides": {"alice@example.com": 1000}}
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 500, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, engine=self.engine)
        exceeded, limit, used = ai_usage_log.would_exceed_limit("alice@example.com", config, engine=self.engine)
        self.assertFalse(exceeded)  # under alice's own 1000 override, even though over the 100 global default
        self.assertEqual(limit, 1000)

    def test_unrelated_user_not_affected_by_someone_elses_usage(self):
        config = {"daily_token_limit_per_user": 100}
        ai_usage_log.record_usage("alice@example.com", "ai-assist", "m", {"input_tokens": 500, "output_tokens": 0, "cache_creation_input_tokens": None, "cache_read_input_tokens": None}, 0.01, True, engine=self.engine)
        exceeded, limit, used = ai_usage_log.would_exceed_limit("bob@example.com", config, engine=self.engine)
        self.assertFalse(exceeded)
        self.assertEqual(used, 0)


if __name__ == "__main__":
    unittest.main()
