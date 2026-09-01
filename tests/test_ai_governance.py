"""Tests for remediation/config/ai_governance.py."""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.config import ai_governance  # noqa: E402


class LoadGovernance(unittest.TestCase):
    def test_missing_file_returns_honest_unconfigured_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            data = ai_governance.load_governance(path=Path(d) / "missing.yaml")
        self.assertIsNone(data["default_model"])
        self.assertIsNone(data["daily_token_limit_per_user"])
        self.assertEqual(data["per_user_overrides"], {})


class SaveGovernance(unittest.TestCase):
    def test_round_trips_valid_config(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ai_governance.yaml"
            ai_governance.save_governance("sonnet", 50000, {"a@example.com": 100000}, path=path)
            data = ai_governance.load_governance(path=path)
        self.assertEqual(data["default_model"], "sonnet")
        self.assertEqual(data["daily_token_limit_per_user"], 50000)
        self.assertEqual(data["per_user_overrides"], {"a@example.com": 100000})

    def test_rejects_unknown_model_alias(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ai_governance.yaml"
            with self.assertRaises(ValueError):
                ai_governance.save_governance("gpt-5", None, {}, path=path)
            self.assertFalse(path.exists())  # rejected before writing anything

    def test_rejects_negative_limit(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ai_governance.yaml"
            with self.assertRaises(ValueError):
                ai_governance.save_governance(None, -5, {}, path=path)

    def test_null_model_and_limit_are_valid(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ai_governance.yaml"
            data = ai_governance.save_governance(None, None, {}, path=path)
        self.assertIsNone(data["default_model"])


if __name__ == "__main__":
    unittest.main()
