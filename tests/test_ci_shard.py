"""The CI shard splitter puts every test module in exactly one shard, deterministically."""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import ci_shard  # noqa: E402


class ShardTests(unittest.TestCase):
    def test_every_module_in_exactly_one_shard(self):
        every = sorted(f"tests.{p.stem}" for p in (ROOT / "tests").glob("test_*.py"))
        for count in (1, 3, 4, 7):
            parts = ci_shard.shards(count)
            flat = [m for s in parts for m in s]
            self.assertEqual(sorted(flat), every)
            self.assertEqual(len(flat), len(set(flat)))

    def test_it_is_deterministic_and_reasonably_balanced(self):
        self.assertEqual(ci_shard.shards(4), ci_shard.shards(4))
        sizes = [sum((ROOT / "tests" / (m.split(".")[1] + ".py")).stat().st_size for m in s) for s in ci_shard.shards(4)]
        self.assertLess(max(sizes), 1.5 * min(sizes))

    def test_command_line_prints_the_shard_and_rejects_a_bad_index(self):
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "ci_shard.py"), "2", "4"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertEqual(out.stdout.split(), ci_shard.shards(4)[1])
        bad = subprocess.run([sys.executable, str(ROOT / "scripts" / "ci_shard.py"), "5", "4"], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
