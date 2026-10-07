"""Splits the test modules into balanced shards so CI can run them in parallel.

Usage: python scripts/ci_shard.py <shard-index> <shard-count>   (index is 1-based)
Prints the dotted module names of that shard, one per line. Every test_*.py file lands in exactly one shard. File size is the
balancing weight (a rough proxy for run time); the assignment is deterministic, so a given file always goes to the same shard
for a given set of files.
"""
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent / "tests"


def shards(count):
    files = sorted(TESTS.glob("test_*.py"), key=lambda p: (-p.stat().st_size, p.name))
    loads = [0] * count
    out = [[] for _ in range(count)]
    for f in files:
        i = loads.index(min(loads))
        out[i].append(f"tests.{f.stem}")
        loads[i] += max(f.stat().st_size, 1)
    return [sorted(s) for s in out]


if __name__ == "__main__":
    index, count = int(sys.argv[1]), int(sys.argv[2])
    if not 1 <= index <= count:
        raise SystemExit("shard index must be between 1 and the shard count")
    print("\n".join(shards(count)[index - 1]))
