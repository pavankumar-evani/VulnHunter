"""
Measures what storing the findings as one whole file costs as the estate grows.

Builds N synthetic findings, then times the operations that touch the whole file: a merge of a
small batch (read, merge, write), a full read, and the database-backed file sync's push (the file
as one stored row). Prints a table so the point where it stops being comfortable is a number, not
a guess.

    python scripts/bench_findings_scale.py 10000 50000 200000
"""
import json
import sys
import tempfile
import time
from pathlib import Path

from sqlalchemy import create_engine

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation.ingest import merge  # noqa: E402
from remediation.utils import file_sync  # noqa: E402


def make(n):
    return [{"id": f"FIND-{i}", "source": "tenable", "source_ref": str(i), "title": f"Vulnerability {i} in a package", "severity": "High",
             "cve": f"CVE-2024-{i:05d}", "cvss": 7.5, "asset": {"name": f"host-{i % 5000}", "type": "unix-server", "os": "Ubuntu 22.04"},
             "description": "x" * 220, "recommended_fix": "Upgrade the package to the fixed version " + "y" * 60,
             "first_seen": "2026-09-01", "last_seen": "2026-10-01", "kev": None, "epss": {"score": 0.12}, "remediation_domain": "unix-server"}
            for i in range(n)]


def t(fn):
    s = time.perf_counter()
    r = fn()
    return time.perf_counter() - s, r


def main(sizes):
    print(f"{'findings':>10} {'file MB':>8} {'read s':>7} {'merge 50 s':>11} {'db push s':>10}")
    for n in sizes:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / "remediation" / "output" / "normalized-findings.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(make(n)), encoding="utf-8")
            mb = path.stat().st_size / 1e6
            read_s, _ = t(lambda: merge.load(path))
            batch = [{"title": f"New {i}", "severity": "High", "asset": {"name": "h"}, "cve": None, "source_ref": f"n{i}"} for i in range(50)]
            merge_s, _ = t(lambda: merge.merge(batch, "tenable", path=path))
            engine = create_engine(f"sqlite:///{root / 'b.db'}")
            fs = file_sync.FileSync(root, engine=engine, interval=0)
            push_s, _ = t(lambda: fs.sync(force=True))
            print(f"{n:>10,} {mb:>8.1f} {read_s:>7.2f} {merge_s:>11.2f} {push_s:>10.2f}", flush=True)
            engine.dispose()


if __name__ == "__main__":
    main([int(a) for a in sys.argv[1:]] or [10000, 50000, 200000])
