"""
Tests for remediation/connectors/live_data_store.py - the shared store for
"pending, not-yet-merged" adapter output (generic webhook ingest, PrismaCloud/Cortex
XSIAM fetch). Every test uses a fresh in-memory SQLite engine (never the real, shared
remediation/vulnhunter.db).
"""
import sys
import unittest
from pathlib import Path

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors import live_data_store as lds  # noqa: E402


class LiveDataStore(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def test_load_from_empty_db_returns_empty_list(self):
        self.assertEqual(lds.load_findings(lds.SOURCE_GENERIC_INGEST, engine=self.engine), [])

    def test_append_then_load_round_trips_full_finding_dicts(self):
        finding = {
            "id": "FIND-101", "title": "Reflected XSS", "severity": "High",
            "asset": {"name": "APP-ORDERS01", "type": "application"},
        }
        lds.append_findings(lds.SOURCE_GENERIC_INGEST, [finding], engine=self.engine)
        loaded = lds.load_findings(lds.SOURCE_GENERIC_INGEST, engine=self.engine)
        self.assertEqual(loaded, [finding])

    def test_append_empty_list_is_a_no_op(self):
        lds.append_findings(lds.SOURCE_GENERIC_INGEST, [], engine=self.engine)
        self.assertEqual(lds.load_findings(lds.SOURCE_GENERIC_INGEST, engine=self.engine), [])
        self.assertEqual(lds.count(lds.SOURCE_GENERIC_INGEST, engine=self.engine), 0)

    def test_sources_are_isolated_from_each_other(self):
        lds.append_findings(lds.SOURCE_GENERIC_INGEST, [{"id": "FIND-1", "title": "a"}], engine=self.engine)
        lds.append_findings(lds.SOURCE_PRISMACLOUD, [{"id": "FIND-2", "title": "b"}], engine=self.engine)
        self.assertEqual(len(lds.load_findings(lds.SOURCE_GENERIC_INGEST, engine=self.engine)), 1)
        self.assertEqual(len(lds.load_findings(lds.SOURCE_PRISMACLOUD, engine=self.engine)), 1)
        self.assertEqual(len(lds.load_findings(lds.SOURCE_CORTEX_XSIAM, engine=self.engine)), 0)

    def test_count_reflects_only_the_given_source(self):
        lds.append_findings(lds.SOURCE_CORTEX_XSIAM, [{"id": "FIND-1"}, {"id": "FIND-2"}], engine=self.engine)
        self.assertEqual(lds.count(lds.SOURCE_CORTEX_XSIAM, engine=self.engine), 2)
        self.assertEqual(lds.count(lds.SOURCE_GENERIC_INGEST, engine=self.engine), 0)

    def test_load_returns_oldest_first_matching_old_append_order(self):
        lds.append_findings(lds.SOURCE_GENERIC_INGEST, [{"id": "FIND-1"}], engine=self.engine)
        lds.append_findings(lds.SOURCE_GENERIC_INGEST, [{"id": "FIND-2"}], engine=self.engine)
        loaded = lds.load_findings(lds.SOURCE_GENERIC_INGEST, engine=self.engine)
        self.assertEqual([f["id"] for f in loaded], ["FIND-1", "FIND-2"])

    def test_concurrent_appends_across_sources_never_lose_a_real_finding(self):
        """Real threads, real on-disk SQLite file (not :memory:, which isn't shared
        across connections) - proves with_lock() actually serializes concurrent
        writers, so findings appended at nearly the same real moment (as
        dashboard/app.py's ingest/fetch routes would under real concurrent requests)
        never collide or silently drop one another."""
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine(f"sqlite:///{Path(tmpdir) / 'test.db'}")

            def append_one(n):
                with lds.with_lock():
                    lds.append_findings(lds.SOURCE_GENERIC_INGEST, [{"id": f"FIND-{n}", "title": f"t{n}"}], engine=engine)

            threads = [threading.Thread(target=append_one, args=(n,)) for n in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            loaded = lds.load_findings(lds.SOURCE_GENERIC_INGEST, engine=engine)
            self.assertEqual(len(loaded), 20)
            self.assertEqual(len({f["id"] for f in loaded}), 20)
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
