"""Migration policy: expand / backfill / contract.

An application rollback must leave the database valid, so a normal release only EXPANDS the schema (new tables, new nullable columns,
backfills). A destructive step (drop, rename, truncate, delete) is a CONTRACT migration: it may ship only in a later release, after the
release that stopped using the old column is no longer one you would roll back to. See docs/RELEASE_PROCESS.md. No contract migration exists
today, so none is allowed without being recorded here deliberately.
"""
import inspect
import re
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine

from remediation.utils import db, migrations

DESTRUCTIVE = [
    (r"\bDROP\s+(TABLE|COLUMN|INDEX|CONSTRAINT)", "DROP"),
    (r"\bRENAME\b", "RENAME"),
    (r"ALTER\s+TABLE[^\n]*\bDROP\b", "ALTER ... DROP"),
    (r"\bTRUNCATE\b", "TRUNCATE"),
    (r"\bDELETE\s+FROM\b(?![^\n]*\bWHERE\b)", "DELETE FROM without WHERE"),
    (r"\.drop\(|drop_all|drop_column|drop_table|rename_table|alter_column", "SQLAlchemy drop/rename"),
]
CONTRACT_ALLOWED = set()  # migration numbers deliberately recorded as contract steps (with the release gap documented)


class MigrationPolicyTests(unittest.TestCase):
    def test_numbered_consecutively_from_one(self):
        self.assertEqual([m[0] for m in migrations.MIGRATIONS], list(range(1, len(migrations.MIGRATIONS) + 1)))

    def test_every_migration_is_expand_only(self):
        for num, name, fn in migrations.MIGRATIONS:
            if num in CONTRACT_ALLOWED:
                continue
            src = inspect.getsource(fn)
            for pattern, label in DESTRUCTIVE:
                self.assertIsNone(
                    re.search(pattern, src, re.I),
                    f"migration {num} ({name}) contains {label}. A release must be rollback-safe: expand (add nullable columns/tables), "
                    "backfill, and only in a LATER release, once no version you could roll back to reads the old shape, contract "
                    "(drop/rename). Split this into an expand now and a contract later; see docs/RELEASE_PROCESS.md.")

    def test_idempotent_on_a_temp_database(self):
        with tempfile.TemporaryDirectory() as d:
            engine = create_engine(f"sqlite:///{Path(d) / 't.db'}")
            db.ensure_schema(engine)
            migrations.apply(engine)
            for num, name, fn in migrations.MIGRATIONS:
                fn(engine)
                fn(engine)  # twice more: must not raise or change the outcome
            self.assertEqual(migrations.pending(engine), [])
            self.assertEqual(migrations.apply(engine), [])
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
