"""
Shared store for "pending, not-yet-merged-into-the-queue" adapter output: the generic
webhook ingest adapter (POST /api/ingest/generic) and the PrismaCloud/Cortex XSIAM
connectors' own fetch routes each write real, already-normalized Finding-schema
records here - one row per finding in the shared SQLite database (see
remediation/utils/db.py), previously three separate flat JSON files under the
gitignored remediation/live-data/ (real runtime output, not seed data). Deliberately
NOT auto-merged into remediation/output/normalized-findings.json or the live queue -
see dashboard/app.py's own routes for why; this store exists so that data survives
across requests and stays genuinely inspectable (via `/remediate <file>` or a direct
DB query), not so it gets folded in silently.

Each finding is stored as an opaque JSON blob (the `data` column) - nothing in this
module (or its callers) queries into a finding's individual fields, so there's no
reason to normalize the Finding schema's many fields into real columns the way, e.g.,
activity_log's own actor/action are. `source` distinguishes which of the three writers
produced a given row, letting all three share one table instead of three
near-identical ones.
"""
import json
from pathlib import Path

from sqlalchemy import func, insert, select

from remediation.utils import db as db_module
from remediation.utils.file_lock import FileLock

SOURCE_GENERIC_INGEST = "generic-ingest"
SOURCE_PRISMACLOUD = "prismacloud"
SOURCE_CORTEX_XSIAM = "cortex-xsiam"

# Real, on-disk lock guarding the read-existing-then-assign-ids-then-insert cycle every
# writer above does (id assignment happens in the caller, not here - see
# with_lock()) - the same class of race every other migrated store in this repo
# guards against: two concurrent fetches/ingests could otherwise both compute the same
# "next" id from the same stale read and collide on insert.
LOCK_PATH = Path(__file__).resolve().parent / ".live_data_findings.lock"


def with_lock(lock_path=None):
    """Returns the FileLock context manager a caller holds across its own
    read-existing / compute-fresh-ids / append cycle - see dashboard/app.py's
    generic-ingest/PrismaCloud/Cortex-XSIAM routes for the actual read+id-assignment
    logic, which stays there since it needs `real_findings` (the real pipeline's own
    committed findings, entirely unrelated to this store) to compute a real,
    non-colliding FIND-N id."""
    return FileLock(lock_path or LOCK_PATH)


def load_findings(source, engine=None):
    """Every finding already written for this source, oldest first (matching the old
    JSON file's append order)."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    table = db_module.live_data_findings
    with engine.connect() as conn:
        rows = conn.execute(
            select(table).where(table.c.source == source).order_by(table.c.id),
        ).mappings().all()
    return [json.loads(r["data"]) for r in rows]


def append_findings(source, findings, engine=None):
    """Appends `findings` (each a real, already-normalized Finding-schema dict with
    its own unique `id` already assigned by the caller - see with_lock() above for
    why id assignment isn't done in this function) as new rows for this source. A
    no-op if `findings` is empty, matching the old code's "only write if there's
    something new" behavior (never rewrites the file/table just to no-op)."""
    if not findings:
        return
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    rows = [{"id": f["id"], "source": source, "data": json.dumps(f)} for f in findings]
    with engine.begin() as conn:
        conn.execute(insert(db_module.live_data_findings), rows)


def count(source, engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    table = db_module.live_data_findings
    with engine.connect() as conn:
        return conn.execute(
            select(func.count()).select_from(table).where(table.c.source == source),
        ).scalar_one()
