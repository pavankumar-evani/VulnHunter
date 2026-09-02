"""
Shared SQLite persistence layer - the first real database backing for VulnHunter's
record stores, replacing ad hoc flat-JSON read-modify-write. See the project's
production-readiness plan for the full migration this is part of; this module starts
with the two stores that had a confirmed, currently-active write race
(alert_state/schedule_state).

One shared engine per process, created lazily so importing this module never touches
disk. Each caller opens its own short-lived connection/transaction - SQLite's own
locking gives real atomicity for a single statement, but a caller whose critical
section spans more than one statement (or slow I/O like sending an email) still needs
its own explicit mutual exclusion around that whole section - see
remediation/utils/file_lock.py for the primitive already used for that.

Tests inject a separate `engine=` (typically `create_engine("sqlite:///:memory:")`)
instead of a file path, mirroring the exact same "isolate storage per test" intent the
old `path=None` parameter served on the JSON-backed stores.
"""
from pathlib import Path

from sqlalchemy import Column, MetaData, String, Table, create_engine

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "vulnhunter.db"

_default_engine = None


def get_engine():
    """The shared, process-lifetime engine for the real on-disk DB, created lazily on
    first call. Tests should build their own isolated engine directly
    (`create_engine("sqlite:///:memory:")`) rather than calling this."""
    global _default_engine
    if _default_engine is None:
        _default_engine = create_engine(f"sqlite:///{DEFAULT_DB_PATH}")
    return _default_engine


metadata = MetaData()

# One row per (subscription, already-alerted finding) - a normalized dedup-tracking
# table, replacing alert_state.json's {subscription_id: [finding_id, ...]} shape.
alert_state = Table(
    "alert_state", metadata,
    Column("subscription_id", String, primary_key=True),
    Column("finding_id", String, primary_key=True),
)

# One row per subscription - replacing schedule_state.json's
# {subscription_id: last_sent_at_iso} shape directly, no normalization needed.
schedule_state = Table(
    "schedule_state", metadata,
    Column("subscription_id", String, primary_key=True),
    Column("last_sent_at", String, nullable=True),
)


def ensure_schema(engine):
    """Creates any of this module's tables that don't already exist. Idempotent and
    cheap - safe to call on every access rather than requiring a separate migration
    step, since current record counts are tiny and there's no other schema-versioning
    need yet."""
    metadata.create_all(engine, tables=[alert_state, schedule_state])
