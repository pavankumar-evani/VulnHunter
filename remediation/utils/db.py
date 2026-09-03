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

from sqlalchemy import Boolean, Column, Float, Integer, MetaData, String, Table, Text, create_engine

from remediation.utils.file_lock import FileLock

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "vulnhunter.db"
# Real, on-disk lock guarding schema creation specifically (see ensure_schema below) -
# separate from every store module's own per-record lock, since two DIFFERENT stores'
# very first calls (each holding only their own lock) could otherwise still race on
# creating tables on a brand-new DB file.
_SCHEMA_LOCK_PATH = Path(__file__).resolve().parent / ".db_schema.lock"

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



# One row per exception (risk-acceptance waiver) - replacing exceptions.json's flat
# list. String id ("EXC-N") kept as the primary key, not switched to a DB autoincrement
# int, since remediation/exceptions/store.py's own _next_id() scanning behavior is
# preserved as-is (see that module's migration notes) rather than changed here too.
exceptions = Table(
    "exceptions", metadata,
    Column("id", String, primary_key=True),
    Column("finding_id", String, nullable=False),
    Column("reason", Text, nullable=False),
    Column("requested_by", String, nullable=False),
    Column("approved_by", String, nullable=False),
    Column("created_on", String, nullable=False),
    Column("expires_on", String, nullable=False),
    Column("status", String, nullable=False),
    Column("revoked_by", String, nullable=True),
    Column("revoked_at", String, nullable=True),
)

# One row per remediation approval request - replacing remediation_approvals.json's
# flat list. `scheduled_window` is stored as JSON-encoded text (it's a real nested
# dict, e.g. {"date": ..., ...}) rather than normalized into its own columns - it's
# opaque to every caller except the page that renders it, same "don't normalize what
# nothing queries by" reasoning as ai_usage_log's `usage` column below.
remediation_approvals = Table(
    "remediation_approvals", metadata,
    Column("id", String, primary_key=True),
    Column("finding_id", String, nullable=False),
    Column("requested_by", String, nullable=False),
    Column("scheduled_window", Text, nullable=True),  # JSON-encoded dict
    Column("created_on", String, nullable=False),
    Column("status", String, nullable=False),
    Column("approved_by", String, nullable=True),
    Column("approved_at", String, nullable=True),
    Column("ad_group_validated", Boolean, nullable=True),
    Column("rejected_by", String, nullable=True),
    Column("rejected_at", String, nullable=True),
    Column("rejection_reason", String, nullable=True),
    Column("staging_validated_by", String, nullable=True),
    Column("staging_validated_at", String, nullable=True),
    Column("triggered_by", String, nullable=True),
    Column("triggered_at", String, nullable=True),
)

# One row per activity-log entry - append-only, real DB autoincrement replacing the old
# len(entries)+1 id computation (identical sequence for an append-only, never-deleted
# table, and removes the need to scan+compute the next id by hand).
activity_log = Table(
    "activity_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("actor", String, nullable=False),
    Column("action", String, nullable=False),
    Column("target", String, nullable=True),
    Column("details", Text, nullable=True),  # JSON-encoded dict
    Column("timestamp", String, nullable=False),
)

# One row per AI-usage-log entry - same append-only/autoincrement reasoning as
# activity_log above. `usage` is JSON-encoded text (the 4-field token-count dict) -
# nothing queries into its individual fields, only total_tokens (its own real column,
# since tokens_used_today()/usage_by_user() sum it directly).
ai_usage_log = Table(
    "ai_usage_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("actor", String, nullable=False),
    Column("route", String, nullable=False),
    Column("model", String, nullable=True),
    Column("usage", Text, nullable=True),  # JSON-encoded {input_tokens, output_tokens, ...}
    Column("total_tokens", Integer, nullable=True),
    Column("total_cost_usd", Float, nullable=True),
    Column("extraction_ok", Boolean, nullable=False),
    Column("timestamp", String, nullable=False),
)


# One row per asset, keyed by its real asset name - replacing asset_ownership.json's
# {asset_name: {owner, team, ...}} shape directly. Every column besides the key is
# nullable: a real asset row is built up incrementally, one field group at a time (a
# "set owner" edit doesn't also set facing/environment), unlike the append-only or
# full-record stores above. `remediation_schedule` is JSON-encoded text (a real nested
# {cadence, maintenance_window} dict or None) - opaque to every caller except the page
# that renders it, same reasoning as the JSON-encoded columns above.
asset_ownership = Table(
    "asset_ownership", metadata,
    Column("asset_name", String, primary_key=True),
    Column("owner", String, nullable=True),
    Column("team", String, nullable=True),
    Column("facing", String, nullable=True),
    Column("environment", String, nullable=True),
    Column("remediation_schedule", Text, nullable=True),  # JSON-encoded dict
    Column("ip", String, nullable=True),
    Column("mac", String, nullable=True),
)


# One row per local user account - replacing dashboard/auth/users.json's
# {email: {name, role, team, password_hash}} shape. Every column but `team` is
# required (create_user() always sets name/role/password_hash together at creation),
# unlike asset_ownership above where most columns start unset.
users = Table(
    "users", metadata,
    Column("email", String, primary_key=True),
    Column("name", String, nullable=False),
    Column("role", String, nullable=False),
    Column("team", String, nullable=True),
    Column("password_hash", String, nullable=False),
)

# One row per finding written by one of three "pending, not-yet-merged-into-the-queue"
# adapters: the generic ingest webhook, and the PrismaCloud/Cortex XSIAM connectors'
# own fetch routes (see remediation/connectors/live_data_store.py) - previously three
# separate flat JSON files under remediation/live-data/. `data` is the finding's own
# full, already-normalized Finding-schema dict, JSON-encoded whole rather than
# exploded into columns - nothing queries into a finding's individual fields here, so
# there's no reason to model the (large, evolving) Finding schema as real columns the
# way, e.g., activity_log's own actor/action are. `source` distinguishes which of the
# three writers produced a given row, letting all three share one table.
live_data_findings = Table(
    "live_data_findings", metadata,
    Column("id", String, primary_key=True),
    Column("source", String, nullable=False),
    Column("data", Text, nullable=False),
)


def ensure_schema(engine):
    """Creates any of this module's tables that don't already exist. Idempotent and
    cheap - safe to call on every access rather than requiring a separate migration
    step, since current record counts are tiny and there's no other schema-versioning
    need yet.

    Locked: create_all()'s default checkfirst=True is a check-then-create race - two
    callers hitting a brand-new DB file at nearly the same real moment (even from two
    DIFFERENT store modules, each holding only its own per-record lock, if either of
    them) can both see "table doesn't exist yet" and both attempt to create it, and
    the second CREATE TABLE fails with "table already exists" (confirmed: this is a
    real, reproducible failure, not a hypothetical one - a 20-thread concurrency test
    against a fresh on-disk DB hit it directly). This lock is scoped to schema
    creation specifically, separate from every store's own lock, since it's the one
    piece every store's first-ever access shares."""
    with FileLock(_SCHEMA_LOCK_PATH):
        metadata.create_all(engine, tables=[
            alert_state, schedule_state, exceptions, remediation_approvals,
            activity_log, ai_usage_log, asset_ownership, users, live_data_findings,
        ])
