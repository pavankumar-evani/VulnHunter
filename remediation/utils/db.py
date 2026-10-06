"""
Shared SQLite persistence layer - the first real database backing for Quanta's
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
import contextlib
import os
import weakref
from pathlib import Path

from sqlalchemy import Boolean, Column, Float, Integer, MetaData, String, Table, Text, UniqueConstraint, create_engine, text

from remediation.utils.file_lock import FileLock

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "quanta.db"
# Real, on-disk lock guarding schema creation specifically (see ensure_schema below) -
# separate from every store module's own per-record lock, since two DIFFERENT stores'
# very first calls (each holding only their own lock) could otherwise still race on
# creating tables on a brand-new DB file.
_SCHEMA_LOCK_PATH = Path(__file__).resolve().parent / ".db_schema.lock"

_default_engine = None
_MIGRATED = weakref.WeakSet()  # engines whose pending migrations have already been applied
_SCHEMA_READY = weakref.WeakSet()  # engines whose tables have already been checked and created: ensure_schema runs on every store call (about 90 call sites)
# and re-checking 70+ tables each time cost most of a store write and, under a file lock, made every concurrent writer wait for it


def forget_schema(engine):
    """Make the next ensure_schema(engine) check the tables again (after the database file was replaced, or a table dropped by hand)."""
    _SCHEMA_READY.discard(engine)
    _MIGRATED.discard(engine)


def get_engine():
    """The shared, process-lifetime engine for the real on-disk DB, created lazily on
    first call. Tests should build their own isolated engine directly
    (`create_engine("sqlite:///:memory:")`) rather than calling this."""
    global _default_engine
    if _default_engine is None:
        _default_engine = create_engine(database_url())
    return _default_engine


def database_url():
    """The SQLAlchemy URL for the shared database. Defaults to the local SQLite file;
    set QUANTA_DATABASE_URL (e.g. postgresql+psycopg2://user:pass@host/quanta) to run the
    same stores on PostgreSQL - the move SQLAlchemy Core was chosen for. The advisory
    file lock still serialises writers on ONE host only; a multi-replica deployment needs
    row-level locking or a single writer (see docs/DEPLOYMENT_ARCHITECTURE.md)."""
    return os.environ.get("QUANTA_DATABASE_URL", "").strip() or f"sqlite:///{DEFAULT_DB_PATH}"


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
    Column("source_mode", String, nullable=True),  # "simulation" for a row written by a simulated asset source; None for live/human-entered
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


# First-class assignment groups (ServiceNow-style "teams"). Before this table a team
# was only ever a free-text string on a user or an asset; this gives a team a real
# identity (description, accountable manager) without replacing those strings - a
# user's / asset's `team` still just names a team here. Teams that exist only as a
# string on a user or asset (every pre-existing deployment) are surfaced too, by
# remediation/assignments/store.py's list_teams(), so nothing has to be migrated.
teams = Table(
    "teams", metadata,
    Column("name", String, primary_key=True),
    Column("description", String, nullable=True),
    Column("manager_email", String, nullable=True),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=True),
)

# One row per finding that has been explicitly assigned (a finding with no row here is
# simply unassigned - the table is sparse, since most of a large queue never needs a
# row). `assignee_email` and `assigned_team` are each optional but at least one is
# always set; `status` is the assignee's own work-state, independent of whether the
# scanner still sees the vulnerability (a "resolved" assignment on a still-open
# finding means "the owner says it's fixed, awaiting rescan", never a silent close).
# Who changed what, and when, lives in activity_log (action "finding.*"), not here.
finding_assignments = Table(
    "finding_assignments", metadata,
    Column("finding_id", String, primary_key=True),
    Column("assignee_email", String, nullable=True),
    Column("assigned_team", String, nullable=True),
    Column("status", String, nullable=False),
    Column("notes", Text, nullable=True),
    Column("assigned_by", String, nullable=False),
    Column("assigned_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)

# In-app support tickets (the helpdesk behind the Support page). Kept in the customer's
# own database on purpose: a ticket can describe their environment, so it is never sent
# to a public tracker. `id` is the numeric key; the human reference is "TKT-<id>".
# Comments are a separate table; `internal` comments are visible to admins only.
support_tickets = Table(
    "support_tickets", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("kind", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("subject", String, nullable=False),
    Column("description", Text, nullable=False),
    Column("status", String, nullable=False),
    Column("requester_email", String, nullable=False),
    Column("assignee_email", String, nullable=True),
    Column("resolution", Text, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
    Column("resolved_at", String, nullable=True),
    # ITSM layer (added after first release; ensure_schema() adds them to an older table)
    Column("team", String, nullable=True),              # routed assignment group
    Column("impact", String, nullable=True),            # individual | team | organization
    Column("priority", String, nullable=True),          # P1..P4 = impact x urgency (severity)
    Column("finding_id", String, nullable=True),        # optional link to a finding
    Column("first_response_at", String, nullable=True),
    Column("response_due_at", String, nullable=True),
    Column("resolution_due_at", String, nullable=True),
    Column("paused_at", String, nullable=True),         # set while waiting on the requester
    Column("reopen_count", Integer, nullable=True),
    Column("csat_score", Integer, nullable=True),       # 1..5, from the requester after resolution
    Column("csat_comment", Text, nullable=True),
    Column("csat_at", String, nullable=True),
)

support_ticket_comments = Table(
    "support_ticket_comments", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ticket_id", Integer, nullable=False),
    Column("author_email", String, nullable=False),
    Column("body", Text, nullable=False),
    Column("internal", Integer, nullable=False, default=0),
    Column("created_at", String, nullable=False),
)


# Stored connector connections (remediation/connections/). Credentials are encrypted as one
# blob (`secrets_blob`) with a key that lives outside the database; `config` holds the
# non-secret settings as JSON. last_* describe the most recent sync.
connections = Table(
    "connections", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False, unique=True),
    Column("type", String, nullable=False),
    Column("config", Text, nullable=True),
    Column("secrets_blob", Text, nullable=True),
    Column("enabled", Integer, nullable=False, default=1),
    Column("schedule_minutes", Integer, nullable=False, default=0),
    Column("last_run_at", String, nullable=True),
    Column("last_status", String, nullable=True),
    Column("last_message", Text, nullable=True),
    Column("last_count", Integer, nullable=True),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)


# Keys that external systems use to call INTO Quanta (remediation/apikeys/). Only a SHA-256
# hash of the key is stored; the key itself is shown once at creation.
api_keys = Table(
    "api_keys", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False),
    Column("prefix", String, nullable=False, index=True),
    Column("key_hash", String, nullable=False),
    Column("scopes", Text, nullable=False),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("expires_at", String, nullable=True),
    Column("last_used_at", String, nullable=True),
    Column("revoked_at", String, nullable=True),
)

# Links between a finding and a ticket in an external system (remediation/connections/links.py).
ticket_links = Table(
    "ticket_links", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("connection_id", Integer, nullable=True),
    Column("finding_id", String, nullable=False, index=True),
    Column("system", String, nullable=False),
    Column("external_id", String, nullable=True),
    Column("external_ref", String, nullable=True),
    Column("state", String, nullable=True),
    Column("last_error", Text, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)


# Coordination between replicas (remediation/coordination/): a named lease with an expiry,
# used for cross-replica locks and for electing the one replica that runs the schedulers.
leases = Table(
    "leases", metadata,
    Column("name", String, primary_key=True),
    Column("holder", String, nullable=False),
    Column("expires_at", Float, nullable=False),
)

# A durable job queue (remediation/coordination/jobs.py). Any replica enqueues; workers claim.
jobs = Table(
    "jobs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("kind", String, nullable=False),
    Column("payload", Text, nullable=False),
    Column("status", String, nullable=False, index=True),
    Column("attempts", Integer, nullable=False, default=0),
    Column("max_attempts", Integer, nullable=False, default=3),
    Column("run_after", Float, nullable=False, index=True),
    Column("locked_by", String, nullable=True),
    Column("locked_until", Float, nullable=True),
    Column("dedupe_key", String, nullable=True, index=True),
    Column("result", Text, nullable=True),
    Column("error", Text, nullable=True),
    Column("created_at", Float, nullable=False),
    Column("updated_at", Float, nullable=False),
)


# Working files shared between replicas when QUANTA_FILES_BACKEND=db (remediation/utils/file_sync.py).
file_snapshots = Table(
    "file_snapshots", metadata,
    Column("path", String, primary_key=True),
    Column("content", Text, nullable=False),
    Column("sha", String, nullable=False),
    Column("version", Integer, nullable=False),
    Column("deleted", Boolean, nullable=False, default=False),
    Column("updated_at", Float, nullable=False),
)


# The client's security controls, per asset or asset pattern (remediation/controls/store.py). `state` is "verified"
# when a connector observed it and "claimed" when a person recorded it.
asset_controls = Table(
    "asset_controls", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("asset_name", String, nullable=False, index=True),
    Column("control_class", String, nullable=False),
    Column("name", String, nullable=False),
    Column("state", String, nullable=False),
    Column("source", String, nullable=False),
    Column("detail", Text, nullable=True),
    Column("last_seen", String, nullable=False),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
)


# AI usage across the organization (remediation/aiusage/). No prompt or response text is ever stored.
ai_usage_events = Table(
    "ai_usage_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", String, nullable=False, index=True),
    Column("source", String, nullable=False),
    Column("event_key", String, nullable=False),
    Column("provider", String, nullable=True),
    Column("model", String, nullable=False, index=True),
    Column("team", String, nullable=True, index=True),
    Column("application", String, nullable=True),
    Column("user_ref", String, nullable=True),
    Column("input_tokens", Integer, nullable=False, default=0),
    Column("output_tokens", Integer, nullable=False, default=0),
    Column("cache_read_tokens", Integer, nullable=False, default=0),
    Column("cache_write_tokens", Integer, nullable=False, default=0),
    Column("request_count", Integer, nullable=False, default=1),
    Column("latency_ms", Integer, nullable=True),
    Column("cost_usd", Float, nullable=True),
    Column("cost_basis", String, nullable=False, default="unknown"),
    Column("received_at", String, nullable=False),
    Column("source_mode", String, nullable=True),  # "simulation" for demonstration data; None for live. Not part of the unique key.
    UniqueConstraint("source", "event_key", name="uq_ai_usage_event"),
)

# AI applications found in the organization (sanctioned, unreviewed or blocked): the shadow-AI list.
ai_apps = Table(
    "ai_apps", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False),
    Column("domain", String, nullable=False, unique=True),
    Column("status", String, nullable=False),
    Column("owner", String, nullable=True),
    Column("users_seen", Integer, nullable=False, default=0),
    Column("requests_seen", Integer, nullable=False, default=0),
    Column("signals", Text, nullable=True),
    Column("first_seen", String, nullable=False),
    Column("last_seen", String, nullable=False),
    Column("note", Text, nullable=True),
)

# Spending or token budgets, by team, application or the whole organization.
ai_budgets = Table(
    "ai_budgets", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scope", String, nullable=False),
    Column("scope_value", String, nullable=True),
    Column("period", String, nullable=False),
    Column("limit_usd", Float, nullable=True),
    Column("limit_tokens", Integer, nullable=True),
    Column("alert_pct", Integer, nullable=False, default=80),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
)


# Threat models (remediation/threatmodel/). Threats are computed from the model on read; only reviews are stored.
threat_models = Table(
    "threat_models", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False),
    Column("description", Text, nullable=True),
    Column("model_json", Text, nullable=False),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
    Column("updated_by", String, nullable=True),
)

threat_reviews = Table(
    "threat_reviews", metadata,
    Column("model_id", Integer, primary_key=True),
    Column("threat_key", String, primary_key=True),
    Column("status", String, nullable=False),
    Column("note", Text, nullable=True),
    Column("reviewer", String, nullable=True),
    Column("updated_at", String, nullable=False),
)


# Governance, risk and compliance (remediation/grc/): frameworks and their controls, the risk register, automated control evidence,
# attestations, and policies with acknowledgements.
grc_frameworks = Table(
    "grc_frameworks", metadata,
    Column("id", String, primary_key=True),
    Column("name", String, nullable=False),
    Column("version", String, nullable=True),
    Column("source", String, nullable=False),
    Column("control_count", Integer, nullable=False, default=0),
    Column("imported_at", String, nullable=False),
)

grc_controls = Table(
    "grc_controls", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("framework_id", String, nullable=False, index=True),
    Column("control_id", String, nullable=False),
    Column("title", String, nullable=False),
    Column("family", String, nullable=True),
    Column("statement", Text, nullable=True),
    UniqueConstraint("framework_id", "control_id", name="uq_grc_control"),
)

grc_risks = Table(
    "grc_risks", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String, nullable=False),
    Column("description", Text, nullable=True),
    Column("category", String, nullable=True),
    Column("owner", String, nullable=True),
    Column("status", String, nullable=False),
    Column("inherent_likelihood", Integer, nullable=False),
    Column("inherent_impact", Integer, nullable=False),
    Column("residual_likelihood", Integer, nullable=True),
    Column("residual_impact", Integer, nullable=True),
    Column("treatment", String, nullable=True),
    Column("treatment_plan", Text, nullable=True),
    Column("due_date", String, nullable=True),
    Column("review_date", String, nullable=True),
    Column("source", String, nullable=False),
    Column("source_ref", String, nullable=True),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)

grc_evidence = Table(
    "grc_evidence", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("test_id", String, nullable=False, index=True),
    Column("result", String, nullable=False),
    Column("metric", Float, nullable=True),
    Column("threshold", Float, nullable=True),
    Column("detail", Text, nullable=True),
    Column("collected_at", String, nullable=False, index=True),
)

grc_attestations = Table(
    "grc_attestations", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("framework_id", String, nullable=False, index=True),
    Column("control_id", String, nullable=False),
    Column("result", String, nullable=False),
    Column("statement", Text, nullable=True),
    Column("attested_by", String, nullable=False),
    Column("attested_at", String, nullable=False),
    Column("valid_until", String, nullable=True),
)

grc_policies = Table(
    "grc_policies", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String, nullable=False),
    Column("version", Integer, nullable=False),
    Column("owner", String, nullable=True),
    Column("status", String, nullable=False),
    Column("body", Text, nullable=False),
    Column("review_date", String, nullable=True),
    Column("updated_at", String, nullable=False),
    Column("updated_by", String, nullable=True),
)

grc_policy_acks = Table(
    "grc_policy_acks", metadata,
    Column("policy_id", Integer, primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("user_email", String, primary_key=True),
    Column("acked_at", String, nullable=False),
)


_SCHEMA_ADVISORY_KEY = 727270001


@contextlib.contextmanager
def _cluster_schema_lock(engine):
    """On PostgreSQL, a session advisory lock so that several replicas starting at once do not
    race to create tables or apply a migration (the file lock above only covers one machine).
    A no-op on SQLite, which has a single process on a single file."""
    if engine.dialect.name != "postgresql":
        yield
        return
    conn = engine.connect()
    try:
        conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": _SCHEMA_ADVISORY_KEY})
        conn.commit()
        yield
    finally:
        try:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _SCHEMA_ADVISORY_KEY})
            conn.commit()
        finally:
            conn.close()


hunts = Table(
    "hunts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String, nullable=False),
    Column("hypothesis", Text, nullable=False),
    Column("source", String, nullable=False),  # generated | manual
    Column("source_ref", String, nullable=True),  # e.g. the CVE a generated hunt came from; unique per source when set
    Column("status", String, nullable=False),  # proposed | active | closed
    Column("outcome", String, nullable=True),  # confirmed | not-found | needs-data
    Column("techniques_json", Text, nullable=False),
    Column("assets_json", Text, nullable=False),
    Column("data_sources_json", Text, nullable=False),
    Column("queries_json", Text, nullable=False),
    Column("notes", Text, nullable=True),
    Column("follow_ups", Text, nullable=True),
    Column("detection_created", Integer, nullable=False, default=0),
    Column("owner", String, nullable=True),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
    Column("closed_at", String, nullable=True),
    UniqueConstraint("source", "source_ref", name="uq_hunts_source_ref"),
)

soc_alerts = Table(
    "soc_alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("source", String, nullable=False),
    Column("external_id", String, nullable=False),
    Column("title", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("asset", String, nullable=True),
    Column("technique", String, nullable=True),
    Column("detail", Text, nullable=True),
    Column("status", String, nullable=False),  # new | investigating | closed
    Column("disposition", String, nullable=True),  # true-positive | benign | false-positive | needs-data
    Column("assignee", String, nullable=True),
    Column("notes", Text, nullable=True),
    Column("occurred_at", String, nullable=True),
    Column("received_at", String, nullable=False),
    Column("closed_at", String, nullable=True),
    Column("rule_name", String, nullable=True),
    Column("entities_json", Text, nullable=True),
    Column("action_taken", String, nullable=True),
    UniqueConstraint("source", "external_id", name="uq_soc_alert_source_ext"),
)

soc_cases = Table(
    "soc_cases", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("impact", String, nullable=False),  # single | multiple | widespread
    Column("priority", String, nullable=False),  # P1..P4
    Column("tier", Integer, nullable=False),  # 1 | 2 | 3: the queue the case sits in
    Column("status", String, nullable=False),  # new | in_progress | pending | escalated | resolved | closed
    Column("assignee", String, nullable=True),
    Column("resolution", String, nullable=True),
    Column("summary", Text, nullable=True),  # the running summary note; rewritten on hand-off and at resolution
    Column("techniques_json", Text, nullable=False),
    Column("entities_json", Text, nullable=False),
    Column("assets_json", Text, nullable=False),
    Column("recommendation", String, nullable=True),  # what the system recommended on opening: the verdict, kept to measure accuracy
    Column("source", String, nullable=False),  # manual | auto | alert
    Column("reopen_count", Integer, nullable=False, default=0),
    Column("escalation_count", Integer, nullable=False, default=0),
    Column("auto_escalated_tiers_json", Text, nullable=False),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("acknowledged_at", String, nullable=True),
    Column("tier_since", String, nullable=False),  # when the case entered its current tier
    Column("picked_up_at", String, nullable=True),  # when the current tier took it
    Column("resolved_at", String, nullable=True),
    Column("closed_at", String, nullable=True),
    Column("updated_at", String, nullable=False),
)

soc_case_events = Table(
    "soc_case_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer, nullable=False, index=True),
    Column("kind", String, nullable=False),  # opened | note | assigned | acknowledged | escalated | auto_escalated | resolved | closed | reopened | alert_linked | priority | evidence
    Column("actor", String, nullable=True),
    Column("body", Text, nullable=True),
    Column("data_json", Text, nullable=True),
    Column("created_at", String, nullable=False),
)

soc_case_alerts = Table(
    "soc_case_alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer, nullable=False, index=True),
    Column("alert_id", Integer, nullable=False),
    Column("linked_at", String, nullable=False),
    UniqueConstraint("case_id", "alert_id", name="uq_soc_case_alert"),
)

detection_usecases = Table(
    "detection_usecases", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("key", String, nullable=False, unique=True),
    Column("kind", String, nullable=False),
    Column("title", String, nullable=False),
    Column("status", String, nullable=False),
    Column("note", Text, nullable=True),
    Column("ai_suggestion", Text, nullable=True),
    Column("data_json", Text, nullable=False),
    Column("decided_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)

darkweb_hits = Table(
    "darkweb_hits", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("dedupe_key", String, nullable=False, unique=True),
    Column("source", String, nullable=False),
    Column("kind", String, nullable=False),  # leak-site-post | supply-chain-post | credential-exposure | mention
    Column("term", String, nullable=False),
    Column("term_kind", String, nullable=False),  # domain | brand | vendor | keyword
    Column("title", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("detail", Text, nullable=True),
    Column("url", String, nullable=True),
    Column("status", String, nullable=False),  # new | reviewing | actioned | dismissed
    Column("note", Text, nullable=True),
    Column("alert_id", Integer, nullable=True),
    Column("first_seen", String, nullable=False),
    Column("updated_at", String, nullable=False),
)

cvd_advisories = Table(
    "cvd_advisories", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("source", String, nullable=False),
    Column("advisory_id", String, nullable=False),
    Column("title", String, nullable=True),
    Column("cves", Text, nullable=True),  # JSON list
    Column("vendor", String, nullable=True),
    Column("product", String, nullable=True),
    Column("severity", String, nullable=True),
    Column("published", String, nullable=True),
    Column("state", String, nullable=True),
    Column("url", String, nullable=True),
    Column("first_seen", String, nullable=False),
    Column("updated_at", String, nullable=False),
    UniqueConstraint("source", "advisory_id", name="uq_cvd_source_id"),
)

darkweb_sources = Table(
    "darkweb_sources", metadata,
    Column("source_id", String, primary_key=True),
    Column("enabled", Integer, nullable=False, default=1),
    Column("last_run_at", String, nullable=True),
    Column("last_status", String, nullable=True),
    Column("last_count", Integer, nullable=True),
)

soc_analysts = Table(
    "soc_analysts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", String, nullable=False, unique=True),
    Column("tier", Integer, nullable=False),
    Column("active", Integer, nullable=False, default=1),
    Column("created_at", String, nullable=False),
)

threat_intel_reports = Table(
    "threat_intel_reports", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String, nullable=False),
    Column("source", String, nullable=True),
    Column("content_hash", String, nullable=False, unique=True),
    Column("extracted_json", Text, nullable=False),
    Column("relevance", Integer, nullable=False),
    Column("priority", String, nullable=False),
    Column("reasons_json", Text, nullable=False),
    Column("hunt_id", Integer, nullable=True),
    Column("received_by", String, nullable=True),
    Column("received_at", String, nullable=False),
)

soc_investigations = Table(
    "soc_investigations", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", Integer, nullable=False),
    Column("verdict", String, nullable=False),  # likely-true-positive | likely-false-positive | escalate-l2
    Column("confidence", String, nullable=False),  # low | medium | high
    Column("reasons_json", Text, nullable=False),
    Column("evidence_json", Text, nullable=False),
    Column("report_md", Text, nullable=False),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
)

detection_rules = Table(
    "detection_rules", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False, unique=True),
    Column("platform", String, nullable=True),
    Column("logic", Text, nullable=True),
    Column("format", String, nullable=False),  # sigma | text
    Column("techniques_json", Text, nullable=False),
    Column("enabled", Integer, nullable=False, default=1),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)

detection_assessments = Table(
    "detection_assessments", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("created_at", String, nullable=False),
    Column("created_by", String, nullable=True),
    Column("window_days", Integer, nullable=False),
    Column("result_json", Text, nullable=False),
)

soar_playbooks = Table(
    "soar_playbooks", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False, unique=True),
    Column("description", Text, nullable=True),
    Column("trigger_json", Text, nullable=False),
    Column("steps_json", Text, nullable=False),
    Column("enabled", Integer, nullable=False, default=1),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
    Column("updated_by", String, nullable=True),
)

soar_runs = Table(
    "soar_runs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("playbook_id", Integer, nullable=False),
    Column("playbook_name", String, nullable=False),
    Column("alert_id", Integer, nullable=True),
    Column("status", String, nullable=False),  # running | waiting-approval | completed | failed | rejected | cancelled
    Column("dry_run", Integer, nullable=False),
    Column("started_by", String, nullable=False),
    Column("started_at", String, nullable=False),
    Column("finished_at", String, nullable=True),
    Column("next_step", Integer, nullable=False, default=0),
    Column("context_json", Text, nullable=False),
    Column("log_json", Text, nullable=False),
)

risk_scenarios = Table(
    "risk_scenarios", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False),
    Column("description", Text, nullable=True),
    Column("asset_scope", String, nullable=True),
    Column("category", String, nullable=False),
    Column("tef_min", Float, nullable=False),
    Column("tef_likely", Float, nullable=False),
    Column("tef_max", Float, nullable=False),
    Column("loss_min", Float, nullable=False),
    Column("loss_likely", Float, nullable=False),
    Column("loss_max", Float, nullable=False),
    Column("options_json", Text, nullable=False),
    Column("status", String, nullable=False),
    Column("owner", String, nullable=True),
    Column("risk_id", Integer, nullable=True),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
    Column("updated_by", String, nullable=True),
)

scan_runs = Table(
    "scan_runs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("asset", String, nullable=False),
    Column("scan_type", String, nullable=False),
    Column("tool", String, nullable=True),
    Column("source", String, nullable=True),
    Column("findings", Integer, nullable=False),
    Column("received_at", String, nullable=False),
    Column("received_by", String, nullable=True),
)

devsecops_status = Table(
    "devsecops_status", metadata,
    Column("asset", String, primary_key=True),
    Column("control_id", String, primary_key=True),
    Column("state", String, nullable=False),
    Column("note", Text, nullable=True),
    Column("set_by", String, nullable=True),
    Column("set_at", String, nullable=False),
)

remediation_factory = Table(
    "remediation_factory", metadata,
    Column("finding_id", String, primary_key=True),
    Column("state", String, nullable=False),
    Column("assignee", String, nullable=True),
    Column("pr_url", String, nullable=True),
    Column("notes", Text, nullable=True),
    Column("queued_by", String, nullable=True),
    Column("queued_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
)

fw_rules = Table(
    "fw_rules", metadata,
    Column("device", String, primary_key=True),
    Column("key", String, primary_key=True),
    Column("position", Integer, nullable=False),
    Column("data_json", Text, nullable=False),
    Column("first_seen", String, nullable=False),
    Column("fingerprint", String, nullable=False),
    Column("certified_at", String, nullable=True),
    Column("certified_by", String, nullable=True),
    Column("decision", String, nullable=True),
    Column("decision_note", Text, nullable=True),
    Column("imported_at", String, nullable=False),
)

fw_requests = Table(
    "fw_requests", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("requester", String, nullable=False),
    Column("request_json", Text, nullable=False),
    Column("justification", Text, nullable=False),
    Column("status", String, nullable=False),
    Column("check_json", Text, nullable=False),
    Column("created_at", String, nullable=False),
    Column("decided_by", String, nullable=True),
    Column("decided_at", String, nullable=True),
    Column("decision_note", Text, nullable=True),
    Column("implemented_at", String, nullable=True),
)

ai_assets = Table(
    "ai_assets", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False, unique=True),
    Column("kind", String, nullable=False),
    Column("data_json", Text, nullable=False),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
    Column("updated_by", String, nullable=True),
)

iam_entitlements = Table(
    "iam_entitlements", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user", String, nullable=False),
    Column("account", String, nullable=False),
    Column("system", String, nullable=False),
    Column("entitlement", String, nullable=False),
    Column("privileged", Boolean, nullable=False, default=False),
    Column("last_login", String, nullable=True),
    Column("status", String, nullable=False),
    Column("manager", String, nullable=True),
    Column("department", String, nullable=True),
    Column("granted_at", String, nullable=True),
    Column("source", String, nullable=False),
    Column("imported_at", String, nullable=False),
)

iam_roster = Table(
    "iam_roster", metadata,
    Column("user", String, primary_key=True),
    Column("status", String, nullable=False),
    Column("manager", String, nullable=True),
    Column("department", String, nullable=True),
    Column("end_date", String, nullable=True),
)

iam_campaigns = Table(
    "iam_campaigns", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False),
    Column("scope_json", Text, nullable=False),
    Column("due_date", String, nullable=False),
    Column("status", String, nullable=False),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
)

iam_review_items = Table(
    "iam_review_items", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("campaign_id", Integer, nullable=False),
    Column("reviewer", String, nullable=False),
    Column("decision", String, nullable=True),
    Column("decided_by", String, nullable=True),
    Column("decided_at", String, nullable=True),
    Column("note", Text, nullable=True),
    Column("snapshot_json", Text, nullable=False),
)

# ---------------------------------------------------------------- API security (inventory, traffic aggregates, classification, protection policies)
api_specs = Table(
    "api_specs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("service", String, nullable=False, unique=True),
    Column("title", String, nullable=True),
    Column("version", String, nullable=True),
    Column("source", String, nullable=False),
    Column("source_ref", String, nullable=True),
    Column("sha256", String, nullable=False),
    Column("hosts_json", Text, nullable=False),
    Column("meta_json", Text, nullable=False),
    Column("endpoints", Integer, nullable=False, default=0),
    Column("content", Text, nullable=False),
    Column("uploaded_by", String, nullable=True),
    Column("uploaded_at", String, nullable=False),
)

api_endpoints = Table(
    "api_endpoints", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("service", String, nullable=False),
    Column("method", String, nullable=False),
    Column("path_key", String, nullable=False),
    Column("template", String, nullable=False),
    Column("in_spec", Boolean, nullable=False, default=False),
    Column("observed", Boolean, nullable=False, default=False),
    Column("spec_json", Text, nullable=True),
    Column("observed_json", Text, nullable=False),
    Column("owner", String, nullable=True),
    Column("exposure_override", String, nullable=True),
    Column("status", String, nullable=False, default="active"),
    Column("notes", Text, nullable=True),
    Column("first_seen", String, nullable=True),
    Column("last_seen", String, nullable=True),
    Column("calls_total", Integer, nullable=False, default=0),
    Column("created_at", String, nullable=False),
    Column("updated_at", String, nullable=False),
    UniqueConstraint("service", "method", "path_key", name="uq_api_endpoint"),
)

api_metrics = Table(
    "api_metrics", metadata,
    Column("endpoint_id", Integer, primary_key=True),
    Column("day", String, primary_key=True),
    Column("calls", Integer, nullable=False, default=0),
    Column("errors", Integer, nullable=False, default=0),
    Column("exceptions", Integer, nullable=False, default=0),
    Column("latency_sum_ms", Float, nullable=False, default=0.0),
    Column("latency_n", Integer, nullable=False, default=0),
    Column("latency_max_ms", Float, nullable=True),
    Column("bytes_in", Integer, nullable=False, default=0),
    Column("bytes_out", Integer, nullable=False, default=0),
    Column("security_events", Integer, nullable=False, default=0),
)

api_actor_hits = Table(
    "api_actor_hits", metadata,
    Column("endpoint_id", Integer, primary_key=True),
    Column("day", String, primary_key=True),
    Column("actor", String, primary_key=True),
    Column("calls", Integer, nullable=False, default=0),
    Column("errors", Integer, nullable=False, default=0),
    Column("bytes_out", Integer, nullable=False, default=0),
    Column("distinct_objects", Integer, nullable=False, default=0),
    Column("ips_json", Text, nullable=True),
)

api_dependencies = Table(
    "api_dependencies", metadata,
    Column("source_service", String, primary_key=True),
    Column("dest_service", String, primary_key=True),
    Column("dest_exposure", String, nullable=True),
    Column("calls", Integer, nullable=False, default=0),
    Column("first_seen", String, nullable=True),
    Column("last_seen", String, nullable=True),
)

api_data_classes = Table(
    "api_data_classes", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False, unique=True),
    Column("priority", Integer, nullable=False),
    Column("description", Text, nullable=True),
    Column("detectors_json", Text, nullable=False),
    Column("patterns_json", Text, nullable=False),
    Column("imported_by", String, nullable=True),
    Column("imported_at", String, nullable=False),
)

api_policies = Table(
    "api_policies", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False, unique=True),
    Column("kind", String, nullable=False),
    Column("mode", String, nullable=False),
    Column("enabled", Boolean, nullable=False, default=True),
    Column("scope_json", Text, nullable=False),
    Column("params_json", Text, nullable=False),
    Column("description", Text, nullable=True),
    Column("version", Integer, nullable=False, default=1),
    Column("approved_by", String, nullable=True),
    Column("approved_version", Integer, nullable=True),
    Column("push_state", String, nullable=False, default="draft"),
    Column("last_push_id", Integer, nullable=True),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("updated_by", String, nullable=True),
    Column("updated_at", String, nullable=False),
)

applications = Table(
    "applications", metadata,
    Column("name", String, primary_key=True),
    Column("environment", String, nullable=True),
    Column("platform", String, nullable=True),
    Column("os", String, nullable=True),
    Column("owner", String, nullable=True),
    Column("team", String, nullable=True),
    Column("business_criticality", String, nullable=True),
    Column("internet_facing", Boolean, nullable=True),
    Column("data_classification", String, nullable=True),
    Column("repo_provider", String, nullable=True),
    Column("repo", String, nullable=True),
    Column("default_branch", String, nullable=True),
    Column("manifest_paths", Text, nullable=True),
    Column("connection_id", Integer, nullable=True),
    Column("notes", Text, nullable=True),
    Column("updated_by", String, nullable=True),
    Column("updated_at", String, nullable=False),
)

api_policy_events = Table(
    "api_policy_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("policy_id", Integer, nullable=False),
    Column("policy_name", String, nullable=False),
    Column("version", Integer, nullable=True),
    Column("action", String, nullable=False),
    Column("actor", String, nullable=True),
    Column("detail_json", Text, nullable=True),
    Column("at", String, nullable=False),
)

api_policy_pushes = Table(
    "api_policy_pushes", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("policy_id", Integer, nullable=False),
    Column("policy_name", String, nullable=False),
    Column("version", Integer, nullable=False),
    Column("mode", String, nullable=False),
    Column("connection_id", Integer, nullable=True),
    Column("status", String, nullable=False),
    Column("http_status", Integer, nullable=True),
    Column("message", Text, nullable=True),
    Column("payload_sha256", String, nullable=False),
    Column("requested_by", String, nullable=True),
    Column("approved_by", String, nullable=True),
    Column("sent_at", String, nullable=False),
    Column("reported_at", String, nullable=True),
    Column("reported_by", String, nullable=True),
)

api_rollout_state = Table(
    "api_rollout_state", metadata,
    Column("item_id", String, primary_key=True),
    Column("done", Boolean, nullable=False, default=False),
    Column("note", Text, nullable=True),
    Column("set_by", String, nullable=True),
    Column("set_at", String, nullable=False),
)

app_sboms = Table(
    "app_sboms", metadata,
    Column("application", String, primary_key=True),
    Column("format", String, nullable=False),
    Column("source", String, nullable=True),
    Column("graph_json", Text, nullable=False),
    Column("component_count", Integer, nullable=False),
    Column("notes_json", Text, nullable=True),
    Column("uploaded_by", String, nullable=True),
    Column("uploaded_at", String, nullable=False),
)

fix_proposals = Table(
    "fix_proposals", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("application", String, nullable=False),
    Column("kind", String, nullable=False),
    Column("finding_ids", Text, nullable=False),
    Column("title", String, nullable=False),
    Column("summary_json", Text, nullable=True),
    Column("provider", String, nullable=True),
    Column("repo", String, nullable=True),
    Column("connection_id", Integer, nullable=True),
    Column("base_branch", String, nullable=True),
    Column("branch", String, nullable=True),
    Column("files_json", Text, nullable=False),
    Column("pr_title", String, nullable=False),
    Column("pr_body", Text, nullable=False),
    Column("test_command", String, nullable=True),
    Column("status", String, nullable=False),
    Column("pr_number", Integer, nullable=True),
    Column("pr_url", String, nullable=True),
    Column("pr_state", String, nullable=True),
    Column("review_state", String, nullable=True),
    Column("checks_state", String, nullable=True),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
    Column("approved_by", String, nullable=True),
    Column("approved_at", String, nullable=True),
    Column("opened_by", String, nullable=True),
    Column("opened_at", String, nullable=True),
    Column("merged_at", String, nullable=True),
    Column("closed_at", String, nullable=True),
    Column("verified_state", String, nullable=True),
    Column("verified_at", String, nullable=True),
    Column("last_synced_at", String, nullable=True),
    Column("last_error", Text, nullable=True),
    Column("notes", Text, nullable=True),
)

gate_runs = Table(
    "gate_runs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("application", String, nullable=False),
    Column("environment", String, nullable=False),
    Column("decision", String, nullable=False),
    Column("detail_json", Text, nullable=False),
    Column("evaluated_by", String, nullable=True),
    Column("evaluated_at", String, nullable=False),
)

devsecops_custom_controls = Table(
    "devsecops_custom_controls", metadata,
    Column("id", String, primary_key=True),
    Column("stage", String, nullable=False),
    Column("title", String, nullable=False),
    Column("why", Text, nullable=False),
    Column("how", Text, nullable=False),
    Column("keywords_json", Text, nullable=True),
    Column("evidence_json", Text, nullable=True),
    Column("created_by", String, nullable=True),
    Column("created_at", String, nullable=False),
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
    if engine in _SCHEMA_READY and engine in _MIGRATED:
        return
    with FileLock(_SCHEMA_LOCK_PATH, timeout=120.0, local=True), _cluster_schema_lock(engine):   # creating every table can take seconds on a slow disk
        metadata.create_all(engine, tables=[
            alert_state, schedule_state, exceptions, remediation_approvals,
            activity_log, ai_usage_log, asset_ownership, users, live_data_findings,
            teams, finding_assignments, support_tickets, support_ticket_comments, connections, api_keys, ticket_links, leases, jobs, file_snapshots, asset_controls, ai_usage_events, ai_apps, ai_budgets, threat_models, threat_reviews,
            grc_frameworks, grc_controls, grc_risks, grc_evidence, grc_attestations, grc_policies, grc_policy_acks,
            hunts, soc_alerts, soc_cases, soc_case_events, soc_case_alerts, soc_analysts, detection_usecases, darkweb_hits, darkweb_sources, cvd_advisories, threat_intel_reports, soc_investigations, detection_rules, detection_assessments, soar_playbooks, soar_runs, risk_scenarios, scan_runs, devsecops_status, remediation_factory, fw_rules, fw_requests, ai_assets, iam_entitlements, iam_roster, iam_campaigns, iam_review_items,
            api_specs, api_endpoints, api_metrics, api_actor_hits, api_dependencies, api_data_classes, api_policies, api_policy_events, api_policy_pushes, api_rollout_state,
            applications, app_sboms, fix_proposals, gate_runs, devsecops_custom_controls,
        ])
    if engine not in _MIGRATED:
        from remediation.utils import migrations
        with _cluster_schema_lock(engine):
            migrations.apply(engine)
        _MIGRATED.add(engine)
    _SCHEMA_READY.add(engine)


