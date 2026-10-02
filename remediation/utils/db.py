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
    with FileLock(_SCHEMA_LOCK_PATH, local=True), _cluster_schema_lock(engine):
        metadata.create_all(engine, tables=[
            alert_state, schedule_state, exceptions, remediation_approvals,
            activity_log, ai_usage_log, asset_ownership, users, live_data_findings,
            teams, finding_assignments, support_tickets, support_ticket_comments, connections, api_keys, ticket_links, leases, jobs, file_snapshots, asset_controls, ai_usage_events, ai_apps, ai_budgets, threat_models, threat_reviews,
            grc_frameworks, grc_controls, grc_risks, grc_evidence, grc_attestations, grc_policies, grc_policy_acks,
        ])
    if engine not in _MIGRATED:
        from remediation.utils import migrations
        with _cluster_schema_lock(engine):
            migrations.apply(engine)
        _MIGRATED.add(engine)


