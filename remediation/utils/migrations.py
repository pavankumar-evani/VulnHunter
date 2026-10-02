"""
Ordered, recorded schema migrations.

`db.ensure_schema()` creates any missing table, which covers a fresh install. A migration is
for a change to an EXISTING table (a new column, a backfill) and runs exactly once per
database, recorded in `schema_migrations`. To add one: append `(next_number, "name", fn)`
to MIGRATIONS; `fn(engine)` must be safe on both a database that already has the change
(an upgrade path that partially ran) and one that does not.

`python cli/quanta_admin.py migrate` shows and applies pending migrations; the app also
applies them on startup, so an upgrade needs no manual step.
"""
import datetime

from sqlalchemy import Column, Integer, MetaData, String, Table, inspect, select, text

_meta = MetaData()
schema_migrations = Table(
    "schema_migrations", _meta,
    Column("version", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("applied_at", String, nullable=False),
)


def _add_missing_columns(engine, table):
    existing = {c["name"] for c in inspect(engine).get_columns(table.name)}
    with engine.begin() as conn:
        for col in table.columns:
            if col.name not in existing:
                conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(engine.dialect)}"))


def _m001_baseline(engine):
    """Marks the point from which migrations are tracked."""


def _m002_support_ticket_columns(engine):
    from remediation.utils import db
    if inspect(engine).has_table("support_tickets"):
        _add_missing_columns(engine, db.support_tickets)


def _m003_soc_alert_columns(engine):
    from remediation.utils import db
    if inspect(engine).has_table("soc_alerts"):
        _add_missing_columns(engine, db.soc_alerts)


def _m004_soc_alert_action(engine):
    from remediation.utils import db
    if inspect(engine).has_table("soc_alerts"):
        _add_missing_columns(engine, db.soc_alerts)


MIGRATIONS = [
    (1, "baseline", _m001_baseline),
    (2, "support_ticket_itsm_and_csat_columns", _m002_support_ticket_columns),
    (3, "soc_alert_rule_and_entities", _m003_soc_alert_columns),
    (4, "soc_alert_action_taken", _m004_soc_alert_action),
]


def applied(engine):
    schema_migrations.create(engine, checkfirst=True)
    with engine.connect() as conn:
        return {r[0] for r in conn.execute(select(schema_migrations.c.version))}


def pending(engine):
    done = applied(engine)
    return [(v, n) for v, n, _ in MIGRATIONS if v not in done]


def apply(engine):
    """Applies every pending migration in order. Returns the list applied."""
    done = applied(engine)
    ran = []
    for version, name, fn in MIGRATIONS:
        if version in done:
            continue
        fn(engine)
        with engine.begin() as conn:
            conn.execute(schema_migrations.insert().values(
                version=version, name=name, applied_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))
        ran.append((version, name))
    return ran
