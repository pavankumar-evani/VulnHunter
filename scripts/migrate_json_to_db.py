#!/usr/bin/env python3
"""
One-time migration: copies existing flat-JSON store content into the new shared
SQLite database (see remediation/utils/db.py) for the stores that moved off JSON
files - exceptions, remediation_approvals, activity_log, ai_usage_log,
asset_ownership, and users. Several of these JSON files are real, committed
seed/example data (exceptions.json's one realistic waiver example,
asset_ownership.json's five, users.json's two demo accounts); others are gitignored
local runtime output from actually using the app - both are worth carrying forward
rather than silently dropping on the day someone upgrades to this DB backend, so this
script doesn't distinguish between them.

Safe to run more than once: skips any JSON file that's missing or empty, and skips
any individual record already present in the target table (matched by id for the
flat-list stores, by key for the dict-shaped ones), so a second run against an
already-migrated (or partially migrated) DB is a no-op.

Usage:
    python scripts/migrate_json_to_db.py
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import select  # noqa: E402

from remediation.utils import db as db_module  # noqa: E402


def _existing_ids(engine, table):
    with engine.connect() as conn:
        return {row[0] for row in conn.execute(select(table.c.id))}


def _split_by_id_freshness(records, existing_ids, int_ids):
    """Old JSON stores computed a record's id from len(entries)+1 (int-id tables) or
    by scanning for the max PREFIX-N suffix (string-id tables) at write time - under a
    rare race before FileLock was applied consistently everywhere, this could
    double-assign one id to two different real records (seen in a real
    activity_log.json: two distinct login events both stamped id=29). Splits records
    into (keepers, needs_fresh_id, already_migrated):
    - already_migrated: this id was already in the table before this run started -
      the normal, expected outcome of re-running this script (idempotent, not an
      error, nothing printed).
    - keepers: a new id, no conflict - inserted as-is.
    - needs_fresh_id: a new id that collides with ANOTHER record in this SAME source
      file (the real bug case) - set aside rather than silently dropped or inserted
      with a colliding primary key."""
    already_seen_before_run = set(existing_ids)
    seen_in_batch = set()
    keepers, needs_fresh_id, already_migrated = [], [], []
    for r in records:
        rid = r.get("id")
        if rid in already_seen_before_run:
            already_migrated.append(r)
        elif rid in seen_in_batch:
            needs_fresh_id.append(r)
        else:
            seen_in_batch.add(rid)
            keepers.append(r)
    if needs_fresh_id and not int_ids:
        # String ids (EXC-N/APR-N) have no server-side "assign the next free one"
        # fallback the way an Integer autoincrement column does - rare enough in
        # practice (exceptions/remediation_approvals have far too little history for
        # this race to plausibly have happened) that it's not worth reimplementing
        # each store's own _next_id() here. Surface it honestly instead of guessing.
        print(f"  MANUAL REVIEW NEEDED: {len(needs_fresh_id)} record(s) reuse an id "
              f"already taken by another record in this same file - not migrated: "
              f"{[r.get('id') for r in needs_fresh_id]}")
        needs_fresh_id = []
    return keepers, needs_fresh_id, already_migrated


def _migrate_flat_list(engine, table, json_path, defaults=None, row_transform=lambda r: r, int_ids=False):
    """Reads a flat JSON list of record dicts and inserts whichever ones aren't
    already present (by id) into `table`. `defaults` backfills any nullable column a
    given record's dict doesn't happen to carry (the old JSON stores often just
    omitted a key rather than storing it as null) - every row in one INSERT batch
    needs the same set of keys. `row_transform` additionally re-shapes a record for
    columns that are JSON-encoded text in the DB (scheduled_window/details/usage).
    `int_ids=True` (activity_log/ai_usage_log) lets a record whose id collides with
    one already used get a fresh id assigned by the DB's own autoincrement, by
    omitting `id` from its row entirely, instead of failing the whole batch."""
    if not json_path.exists():
        print(f"skip {json_path} (not present)")
        return 0
    records = json.loads(json_path.read_text(encoding="utf-8"))
    if not records:
        print(f"skip {json_path} (empty)")
        return 0
    existing = _existing_ids(engine, table)
    keepers, needs_fresh_id, already_migrated = _split_by_id_freshness(records, existing, int_ids)

    migrated = 0
    with engine.begin() as conn:
        if keepers:
            conn.execute(table.insert(), [row_transform({**(defaults or {}), **r}) for r in keepers])
            migrated += len(keepers)
        if needs_fresh_id:
            rows = []
            for r in needs_fresh_id:
                row = row_transform({**(defaults or {}), **r})
                row.pop("id", None)
                rows.append(row)
            conn.execute(table.insert(), rows)
            migrated += len(needs_fresh_id)

    unresolved = len(records) - migrated - len(already_migrated)
    if migrated:
        detail = f" ({len(already_migrated)} already migrated)" if already_migrated else ""
        detail += f" ({unresolved} need manual review)" if unresolved else ""
        print(f"migrated {migrated} of {len(records)} record(s) from {json_path}{detail}")
    elif already_migrated:
        print(f"skip {json_path} ({len(records)} record(s), already migrated)")
    else:
        print(f"skip {json_path} ({len(records)} record(s), all need manual review)")
    return migrated


def _migrate_dict(engine, table, json_path, key_column, defaults=None, row_transform=lambda r: r):
    """Reads a JSON object shaped {key: {field: value, ...}} (asset_ownership.json,
    keyed by asset name rather than an "id" field) and inserts whichever keys aren't
    already present as a row into `table`. A JSON object's keys are already unique by
    construction, so there's no id-collision case to handle the way the flat-list
    stores above need."""
    if not json_path.exists():
        print(f"skip {json_path} (not present)")
        return 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    if not data:
        print(f"skip {json_path} (empty)")
        return 0
    with engine.connect() as conn:
        existing = {row[0] for row in conn.execute(select(table.c[key_column]))}
    rows = [
        row_transform({key_column: key, **(defaults or {}), **fields})
        for key, fields in data.items() if key not in existing
    ]
    if not rows:
        print(f"skip {json_path} ({len(data)} record(s), already migrated)")
        return 0
    with engine.begin() as conn:
        conn.execute(table.insert(), rows)
    print(f"migrated {len(rows)} of {len(data)} record(s) from {json_path}")
    return len(rows)


def main():
    engine = db_module.get_engine()
    db_module.ensure_schema(engine)
    print(f"target DB: {engine.url.database}")

    _migrate_flat_list(
        engine, db_module.exceptions,
        REPO_ROOT / "remediation" / "exceptions" / "exceptions.json",
        defaults={"revoked_by": None, "revoked_at": None},
    )
    _migrate_flat_list(
        engine, db_module.remediation_approvals,
        REPO_ROOT / "remediation" / "remediation_approvals" / "remediation_approvals.json",
        defaults={
            "approved_by": None, "approved_at": None, "ad_group_validated": None,
            "rejected_by": None, "rejected_at": None, "rejection_reason": None,
            "staging_validated_by": None, "staging_validated_at": None,
            "triggered_by": None, "triggered_at": None,
        },
        row_transform=lambda r: {**r, "scheduled_window": json.dumps(r.get("scheduled_window") or {})},
    )
    _migrate_flat_list(
        engine, db_module.activity_log,
        REPO_ROOT / "remediation" / "audit" / "activity_log.json",
        row_transform=lambda r: {**r, "details": json.dumps(r.get("details") or {})},
        int_ids=True,
    )
    _migrate_flat_list(
        engine, db_module.ai_usage_log,
        REPO_ROOT / "remediation" / "audit" / "ai_usage_log.json",
        defaults={"model": None, "total_tokens": None, "total_cost_usd": None},
        row_transform=lambda r: {**r, "usage": json.dumps(r.get("usage") or {})},
        int_ids=True,
    )
    _migrate_dict(
        engine, db_module.asset_ownership,
        REPO_ROOT / "remediation" / "inventory" / "asset_ownership.json",
        key_column="asset_name",
        defaults={
            "owner": None, "team": None, "facing": None, "environment": None,
            "remediation_schedule": None, "ip": None, "mac": None,
        },
        row_transform=lambda r: {
            **r,
            "remediation_schedule": json.dumps(r["remediation_schedule"]) if r.get("remediation_schedule") is not None else None,
        },
    )
    _migrate_dict(
        engine, db_module.users,
        REPO_ROOT / "dashboard" / "auth" / "users.json",
        key_column="email",
        defaults={"team": None},
    )


if __name__ == "__main__":
    main()
