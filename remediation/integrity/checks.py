"""
Store consistency checks. Read-only: nothing here changes anything (heal.py does, for the few cases that are safe).

Every check returns {id, title, level, detail, fix, manual}:
  level   ok | info | warn | fail      (info = nothing to do, but worth knowing; "no data" is never reported as ok)
  fix     the name of a heal.py action that can repair it, or None
  manual  what a person must do when there is a problem and no automatic repair
A check that cannot run says so (info/warn) rather than passing.
"""
import datetime
import json
import os
import shutil
import socket
import time
from pathlib import Path

from sqlalchemy import inspect, select, text

from remediation.utils import db as db_module
from remediation.utils import file_lock, file_sync, migrations

REPO_ROOT = Path(__file__).resolve().parents[2]
LEVELS = ("ok", "info", "warn", "fail")
_LOCK_PRUNE = {".git", "__pycache__", "node_modules", "worktrees", "tests"}
UNKNOWN_OWNER_STALE_SECONDS = 300.0   # a lock whose owner cannot be read and that is this old is treated as abandoned


def _c(cid, title, level, detail, fix=None, manual=None, **extra):
    return {"id": cid, "title": title, "level": level, "detail": detail, "fix": fix, "manual": manual, **extra}


def findings_path(root=None):
    return Path(root or REPO_ROOT) / "remediation" / "output" / "normalized-findings.json"


def _load_json(path):
    """(data, error) - error is None when the file parsed."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")), None
    except (OSError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _parse_ts(value):
    try:
        d = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        return None


# ------------------------------------------------------------------ database
def check_database(engine):
    try:
        if engine.dialect.name == "sqlite":
            with engine.connect() as conn:
                rows = [r[0] for r in conn.execute(text("PRAGMA integrity_check"))]
            if rows == ["ok"]:
                return _c("database", "Database integrity", "ok", "SQLite integrity_check reports ok.")
            return _c("database", "Database integrity", "fail", "SQLite integrity_check: " + "; ".join(rows[:5]),
                      manual="Stop the application, take a copy of the database file, restore the latest backup (quanta-admin restore) and re-ingest what changed since.")
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return _c("database", "Database integrity", "ok", f"{engine.dialect.name} answered a probe query (a basic reachability check, not a consistency check).")
    except Exception as exc:  # noqa: BLE001
        return _c("database", "Database integrity", "fail", f"The database could not be queried: {type(exc).__name__}",
                  manual="Check QUANTA_DATABASE_URL, the database service and its credentials.")


def check_schema(engine):
    out = []
    try:
        have = set(inspect(engine).get_table_names())
    except Exception as exc:  # noqa: BLE001
        return [_c("tables", "Tables present", "fail", f"Could not list tables: {type(exc).__name__}")]
    missing = sorted(t for t in db_module.metadata.tables if t not in have)
    if missing:
        out.append(_c("tables", "Tables present", "fail" if len(missing) < len(db_module.metadata.tables) else "warn", f"{len(missing)} expected table(s) are missing: {', '.join(missing[:12])}", fix="recreate_missing_tables", missing=missing))
    else:
        out.append(_c("tables", "Tables present", "ok", f"All {len(db_module.metadata.tables)} expected tables exist."))
    try:
        if "schema_migrations" not in have:
            out.append(_c("schema_version", "Schema version", "warn", "No schema_migrations table: the database has never been migrated.",
                          manual="Run: python cli/quanta_admin.py migrate"))
        else:
            with engine.connect() as conn:
                done = {r[0] for r in conn.execute(select(migrations.schema_migrations.c.version))}
            known = {v for v, _, _ in migrations.MIGRATIONS}
            pending = sorted(known - done)
            ahead = sorted(done - known)
            if ahead:
                out.append(_c("schema_version", "Schema version", "warn", f"The database records migration(s) {ahead} this code does not know: it was written by a newer release.",
                              manual="Run the release that matches the database, or restore a backup taken by this release."))
            elif pending:
                out.append(_c("schema_version", "Schema version", "warn", f"{len(pending)} migration(s) not applied: {pending}.", manual="Run: python cli/quanta_admin.py migrate"))
            else:
                out.append(_c("schema_version", "Schema version", "ok", f"Schema is at migration {max(done) if done else 0}; none pending."))
    except Exception as exc:  # noqa: BLE001
        out.append(_c("schema_version", "Schema version", "warn", f"Could not read migrations: {type(exc).__name__}"))
    return out


# ------------------------------------------------------------------ findings file
def check_findings_file(root=None):
    path = findings_path(root)
    bak = path.with_name(path.name + ".bak")
    if not path.exists():
        return _c("findings_file", "Findings file", "info", "No findings file yet (nothing has been ingested).",
                  bak_present=bak.exists())
    data, err = _load_json(path)
    bak_data, bak_err = _load_json(bak) if bak.exists() else (None, "absent")
    if err:
        if bak.exists() and bak_err is None and isinstance(bak_data, list):
            return _c("findings_file", "Findings file", "fail", f"normalized-findings.json is not valid JSON ({err[:120]}) but the .bak copy is valid.",
                      fix="restore_findings_from_bak", bak_present=True)
        return _c("findings_file", "Findings file", "fail", f"normalized-findings.json is not valid JSON ({err[:120]}) and there is no usable .bak copy.",
                  manual="Restore the file from a backup (quanta-admin restore) or re-run ingestion from the scanner exports.", bak_present=bak.exists())
    if not isinstance(data, list):
        return _c("findings_file", "Findings file", "fail", "normalized-findings.json parses but is not a list of findings.",
                  manual="Restore from a backup or re-run ingestion.", bak_present=bak.exists())
    if not bak.exists():
        return _c("findings_file", "Findings file", "info", f"{len(data)} findings, valid JSON. No .bak copy yet (one is made by the next merge).", bak_present=False)
    return _c("findings_file", "Findings file", "ok", f"{len(data)} findings, valid JSON, .bak copy present.", bak_present=True)


def _finding_ids(root):
    data, err = _load_json(findings_path(root)) if findings_path(root).exists() else (None, "absent")
    if err or not isinstance(data, list):
        return None
    return {str(f.get("id")) for f in data if isinstance(f, dict) and f.get("id") is not None}


# ------------------------------------------------------------------ orphans
def check_orphans(engine, root=None):
    ids = _finding_ids(root)
    if ids is None:
        return [_c("orphans", "Orphaned rows", "info", "Skipped: there is no readable findings file to compare against.")]
    if not ids:
        return [_c("orphans", "Orphaned rows", "info", "Skipped: the findings file is empty, so every reference would look orphaned.")]
    out = []
    try:
        with engine.connect() as conn:
            assigned = [r[0] for r in conn.execute(select(db_module.finding_assignments.c.finding_id))]
            approvals = [(r[0], r[1], r[2]) for r in conn.execute(select(db_module.remediation_approvals.c.id, db_module.remediation_approvals.c.finding_id,
                                                                         db_module.remediation_approvals.c.status))]
    except Exception as exc:  # noqa: BLE001
        return [_c("orphans", "Orphaned rows", "info", f"Skipped: could not read the tables ({type(exc).__name__}); the table check reports missing ones.")]
    orphan_assign = sorted(f for f in assigned if f not in ids)
    out.append(_c("orphan_assignments", "Assignments for findings that no longer exist", "warn" if orphan_assign else "ok",
                  (f"{len(orphan_assign)} assignment(s) point at findings absent from the findings file: {', '.join(orphan_assign[:8])}"
                   if orphan_assign else "Every assignment points at an existing finding."),
                  manual=("A finding drops out when a complete scan no longer reports it. Review them on the Assignments page; Quanta never deletes them automatically."
                          if orphan_assign else None), items=orphan_assign[:50]))
    out_dir = Path(root or REPO_ROOT) / "remediation" / "output"
    present = {p.name for p in out_dir.glob("*")} if out_dir.is_dir() else set()
    missing_pb = []
    for aid, fid, status in approvals:
        if status not in ("approved", "triggered"):
            continue
        prefix = f"{fid}-"
        if not any(n.startswith(prefix) and n.endswith((".yml", ".md", ".json")) for n in present):
            missing_pb.append(f"{aid} ({fid})")
    out.append(_c("orphan_approvals", "Approved remediations with no generated artifact", "warn" if missing_pb else "ok",
                  (f"{len(missing_pb)} approved/triggered approval(s) have no playbook or artifact in remediation/output: {', '.join(missing_pb[:6])}"
                   if missing_pb else "Every approved remediation has a generated artifact."),
                  manual=("Re-run /remediate --finding-id <id> --generate to regenerate the artifact, or reject the approval." if missing_pb else None), items=missing_pb[:50]))
    return out


# ------------------------------------------------------------------ locks
def lock_files(root=None):
    base = Path(root or REPO_ROOT)
    found = []
    for area in ("remediation", "dashboard", "cli"):
        d = base / area
        if not d.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(d):
            dirnames[:] = [x for x in dirnames if x not in _LOCK_PRUNE]
            found += [Path(dirpath) / f for f in filenames if f.endswith(".lock")]
    return sorted(found)


def lock_state(lock_path, now=None):
    """('stale'|'held'|'unknown', reason) for one lock file, using the same owner/host/pid rule as FileLock."""
    now = time.time() if now is None else now
    p = Path(lock_path)
    try:
        age = now - p.stat().st_mtime
        parts = p.read_text(encoding="utf-8").split()
    except OSError:
        return "unknown", "unreadable"
    try:
        pid, host = int(parts[0]), parts[1]
    except (IndexError, ValueError):
        return ("stale", f"no owner recorded and {int(age)}s old") if age > UNKNOWN_OWNER_STALE_SECONDS else ("held", "no owner recorded, recent")
    if host != file_lock._HOSTNAME:
        # another host's lock cannot be judged from here (its process table is not ours)
        return ("stale", f"owner on {host}, {int(age)}s old") if age > file_lock._OWNER_ALIVE_BACKSTOP_SECONDS else ("held", f"owner on {host}")
    if pid == os.getpid() or file_lock._pid_alive(pid):
        return ("stale", f"owner pid {pid} alive but lock is {int(age)}s old") if age > file_lock._OWNER_ALIVE_BACKSTOP_SECONDS else ("held", f"owner pid {pid} is running")
    return "stale", f"owner pid {pid} is not running"


def check_locks(root=None, now=None):
    files = lock_files(root)
    stale = []
    for f in files:
        st, why = lock_state(f, now)
        if st == "stale":
            stale.append({"path": f.relative_to(Path(root or REPO_ROOT)).as_posix(), "why": why})
    if stale:
        return _c("locks", "Lock files", "warn", f"{len(stale)} stale lock file(s): " + "; ".join(f"{s['path']} ({s['why']})" for s in stale[:5]), fix="remove_stale_locks", items=stale)
    return _c("locks", "Lock files", "ok", f"{len(files)} lock file(s), none stale." if files else "No lock files present.")


# ------------------------------------------------------------------ file snapshots
def check_snapshots(engine, root=None):
    if not file_sync.enabled():
        return _c("file_snapshots", "File snapshots", "info", "QUANTA_FILES_BACKEND is not 'db', so files are not mirrored to the database.")
    try:
        with engine.connect() as conn:
            rows = {r[0]: (r[1], r[2]) for r in conn.execute(select(db_module.file_snapshots.c.path, db_module.file_snapshots.c.sha, db_module.file_snapshots.c.deleted))}
        local = file_sync.FileSync(root=root or REPO_ROOT, engine=engine)._local()
    except Exception as exc:  # noqa: BLE001
        return _c("file_snapshots", "File snapshots", "warn", f"Could not compare snapshots: {type(exc).__name__}")
    diverged = sorted(p for p, sha in local.items() if p in rows and not rows[p][1] and rows[p][0] != sha)
    unsnapshotted = sorted(p for p in local if p not in rows)
    if diverged or unsnapshotted:
        return _c("file_snapshots", "File snapshots", "warn", f"{len(diverged)} local file(s) differ from the database copy and {len(unsnapshotted)} have no snapshot yet "
                  "(normal for a few seconds after an edit; persistent means a replica is not syncing).", fix="rebuild_file_snapshots", items=(diverged + unsnapshotted)[:50])
    return _c("file_snapshots", "File snapshots", "ok", f"{len(local)} local file(s) match their database snapshots.")


# ------------------------------------------------------------------ host and clock
def _data_dir(engine, root=None):
    try:
        if engine.dialect.name == "sqlite" and engine.url.database and engine.url.database != ":memory:":
            return Path(engine.url.database).resolve().parent
    except Exception:  # noqa: BLE001
        pass
    return Path(root or REPO_ROOT) / "remediation"


def check_disk(engine, root=None, usage=None):
    d = _data_dir(engine, root)
    try:
        u = (usage or shutil.disk_usage)(str(d))
    except OSError as exc:
        return _c("disk", "Disk space", "warn", f"Could not read disk usage for {d}: {exc}")
    free_pct = 100.0 * u.free / u.total if u.total else 0
    detail = f"{u.free / 2**30:.1f} GiB free of {u.total / 2**30:.1f} GiB ({free_pct:.0f}%) on the volume holding {d}."
    if u.free < 100 * 2**20:
        return _c("disk", "Disk space", "fail", detail, manual="Free space now: SQLite and the findings file cannot be written safely when the disk fills.")
    if u.free < 2**30 or free_pct < 5:
        return _c("disk", "Disk space", "warn", detail, manual="Free space or enlarge the volume (backups and old logs are the usual candidates).")
    return _c("disk", "Disk space", "ok", detail)


def check_clock(engine, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if engine.dialect.name == "sqlite":
        # SQLite has no clock of its own (it uses this host's), so compare the newest stored timestamp with now instead
        try:
            with engine.connect() as conn:
                newest = conn.execute(text("SELECT MAX(timestamp) FROM activity_log")).scalar()
        except Exception:  # noqa: BLE001
            return _c("clock", "Clock", "info", "SQLite uses this host's clock; there is no activity yet to compare against.")
        ts = _parse_ts(newest) if newest else None
        if ts and ts > now + datetime.timedelta(minutes=5):
            return _c("clock", "Clock", "warn", f"The newest activity-log entry ({newest}) is in the future: this host's clock went backwards or is wrong.",
                      manual="Check NTP on the host; time-based SLAs, licences and lock expiry depend on it.")
        return _c("clock", "Clock", "info", "SQLite shares this host's clock, so skew cannot be measured against the database; no future-dated records found.")
    try:
        with engine.connect() as conn:
            db_now = conn.execute(text("SELECT now()")).scalar()
        db_now = db_now if db_now.tzinfo else db_now.replace(tzinfo=datetime.timezone.utc)
        skew = abs((db_now - now).total_seconds())
    except Exception as exc:  # noqa: BLE001
        return _c("clock", "Clock", "info", f"Could not read the database clock: {type(exc).__name__}")
    if skew > 60:
        return _c("clock", "Clock", "fail", f"This host differs from the database server by {skew:.0f}s.", manual="Fix NTP on this host or the database server.")
    if skew > 5:
        return _c("clock", "Clock", "warn", f"This host differs from the database server by {skew:.1f}s.", manual="Check NTP.")
    return _c("clock", "Clock", "ok", f"Within {skew:.1f}s of the database server.")


# ------------------------------------------------------------------ keys and licence
def check_api_keys(engine, now=None, warn_days=14):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        with engine.connect() as conn:
            rows = list(conn.execute(select(db_module.api_keys.c.name, db_module.api_keys.c.expires_at, db_module.api_keys.c.revoked_at)))
    except Exception as exc:  # noqa: BLE001
        return _c("api_keys", "API keys", "info", f"Could not read API keys: {type(exc).__name__}")
    soon, expired = [], []
    for name, exp, revoked in rows:
        if revoked or not exp:
            continue
        d = _parse_ts(exp)
        if d is None:
            continue
        if d < now:
            expired.append(name)
        elif d < now + datetime.timedelta(days=warn_days):
            soon.append(name)
    if soon or expired:
        parts = ([f"expired and not revoked: {', '.join(expired[:5])}"] if expired else []) + ([f"expiring within {warn_days} days: {', '.join(soon[:5])}"] if soon else [])
        return _c("api_keys", "API keys", "warn", "; ".join(parts), manual="Issue replacement keys on the API Keys page and revoke the old ones; an integration using an expired key is failing now.")
    return _c("api_keys", "API keys", "ok", f"{len(rows)} key(s); none expired or expiring within {warn_days} days.")


def check_licence(today=None, env=None):
    try:
        from remediation.licensing import license as lic
        st = lic.status(today=today, env=env)
    except Exception as exc:  # noqa: BLE001
        return _c("licence", "Licence", "info", f"Could not read licence state: {type(exc).__name__}")
    state = st.get("state")
    if state == "unrestricted":
        return _c("licence", "Licence", "info", "Licence checking is off (QUANTA_LICENSE_MODE=off).")
    if state in ("valid",):
        return _c("licence", "Licence", "ok", st["message"])
    level = "fail" if state in ("expired", "invalid", "missing") and st.get("enforced") else "warn"
    return _c("licence", "Licence", level, st["message"], manual="Install a renewed licence (QUANTA_LICENSE or QUANTA_LICENSE_FILE).")


# ------------------------------------------------------------------ everything
def run_all(engine=None, root=None, now=None, today=None, env=None, disk_usage=None):
    engine = engine or db_module.get_engine()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    checks = [check_database(engine)]
    checks += check_schema(engine)
    checks.append(check_findings_file(root))
    checks += check_orphans(engine, root)
    checks.append(check_locks(root))
    checks.append(check_snapshots(engine, root))
    checks.append(check_disk(engine, root, usage=disk_usage))
    checks.append(check_clock(engine, now))
    checks.append(check_api_keys(engine, now))
    checks.append(check_licence(today, env))
    counts = {lv: sum(1 for c in checks if c["level"] == lv) for lv in LEVELS}
    status = "fail" if counts["fail"] else ("warn" if counts["warn"] else "ok")
    return {"checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "host": socket.gethostname(), "status": status, "counts": counts, "checks": checks,
            "fixable": sorted({c["fix"] for c in checks if c.get("fix")})}
