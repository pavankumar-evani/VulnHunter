"""
Self-heal: the few repairs that are safe to make without a person deciding.

Each repair is a named action. `run()` previews by default and acts only with confirm=True; every action that runs is written to the activity log
(integrity.heal.<name>), whether it succeeded or failed. Hard rules: nothing a customer put in is ever deleted (a replaced file is kept beside the
new one), nothing is touched that the check did not flag, and anything else (corrupt database, orphaned rows, modified code, full disk) is reported
by checks.py with the manual step, never "fixed" here.

  remove_stale_locks         delete lock files whose owner process is gone (the same rule FileLock uses to take one over)
  restore_findings_from_bak  findings file is invalid JSON and the .bak is valid: keep the bad file as .corrupt-<time>, put the .bak back
  recreate_missing_tables    create tables the schema expects and the database lacks (existing tables and rows are never altered)
  rebuild_file_snapshots     (QUANTA_FILES_BACKEND=db) seed snapshots for local files that have none; keep a copy of any local file that differs
                             from the database copy before the normal sync lets the database win
"""
import datetime
import json
import os
import shutil
import time
from pathlib import Path

from sqlalchemy import insert, select

from remediation.audit import activity_log
from remediation.integrity import checks
from remediation.utils import db as db_module
from remediation.utils import file_sync


def _stamp(now):
    return now.strftime("%Y%m%dT%H%M%SZ")


# ------------------------------------------------------------------ remove_stale_locks
def _plan_locks(ctx):
    root = Path(ctx["root"])
    out = []
    for f in checks.lock_files(root):
        st, why = checks.lock_state(f)
        if st == "stale":
            out.append({"path": f.relative_to(root).as_posix(), "why": why})
    return out


def _do_locks(ctx):
    root = Path(ctx["root"])
    done = []
    for item in _plan_locks(ctx):                       # re-evaluated now: a lock that became live in between is left alone
        p = root / item["path"]
        if p.suffix != ".lock":
            continue
        try:
            os.remove(p)
            done.append(item)
        except FileNotFoundError:
            pass
    return {"removed": done}


# ------------------------------------------------------------------ restore_findings_from_bak
def _plan_findings(ctx):
    path = checks.findings_path(ctx["root"])
    bak = path.with_name(path.name + ".bak")
    if not path.exists():
        return []
    _, err = checks._load_json(path)
    if err is None:
        return []
    data, berr = checks._load_json(bak) if bak.exists() else (None, "absent")
    if berr is None and isinstance(data, list):
        return [{"path": path.name, "restore_from": bak.name, "findings_in_bak": len(data)}]
    return []


def _do_findings(ctx):
    items = _plan_findings(ctx)
    if not items:
        return {"restored": []}
    path = checks.findings_path(ctx["root"])
    bak = path.with_name(path.name + ".bak")
    kept = path.with_name(f"{path.name}.corrupt-{_stamp(ctx['now'])}")
    shutil.copy2(path, kept)                              # the bad copy is kept: it may hold data worth recovering by hand
    tmp = path.with_name(path.name + ".restore.tmp")
    shutil.copy2(bak, tmp)
    os.replace(tmp, path)
    return {"restored": [{**items[0], "bad_copy_kept_as": kept.name}]}


# ------------------------------------------------------------------ recreate_missing_tables
def _plan_tables(ctx):
    from sqlalchemy import inspect
    have = set(inspect(ctx["engine"]).get_table_names())
    return [{"table": t} for t in sorted(db_module.metadata.tables) if t not in have]


def _do_tables(ctx):
    planned = [p["table"] for p in _plan_tables(ctx)]
    if not planned:
        return {"created": []}
    db_module.forget_schema(ctx["engine"])               # ensure_schema is cached per engine; make it look again
    db_module.ensure_schema(ctx["engine"])
    still = {p["table"] for p in _plan_tables(ctx)}
    return {"created": [t for t in planned if t not in still], "still_missing": sorted(still)}


# ------------------------------------------------------------------ rebuild_file_snapshots
def _snapshot_gap(ctx):
    if not file_sync.enabled():
        return [], []
    engine = ctx["engine"]
    with engine.connect() as conn:
        rows = {r[0]: (r[1], bool(r[2])) for r in conn.execute(select(db_module.file_snapshots.c.path, db_module.file_snapshots.c.sha, db_module.file_snapshots.c.deleted))}
    local = file_sync.FileSync(root=ctx["root"], engine=engine)._local()
    missing = sorted(p for p in local if p not in rows)
    diverged = sorted(p for p, sha in local.items() if p in rows and not rows[p][1] and rows[p][0] != sha)
    return missing, diverged


def _plan_snapshots(ctx):
    missing, diverged = _snapshot_gap(ctx)
    return [{"path": p, "will": "seed snapshot from local file"} for p in missing] + [{"path": p, "will": "keep a copy of the local file, then let the database copy win"} for p in diverged]


def _do_snapshots(ctx):
    missing, diverged = _snapshot_gap(ctx)
    root, engine, now = Path(ctx["root"]), ctx["engine"], ctx["now"]
    seeded, kept = [], []
    for rel in diverged:
        src = root / rel
        dst = src.with_name(f"{src.name}.local-{_stamp(now)}")
        shutil.copy2(src, dst)
        kept.append({"path": rel, "kept_as": dst.name})
    with engine.begin() as conn:
        for rel in missing:
            try:
                content = (root / rel).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            sha = file_sync._sha(content.encode("utf-8"))
            conn.execute(insert(db_module.file_snapshots).values(path=rel, content=content, sha=sha, version=1, deleted=False, updated_at=time.time()))
            seeded.append(rel)
    return {"seeded": seeded, "local_copies_kept": kept}


ACTIONS = {
    "remove_stale_locks": {"title": "Remove stale lock files", "plan": _plan_locks, "do": _do_locks,
                           "why": "A crashed process left a lock whose owner is gone; every writer of that store waits on it."},
    "restore_findings_from_bak": {"title": "Restore the findings file from its .bak copy", "plan": _plan_findings, "do": _do_findings,
                                  "why": "The findings file is not valid JSON; the previous merge's .bak copy is. The bad file is kept beside it."},
    "recreate_missing_tables": {"title": "Create missing tables", "plan": _plan_tables, "do": _do_tables,
                                "why": "A table the schema expects is not in the database. Existing tables are not changed."},
    "rebuild_file_snapshots": {"title": "Rebuild file snapshots", "plan": _plan_snapshots, "do": _do_snapshots,
                               "why": "Local files and their database snapshots disagree or are missing. Nothing local is overwritten without a kept copy."},
}


def run(actions=None, confirm=False, actor="system", engine=None, root=None, now=None):
    """Preview (confirm False) or perform the named actions (default: every action that has something to do).

    Returns {preview, results:[{action, title, why, planned, done, status}], unknown:[...], manual:[...]} where `manual` lists checks that fail with no automatic fix."""
    engine = engine or db_module.get_engine()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    ctx = {"engine": engine, "root": Path(root or checks.REPO_ROOT), "now": now}
    names = list(actions) if actions else list(ACTIONS)
    unknown = [n for n in names if n not in ACTIONS]
    results = []
    for name in (n for n in names if n in ACTIONS):
        spec = ACTIONS[name]
        try:
            planned = spec["plan"](ctx)
        except Exception as exc:  # noqa: BLE001
            results.append({"action": name, "title": spec["title"], "why": spec["why"], "planned": [], "done": None, "status": f"could not plan: {type(exc).__name__}"})
            continue
        entry = {"action": name, "title": spec["title"], "why": spec["why"], "planned": planned, "done": None, "status": "nothing to do" if not planned else "would run"}
        if confirm and planned:
            try:
                entry["done"] = spec["do"](ctx)
                entry["status"] = "done"
                detail = {"result": entry["done"]}
            except Exception as exc:  # noqa: BLE001 - recorded, and the next action still runs
                entry["status"] = f"failed: {type(exc).__name__}: {exc}"
                detail = {"error": entry["status"]}
            activity_log.record_activity(actor, f"integrity.heal.{name}", target=name, details=detail, engine=engine, as_of=now)
        results.append(entry)
    report = checks.run_all(engine=engine, root=ctx["root"], now=now)
    manual = [{"id": c["id"], "title": c["title"], "level": c["level"], "detail": c["detail"], "manual": c["manual"]}
              for c in report["checks"] if c["level"] in ("warn", "fail") and not c.get("fix") and c.get("manual")]
    return {"preview": not confirm, "results": results, "unknown": unknown, "manual": manual, "after": {"status": report["status"], "counts": report["counts"]}}
