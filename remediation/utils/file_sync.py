"""
Keeps Quanta's working files in the shared database, so several replicas need no shared volume.

Two kinds of state were still plain files: the findings system of record
(`remediation/output/normalized-findings.json`, generated playbooks, `REMEDIATION_PLAN.md`) and the
admin-edited policy (`remediation/config/*.yaml`). Dozens of modules read them straight off disk, so
rather than rewrite every reader, each replica keeps a local copy and this module reconciles that copy
with a `file_snapshots` table. Turn it on with `QUANTA_FILES_BACKEND=db`; the default (`file`) does
nothing and the files are authoritative, exactly as before.

How a sync pass decides, per file (compared with what this process last synced, or, for a file it has
not synced yet, what it found at startup, which is the image's copy):

* changed in the database only        -> pull it (write or delete the local file)
* changed locally only                -> push it (optimistic: succeeds only if nobody pushed first)
* changed in both                     -> the database wins and the conflict is counted
* unchanged, not in the database      -> if the database has never been seeded, push it (the first
  replica seeds the defaults, including the policy YAML shipped in the image); otherwise it is a
  stale image default the cluster has since removed, so delete the local copy

So the database is the source of truth and the local files are a cache. A pass costs one query for the
row versions plus a stat of each tracked file (content is hashed only when size or mtime changed), and
is throttled (QUANTA_FILES_SYNC_SECONDS, default 3). Writers that must see the latest state before they
read-modify-write (the findings merge) call `sync(force=True)` under their lease and again after writing.

Limits, stated plainly: a write is a whole file, so two replicas editing the same policy file at the
same moment resolve by "database wins"; the findings file is one row, so it is for tens of thousands of
findings, not millions; and a deletion is propagated as a tombstone, not by waiting for a timeout.
"""
import glob
import hashlib
import logging
import os
import threading
import time
from pathlib import Path

from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from remediation.utils import db as db_module

log = logging.getLogger("quanta.file_sync")

REPO_ROOT = Path(__file__).resolve().parents[2]
PATTERNS = (
    "remediation/output/normalized-findings.json",
    "remediation/output/*.yml",
    "remediation/output/*.md",
    "remediation/config/*.yaml",
    "REMEDIATION_PLAN.md",
)
SEEDED = "__seeded__"


def enabled():
    return os.environ.get("QUANTA_FILES_BACKEND", "file").strip().lower() == "db"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class FileSync:
    def __init__(self, root=REPO_ROOT, patterns=PATTERNS, engine=None, interval=None):
        self.root = Path(root)
        self.patterns = patterns
        self._engine = engine
        self.interval = float(os.environ.get("QUANTA_FILES_SYNC_SECONDS", "3")) if interval is None else interval
        self._lock = threading.Lock()
        self._last = 0.0
        self._state = {}      # rel path -> {"sha", "version", "mtime", "size"} as last synced
        self._baseline = None  # rel path -> sha at first scan (the image's copy)
        self._stat = {}       # rel path -> (mtime, size, sha) hash cache
        self.conflicts = 0

    # -------------------------------------------------------------- local scan
    def _local(self):
        out = {}
        for pat in self.patterns:
            for p in glob.glob(str(self.root / pat)):
                path = Path(p)
                if not path.is_file():
                    continue
                rel = path.relative_to(self.root).as_posix()
                st = path.stat()
                cached = self._stat.get(rel)
                if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                    out[rel] = cached[2]
                    continue
                sha = _sha(path.read_bytes())
                self._stat[rel] = (st.st_mtime_ns, st.st_size, sha)
                out[rel] = sha
        return out

    def _write_local(self, rel, content):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".sync.tmp")
        tmp.write_bytes(content.encode("utf-8"))
        for attempt in range(6):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                # Windows briefly refuses a rename over a file another process (an indexer, an
                # antivirus scan, OneDrive) has just opened; a short retry is the standard answer
                if attempt == 5:
                    path.write_bytes(content.encode("utf-8"))  # last resort: not atomic, but never leaves it stale
                    with __import__("contextlib").suppress(OSError):
                        tmp.unlink()
                    break
                time.sleep(0.05 * (attempt + 1))
        st = path.stat()
        sha = _sha(content.encode("utf-8"))
        self._stat[rel] = (st.st_mtime_ns, st.st_size, sha)

    def _delete_local(self, rel):
        try:
            (self.root / rel).unlink()
        except OSError:
            pass
        self._stat.pop(rel, None)

    # -------------------------------------------------------------- the pass
    def sync(self, force=False, now=None):
        """Reconciles local files with the database. Returns {pulled, pushed, deleted, conflicts}."""
        now = time.monotonic() if now is None else now
        if not force and now - self._last < self.interval:
            return None
        with self._lock:
            engine = self._engine or db_module.get_engine()
            db_module.ensure_schema(engine)
            self._last = now
            return self._pass(engine)

    def _pass(self, engine):
        t = db_module.file_snapshots
        stats = {"pulled": 0, "pushed": 0, "deleted": 0, "conflicts": 0}
        with engine.connect() as conn:
            rows = {r["path"]: r for r in conn.execute(select(t.c.path, t.c.version, t.c.sha, t.c.deleted)).mappings().all()}
        seeded = SEEDED in rows
        local = self._local()
        first = self._baseline is None
        if first:
            self._baseline = dict(local)
        paths = (set(rows) | set(local) | set(self._state)) - {SEEDED}
        for rel in sorted(paths):
            drow = rows.get(rel)
            remote_live = drow is not None and not drow["deleted"]
            lsha = local.get(rel)
            st = self._state.get(rel)
            ref = st["sha"] if st else self._baseline.get(rel)
            local_changed = lsha != ref
            remote_changed = drow is not None and (st is None or drow["version"] != st["version"])
            if remote_changed:
                if local_changed:
                    same = (remote_live and lsha == drow["sha"]) or (not remote_live and lsha is None)
                    if not same:
                        stats["conflicts"] += 1
                        self.conflicts += 1
                        log.warning("file_sync conflict on %s: the database copy wins", rel)
                self._pull(engine, rel, drow, lsha, stats)
            elif local_changed:
                self._push(engine, rel, drow, lsha, stats)
            elif drow is None and lsha is not None and st is None:
                if not seeded:
                    self._push(engine, rel, None, lsha, stats)   # the first replica seeds the defaults
                else:
                    self._delete_local(rel)                         # a stale image default the cluster has dropped
                    stats["deleted"] += 1
        if not seeded:
            with engine.begin() as conn:
                try:
                    with conn.begin_nested():
                        conn.execute(insert(t).values(path=SEEDED, content="", sha="", version=1, deleted=False, updated_at=time.time()))
                except IntegrityError:
                    pass
        return stats

    def _pull(self, engine, rel, drow, lsha, stats):
        t = db_module.file_snapshots
        if drow["deleted"]:
            if lsha is not None:
                self._delete_local(rel)
                stats["deleted"] += 1
            self._state[rel] = {"sha": None, "version": drow["version"]}
            return
        if lsha != drow["sha"]:
            with engine.connect() as conn:
                content = conn.execute(select(t.c.content).where(t.c.path == rel)).scalar()
            self._write_local(rel, content or "")
            stats["pulled"] += 1
        self._state[rel] = {"sha": drow["sha"], "version": drow["version"]}

    def _push(self, engine, rel, drow, lsha, stats):
        t = db_module.file_snapshots
        deleted = lsha is None
        content = "" if deleted else (self.root / rel).read_text(encoding="utf-8")
        sha = None if deleted else lsha
        try:
            with engine.begin() as conn:
                if drow is None:
                    with conn.begin_nested():
                        conn.execute(insert(t).values(path=rel, content=content, sha=sha or "", version=1, deleted=deleted, updated_at=time.time()))
                    version = 1
                else:
                    version = drow["version"] + 1
                    won = conn.execute(update(t).where(t.c.path == rel, t.c.version == drow["version"]).values(
                        content=content, sha=sha or "", version=version, deleted=deleted, updated_at=time.time())).rowcount
                    if won != 1:
                        raise IntegrityError("stale", None, Exception("version moved"))
        except IntegrityError:
            stats["conflicts"] += 1
            self.conflicts += 1
            return  # someone pushed first; the next pass pulls their copy
        self._state[rel] = {"sha": sha, "version": version}
        stats["pushed"] += 1


_instance = None


def get():
    """The process-wide FileSync, or None when the database backend is off."""
    global _instance
    if not enabled():
        return None
    if _instance is None:
        _instance = FileSync()
    return _instance


def sync_if_enabled(force=False):
    fs = get()
    if fs is None:
        return None
    try:
        return fs.sync(force=force)
    except Exception:  # noqa: BLE001 - a database blip must not take a request down; the next pass retries
        log.exception("file_sync pass failed")
        return None
