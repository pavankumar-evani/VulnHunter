"""
A durable job queue in the shared database, for work that must not run inside a web request
and must not run twice: connection syncs and ticket pushes today.

    enqueue(kind, payload, dedupe_key=None)   any replica adds a job (a duplicate of a job that is
                                              already queued or running is not added again)
    claim(worker_id)                          a worker takes the next due job; no two workers get
                                              the same one
    heartbeat / complete / fail               the worker reports back

Claiming uses `SELECT ... FOR UPDATE SKIP LOCKED` on PostgreSQL, the standard way to let many
workers pull from one table without blocking each other or taking the same row. SQLite has no
row locks, so there the claim is a select followed by an UPDATE guarded on `status = 'queued'`;
if another worker won the race the UPDATE changes nothing and we try the next job. Both give
"at least once" delivery: a job claimed by a worker that then dies is given back to the queue
when its visibility timeout (`locked_until`) passes, so a handler must be safe to run again (a
connection sync is: its own run claim prevents overlap and merging is idempotent). After
`max_attempts` failures a job is marked `dead` and kept for inspection instead of retrying forever.
"""
import json
import time

from sqlalchemy import delete, func, insert, select, update

from remediation.coordination.leases import _engine
from remediation.utils import db as db_module

QUEUED, RUNNING, DONE, DEAD = "queued", "running", "done", "dead"
ACTIVE = (QUEUED, RUNNING)
BACKOFF_BASE_SECONDS = 30
BACKOFF_CAP_SECONDS = 900


def _t(now):
    return time.time() if now is None else now


def enqueue(kind, payload=None, dedupe_key=None, delay=0, max_attempts=3, engine=None, now=None):
    """Adds a job and returns its id. With a dedupe_key, returns the id of the job already
    queued or running under that key instead of adding another."""
    engine = _engine(engine)
    t = db_module.jobs
    ts = _t(now)
    with engine.begin() as conn:
        if dedupe_key:
            existing = conn.execute(select(t.c.id).where(t.c.dedupe_key == dedupe_key, t.c.status.in_(ACTIVE))).scalar()
            if existing:
                return existing
        return conn.execute(insert(t).values(
            kind=kind, payload=json.dumps(payload or {}), status=QUEUED, attempts=0, max_attempts=max_attempts,
            run_after=ts + delay, dedupe_key=dedupe_key, created_at=ts, updated_at=ts)).inserted_primary_key[0]


def _recover_expired(conn, t, ts):
    """Gives back jobs whose worker stopped heartbeating; kills the ones out of attempts."""
    expired = (t.c.status == RUNNING) & (t.c.locked_until < ts)
    conn.execute(update(t).where(expired, t.c.attempts >= t.c.max_attempts)
                 .values(status=DEAD, error="The worker stopped before finishing and the job is out of attempts", updated_at=ts))
    conn.execute(update(t).where(expired).values(status=QUEUED, locked_by=None, locked_until=None, updated_at=ts))


def claim(worker_id, kinds=None, visibility=300, engine=None, now=None):
    """Takes the next due job for this worker, or returns None."""
    engine = _engine(engine)
    t = db_module.jobs
    ts = _t(now)
    with engine.begin() as conn:
        _recover_expired(conn, t, ts)
    for _ in range(5):  # a lost race just means looking at the next candidate
        with engine.begin() as conn:
            q = select(t.c.id).where(t.c.status == QUEUED, t.c.run_after <= ts)
            if kinds:
                q = q.where(t.c.kind.in_(list(kinds)))
            q = q.order_by(t.c.run_after, t.c.id).limit(1).with_for_update(skip_locked=True)
            job_id = conn.execute(q).scalar()
            if job_id is None:
                return None
            won = conn.execute(update(t).where(t.c.id == job_id, t.c.status == QUEUED).values(
                status=RUNNING, locked_by=worker_id, locked_until=ts + visibility,
                attempts=t.c.attempts + 1, updated_at=ts)).rowcount == 1
            if won:
                return _row(conn, t, job_id)
    return None


def _row(conn, t, job_id):
    r = conn.execute(select(t).where(t.c.id == job_id)).mappings().first()
    if not r:
        return None
    d = dict(r)
    d["payload"] = json.loads(d["payload"] or "{}")
    return d


def get(job_id, engine=None):
    engine = _engine(engine)
    with engine.connect() as conn:
        return _row(conn, db_module.jobs, job_id)


def heartbeat(job_id, worker_id, visibility=300, engine=None, now=None):
    """Extends our hold on a running job. False means we lost it (it timed out and was given away)."""
    engine = _engine(engine)
    t = db_module.jobs
    ts = _t(now)
    with engine.begin() as conn:
        return conn.execute(update(t).where(t.c.id == job_id, t.c.locked_by == worker_id, t.c.status == RUNNING)
                            .values(locked_until=ts + visibility, updated_at=ts)).rowcount == 1


def complete(job_id, worker_id, result=None, engine=None, now=None):
    engine = _engine(engine)
    t = db_module.jobs
    with engine.begin() as conn:
        return conn.execute(update(t).where(t.c.id == job_id, t.c.locked_by == worker_id).values(
            status=DONE, result=json.dumps(result) if result is not None else None, error=None,
            locked_by=None, locked_until=None, updated_at=_t(now))).rowcount == 1


def fail(job_id, worker_id, error, engine=None, now=None):
    """Records a failure. Retries later with exponential backoff until max_attempts, then `dead`."""
    engine = _engine(engine)
    t = db_module.jobs
    ts = _t(now)
    with engine.begin() as conn:
        row = conn.execute(select(t.c.attempts, t.c.max_attempts).where(t.c.id == job_id, t.c.locked_by == worker_id)).first()
        if not row:
            return None
        attempts, max_attempts = row
        if attempts >= max_attempts:
            status, run_after = DEAD, ts
        else:
            status, run_after = QUEUED, ts + min(BACKOFF_BASE_SECONDS * 2 ** (attempts - 1), BACKOFF_CAP_SECONDS)
        conn.execute(update(t).where(t.c.id == job_id).values(
            status=status, run_after=run_after, error=str(error)[:1000], locked_by=None, locked_until=None, updated_at=ts))
        return status


def stats(engine=None):
    engine = _engine(engine)
    t = db_module.jobs
    with engine.connect() as conn:
        counts = dict(conn.execute(select(t.c.status, func.count()).group_by(t.c.status)).all())
    return {s: counts.get(s, 0) for s in (QUEUED, RUNNING, DONE, DEAD)}


def recent(limit=50, engine=None):
    engine = _engine(engine)
    t = db_module.jobs
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.id.desc()).limit(limit)).mappings().all()
    out = []
    for r in rows:
        d = dict(r)
        d["payload"] = json.loads(d["payload"] or "{}")
        out.append(d)
    return out


def purge_finished(older_than_seconds=7 * 86400, engine=None, now=None):
    engine = _engine(engine)
    t = db_module.jobs
    with engine.begin() as conn:
        return conn.execute(delete(t).where(t.c.status == DONE, t.c.updated_at < _t(now) - older_than_seconds)).rowcount
