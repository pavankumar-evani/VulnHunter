"""
Database leases: a named lock with an owner and an expiry, shared by every replica.

A file lock only works between processes that see the same local filesystem, and network
filesystems do not make `O_EXCL` file creation reliable. A lease row in the shared database
works for any number of replicas on any number of nodes, because the database already
serialises writers. It is the same idea as a Kubernetes `Lease` object or a Postgres advisory
lock, but it behaves identically on SQLite (one replica, development) and PostgreSQL.

    acquire(name, holder, ttl)  -> True if `holder` now owns the lease. Takes it if it is free,
                                   expired, or already ours (which also extends it).
    renew(name, holder, ttl)    -> True if we still own it (extends it). False means it was lost.
    release(name, holder)       -> frees it if we own it.

A holder that crashes simply stops renewing, and the lease becomes available once its ttl
passes, so there is no stale lock to clean up by hand. The ttl must be longer than the longest
time between renewals, and clocks need only be roughly in step: the expiry is compared against
the time on the replica asking, so a skew of a few seconds just shortens or lengthens a ttl.
"""
import contextlib
import time
import uuid
import weakref

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from remediation.utils import db as db_module

_READY = weakref.WeakSet()  # engines whose tables exist (not id(): ids get reused)


def _engine(engine):
    engine = engine or db_module.get_engine()
    if engine not in _READY:  # creating tables is cheap but not free; do it once per engine
        db_module.ensure_schema(engine)
        _READY.add(engine)
    return engine


def new_holder_id():
    return uuid.uuid4().hex


def acquire(name, holder, ttl, engine=None, now=None):
    engine = _engine(engine)
    t = db_module.leases
    now = time.time() if now is None else now
    with engine.begin() as conn:
        taken = conn.execute(update(t).where(t.c.name == name, (t.c.holder == holder) | (t.c.expires_at < now))
                             .values(holder=holder, expires_at=now + ttl))
        if taken.rowcount == 1:
            return True
        try:
            with conn.begin_nested():
                conn.execute(insert(t).values(name=name, holder=holder, expires_at=now + ttl))
            return True
        except IntegrityError:
            return False  # someone else holds it and it has not expired


def renew(name, holder, ttl, engine=None, now=None):
    engine = _engine(engine)
    t = db_module.leases
    now = time.time() if now is None else now
    with engine.begin() as conn:
        return conn.execute(update(t).where(t.c.name == name, t.c.holder == holder, t.c.expires_at >= now)
                            .values(expires_at=now + ttl)).rowcount == 1


def release(name, holder, engine=None):
    engine = _engine(engine)
    t = db_module.leases
    with engine.begin() as conn:
        conn.execute(delete(t).where(t.c.name == name, t.c.holder == holder))


def current(name, engine=None, now=None):
    """(holder, seconds_left) for a live lease, or None."""
    engine = _engine(engine)
    t = db_module.leases
    now = time.time() if now is None else now
    with engine.connect() as conn:
        row = conn.execute(select(t).where(t.c.name == name)).mappings().first()
    if not row or row["expires_at"] < now:
        return None
    return row["holder"], round(row["expires_at"] - now, 1)


class LeaseTimeout(RuntimeError):
    pass


@contextlib.contextmanager
def lease_lock(name, ttl=120.0, timeout=30.0, poll=0.05, engine=None):
    """`with lease_lock("findings"):` blocks until the lease is ours, then frees it on exit."""
    holder = new_holder_id()
    deadline = time.monotonic() + timeout
    while not acquire(name, holder, ttl, engine):
        if time.monotonic() >= deadline:
            raise LeaseTimeout(f"Could not acquire lock {name!r} within {timeout}s; another replica is holding it.")
        time.sleep(poll)
    try:
        yield holder
    finally:
        with contextlib.suppress(Exception):
            release(name, holder, engine)
