"""
Leader election for the schedulers.

Several replicas each run the same background loops (scheduled connection syncs, notification
reports, SLA escalations). Only one of them should act on a given tick, or every report would
be sent once per replica. Each replica asks `Leader.check()` periodically: the one holding the
`scheduler` lease is the leader. If it dies, its lease expires after `ttl` seconds and another
replica takes over; nobody has to intervene.

This is "at most one leader at a time" as far as the lease's ttl allows. In the gap between a
leader stalling and its lease expiring, the new leader may begin a tick the old one is still
finishing, so the work the leader triggers must itself be idempotent. It is: scheduled syncs are
queued with a dedupe key and each connection is claimed atomically, and report and alert
senders record what they sent.
"""
import os

from remediation.coordination import leases

LEASE_NAME = "scheduler"
DEFAULT_TTL = float(os.environ.get("QUANTA_LEADER_TTL_SECONDS", "60"))


class Leader:
    def __init__(self, name=LEASE_NAME, ttl=DEFAULT_TTL, engine=None):
        self.name = name
        self.ttl = ttl
        self.engine = engine
        self.holder = leases.new_holder_id()
        self.is_leader = False

    def check(self, now=None):
        """Renews the lease if we hold it, otherwise tries to take it. Returns True if we lead."""
        try:
            self.is_leader = (leases.renew(self.name, self.holder, self.ttl, self.engine, now)
                              or leases.acquire(self.name, self.holder, self.ttl, self.engine, now))
        except Exception:  # noqa: BLE001 - if the database is unreachable we must not act as leader
            self.is_leader = False
        return self.is_leader

    def step_down(self):
        self.is_leader = False
        try:
            leases.release(self.name, self.holder, self.engine)
        except Exception:  # noqa: BLE001
            pass
