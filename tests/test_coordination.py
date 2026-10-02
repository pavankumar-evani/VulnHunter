"""
Tests for running several replicas safely: database leases, leader election, the durable job
queue and its worker, the database-backed file lock, cross-replica schema creation and secrets
supplied as files (a key vault mount). No network; SQLite stands in for the shared database.
"""
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine  # noqa: E402

from remediation.coordination import jobs, leases, worker  # noqa: E402
from remediation.coordination.leader import Leader  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from remediation.utils import secret_files  # noqa: E402
from remediation.utils.file_lock import FileLock, LockTimeoutError  # noqa: E402


class SharedDb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # a file database (not :memory:) because the tests use several threads
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'c.db'}", connect_args={"timeout": 30})

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()


class LeaseTests(SharedDb):
    def test_only_one_holder_at_a_time(self):
        self.assertTrue(leases.acquire("x", "a", 30, self.engine, now=1000))
        self.assertFalse(leases.acquire("x", "b", 30, self.engine, now=1010))
        self.assertTrue(leases.acquire("x", "a", 30, self.engine, now=1010))  # the holder extends its own

    def test_an_expired_lease_can_be_taken(self):
        leases.acquire("x", "a", 30, self.engine, now=1000)
        self.assertTrue(leases.acquire("x", "b", 30, self.engine, now=1031))
        self.assertFalse(leases.renew("x", "a", 30, self.engine, now=1032))  # a learns it lost the lease

    def test_release_frees_it(self):
        leases.acquire("x", "a", 30, self.engine, now=1000)
        leases.release("x", "b", self.engine)  # not the holder: no effect
        self.assertFalse(leases.acquire("x", "b", 30, self.engine, now=1001))
        leases.release("x", "a", self.engine)
        self.assertTrue(leases.acquire("x", "b", 30, self.engine, now=1001))
        self.assertEqual(leases.current("x", self.engine, now=1002)[0], "b")

    def test_lease_lock_times_out_while_held(self):
        leases.acquire("busy", "other", 60, self.engine)
        with self.assertRaises(leases.LeaseTimeout):
            with leases.lease_lock("busy", timeout=0.2, engine=self.engine):
                pass

    def test_lease_lock_serialises_threads(self):
        counter = {"n": 0, "inside": 0, "overlap": False}

        def work():
            for _ in range(10):
                with leases.lease_lock("cnt", timeout=30, engine=self.engine):
                    counter["inside"] += 1
                    counter["overlap"] |= counter["inside"] > 1
                    counter["n"] += 1
                    counter["inside"] -= 1

        threads = [threading.Thread(target=work) for _ in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(counter["n"], 40)
        self.assertFalse(counter["overlap"])


class LeaderTests(SharedDb):
    def test_one_leader_and_failover(self):
        a, b = Leader(ttl=30, engine=self.engine), Leader(ttl=30, engine=self.engine)
        self.assertTrue(a.check(now=1000))
        self.assertFalse(b.check(now=1001))
        self.assertTrue(a.check(now=1020))   # a keeps renewing, so b still cannot lead
        self.assertFalse(b.check(now=1030))
        self.assertTrue(b.check(now=1060))   # a stopped renewing; its lease ran out
        self.assertFalse(a.check(now=1061))  # a does not take it back while b is renewing

    def test_step_down_hands_over_at_once(self):
        a, b = Leader(ttl=300, engine=self.engine), Leader(ttl=300, engine=self.engine)
        a.check()
        a.step_down()
        self.assertTrue(b.check())

    def test_a_database_error_means_not_leader(self):
        a = Leader(engine=self.engine)
        with patch.object(leases, "renew", side_effect=RuntimeError("db down")):
            self.assertFalse(a.check())


class JobQueueTests(SharedDb):
    def test_dedupe_key_does_not_queue_twice_while_active(self):
        first = jobs.enqueue("connection.sync", {"connection_id": 1}, dedupe_key="sync:1", engine=self.engine)
        self.assertEqual(jobs.enqueue("connection.sync", {"connection_id": 1}, dedupe_key="sync:1", engine=self.engine), first)
        job = jobs.claim("w", engine=self.engine)
        self.assertEqual(jobs.enqueue("connection.sync", {}, dedupe_key="sync:1", engine=self.engine), first)  # still active (running)
        jobs.complete(job["id"], "w", engine=self.engine)
        self.assertNotEqual(jobs.enqueue("connection.sync", {}, dedupe_key="sync:1", engine=self.engine), first)  # done: a new one is allowed

    def test_claims_in_order_and_never_twice(self):
        ids = [jobs.enqueue("k", {"n": i}, engine=self.engine) for i in range(3)]
        got = [jobs.claim(f"w{i}", engine=self.engine)["id"] for i in range(3)]
        self.assertEqual(got, ids)
        self.assertIsNone(jobs.claim("w9", engine=self.engine))

    def test_delayed_job_waits(self):
        jobs.enqueue("k", delay=100, engine=self.engine, now=1000)
        self.assertIsNone(jobs.claim("w", engine=self.engine, now=1050))
        self.assertIsNotNone(jobs.claim("w", engine=self.engine, now=1101))

    def test_concurrent_workers_split_the_work_without_overlap(self):
        for i in range(30):
            jobs.enqueue("k", {"n": i}, engine=self.engine)
        seen, lock = [], threading.Lock()

        def drain(name):
            while True:
                j = jobs.claim(name, engine=self.engine)
                if not j:
                    return
                with lock:
                    seen.append(j["id"])
                jobs.complete(j["id"], name, engine=self.engine)

        threads = [threading.Thread(target=drain, args=(f"w{i}",)) for i in range(5)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(seen), list(range(1, 31)))  # every job exactly once
        self.assertEqual(jobs.stats(self.engine)["done"], 30)

    def test_failure_retries_with_backoff_then_goes_dead(self):
        jid = jobs.enqueue("k", max_attempts=2, engine=self.engine, now=1000)
        j = jobs.claim("w", engine=self.engine, now=1000)
        self.assertEqual(jobs.fail(j["id"], "w", "boom", self.engine, now=1000), "queued")
        self.assertIsNone(jobs.claim("w", engine=self.engine, now=1010))  # backing off
        j = jobs.claim("w", engine=self.engine, now=1031)
        self.assertEqual(j["attempts"], 2)
        self.assertEqual(jobs.fail(j["id"], "w", "boom again", self.engine, now=1031), "dead")
        self.assertEqual((jobs.get(jid, self.engine)["status"], jobs.get(jid, self.engine)["error"]), ("dead", "boom again"))

    def test_a_job_whose_worker_died_is_given_back(self):
        jobs.enqueue("k", engine=self.engine, now=1000)
        jobs.claim("dead-worker", visibility=60, engine=self.engine, now=1000)
        self.assertIsNone(jobs.claim("w2", engine=self.engine, now=1030))  # still within the visibility timeout
        again = jobs.claim("w2", engine=self.engine, now=1061)
        self.assertEqual((again["locked_by"], again["attempts"]), ("w2", 2))

    def test_a_dead_workers_job_out_of_attempts_is_marked_dead(self):
        jid = jobs.enqueue("k", max_attempts=1, engine=self.engine, now=1000)
        jobs.claim("dead-worker", visibility=60, engine=self.engine, now=1000)
        self.assertIsNone(jobs.claim("w2", engine=self.engine, now=1100))
        self.assertEqual(jobs.get(jid, self.engine)["status"], "dead")

    def test_heartbeat_keeps_a_long_job(self):
        jobs.enqueue("k", engine=self.engine, now=1000)
        j = jobs.claim("w", visibility=60, engine=self.engine, now=1000)
        self.assertTrue(jobs.heartbeat(j["id"], "w", 60, self.engine, now=1050))
        self.assertIsNone(jobs.claim("w2", engine=self.engine, now=1100))  # extended to 1110
        self.assertFalse(jobs.heartbeat(j["id"], "someone-else", 60, self.engine, now=1060))

    def test_only_the_owner_can_complete(self):
        jobs.enqueue("k", engine=self.engine)
        j = jobs.claim("w", engine=self.engine)
        self.assertFalse(jobs.complete(j["id"], "intruder", engine=self.engine))
        self.assertTrue(jobs.complete(j["id"], "w", {"ok": True}, self.engine))


class WorkerTests(SharedDb):
    def test_runs_a_handler_and_records_the_result(self):
        jid = jobs.enqueue("echo", {"x": 5}, engine=self.engine)
        out = worker.run_one("w", {"echo": lambda p: {"got": p["x"]}}, engine=self.engine)
        self.assertEqual(out, {"id": jid, "kind": "echo", "outcome": "done"})
        self.assertEqual(jobs.get(jid, self.engine)["status"], "done")
        self.assertIsNone(worker.run_one("w", {"echo": lambda p: {}}, engine=self.engine))

    def test_a_raising_handler_is_retried_not_fatal(self):
        jid = jobs.enqueue("bad", engine=self.engine)

        def bad(_):
            raise ValueError("nope")

        out = worker.run_one("w", {"bad": bad}, engine=self.engine)
        self.assertEqual(out["outcome"], "queued")
        job = jobs.get(jid, self.engine)
        self.assertIn("ValueError: nope", job["error"])

    def test_only_handled_kinds_are_taken(self):
        jobs.enqueue("other", engine=self.engine)
        self.assertIsNone(worker.run_one("w", {"echo": lambda p: {}}, engine=self.engine))
        self.assertEqual(jobs.stats(self.engine)["queued"], 1)

    def test_connection_sync_handler_calls_the_sync(self):
        with patch("remediation.connections.sync.run", return_value={"ok": True, "message": "m", "count": 3}) as run:
            result = worker.handle_connection_sync({"connection_id": 7, "actor": "scheduler"})
        run.assert_called_once_with(7, "scheduler")
        self.assertEqual(result["count"], 3)

    def test_enqueue_due_queues_each_due_connection_once(self):
        from remediation.connections import sync
        with patch("remediation.connections.sync.store.due", return_value=[{"id": 4, "name": "T"}, {"id": 5, "name": "Q"}]):
            first = sync.enqueue_due(self.engine)
            second = sync.enqueue_due(self.engine)  # a double tick, or a slow sync
        self.assertEqual([r["job"] for r in first], [r["job"] for r in second])
        self.assertEqual(jobs.stats(self.engine)["queued"], 2)


class DbLockBackendTests(SharedDb):
    def test_file_lock_uses_a_lease_when_configured(self):
        path = str(Path(self.tmp.name) / "findings.json")
        counter = {"n": 0}

        def work():
            for _ in range(8):
                with FileLock(path, timeout=30):
                    v = counter["n"]
                    counter["n"] = v + 1

        with patch.dict(os.environ, {"QUANTA_LOCK_BACKEND": "db"}), patch.object(db_module, "get_engine", return_value=self.engine):
            threads = [threading.Thread(target=work) for _ in range(4)]
            [t.start() for t in threads]
            [t.join() for t in threads]
            self.assertEqual(counter["n"], 32)
            self.assertFalse(os.path.exists(path + ".lock"))  # no lock file: the lock lived in the database

    def test_a_held_lease_times_out_like_a_file_lock(self):
        path = str(Path(self.tmp.name) / "x.json")
        with patch.dict(os.environ, {"QUANTA_LOCK_BACKEND": "db"}), patch.object(db_module, "get_engine", return_value=self.engine):
            with FileLock(path, timeout=5):
                with self.assertRaises(LockTimeoutError):
                    FileLock(path, timeout=0.2).acquire()

    def test_default_is_still_a_file_lock(self):
        path = str(Path(self.tmp.name) / "y.json")
        with FileLock(path):
            self.assertTrue(os.path.exists(path + ".lock"))


class SchemaTests(SharedDb):
    def test_new_tables_exist_and_schema_creation_is_idempotent(self):
        db_module.ensure_schema(self.engine)
        db_module.ensure_schema(self.engine)
        from sqlalchemy import inspect
        names = inspect(self.engine).get_table_names()
        for t in ("leases", "jobs", "api_keys", "ticket_links"):
            self.assertIn(t, names)


class SecretFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = Path(self.tmp.name) / name
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_reads_the_value_and_strips_the_newline(self):
        env = {"QUANTA_SESSION_SECRET_FILE": self.write("s", "abc123\n")}
        self.assertEqual(secret_files.load_file_env(env), ["QUANTA_SESSION_SECRET"])
        self.assertEqual(env["QUANTA_SESSION_SECRET"], "abc123")

    def test_an_explicit_value_wins(self):
        env = {"QUANTA_SESSION_SECRET": "explicit", "QUANTA_SESSION_SECRET_FILE": self.write("s", "fromfile")}
        self.assertEqual(secret_files.load_file_env(env), [])
        self.assertEqual(env["QUANTA_SESSION_SECRET"], "explicit")

    def test_a_missing_or_empty_file_is_an_error(self):
        with self.assertRaises(RuntimeError):
            secret_files.load_file_env({"QUANTA_ENCRYPTION_KEY_FILE": str(Path(self.tmp.name) / "nope")})
        with self.assertRaises(RuntimeError):
            secret_files.load_file_env({"QUANTA_ENCRYPTION_KEY_FILE": self.write("e", "\n")})

    def test_a_multi_key_rotation_list_survives(self):
        env = {"QUANTA_ENCRYPTION_KEY_FILE": self.write("k", "newkey,oldkey\n")}
        secret_files.load_file_env(env)
        self.assertEqual(env["QUANTA_ENCRYPTION_KEY"], "newkey,oldkey")

    def test_unrelated_settings_are_never_read_from_files(self):
        env = {"PATH_FILE": self.write("p", "x"), "QUANTA_PORT_FILE": self.write("q", "1")}
        self.assertEqual(secret_files.load_file_env(env), [])
        self.assertNotIn("QUANTA_PORT", env)


if __name__ == "__main__":
    unittest.main()
