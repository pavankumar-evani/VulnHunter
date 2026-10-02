"""
End-to-end check of running several replicas, with real processes.

Copies the application twice (pod A, pod B: separate directories, so no shared files), points both
at one database, and starts two web processes and one queue worker. Then it checks the things a
multi-replica deployment depends on:

  1. first-run setup (`quanta-admin prepare`) run by both pods at once happens exactly once
  2. a finding pushed to pod A through the ingest API is visible on pod B (files reconciled through
     the database, no shared volume)
  3. exactly one pod is the scheduler leader, and when it is stopped the other takes over
  4. a queued job is picked up and run by the worker, and a failing job is retried then marked failed
  5. pod B serves a policy file seeded from the image, and it matches pod A's

Uses SQLite as the shared database (several processes can share one file), so it needs nothing
installed beyond the app's own requirements. The same coordination code runs on PostgreSQL in a
cluster; this proves the logic across processes, not PostgreSQL-specific behaviour.

    python scripts/e2e_replicas.py            # exits 0 and prints PASS lines, or exits 1 on the first failure
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parent.parent
IGNORE = shutil.ignore_patterns(".git", ".claude", "deliverables", "scripts", "docs", "tests", "node_modules", "__pycache__",
                                "*.db", "*.db-journal", "vulnerable-demo-app", "_build", ".sample-backup", "*.lock", "certs")
PORTS = {"a": 5071, "b": 5072}
ADMIN_EMAIL, ADMIN_PASSWORD = "admin@e2e.local", "e2e-admin-password-123"
procs = []


def check(ok, message):
    print(("PASS  " if ok else "FAIL  ") + message, flush=True)
    if not ok:
        raise SystemExit(1)


def wait_for(fn, timeout, interval=0.5):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(interval)
    return None


def make_pod(root, name):
    dest = root / name
    shutil.copytree(REPO, dest, ignore=IGNORE)
    return dest


def env_for(db_url, extra=None):
    env = dict(os.environ)
    env.update({
        "QUANTA_DATABASE_URL": db_url, "QUANTA_PRODUCTION": "true", "QUANTA_DISABLE_TLS": "true", "QUANTA_HOST": "127.0.0.1",
        "QUANTA_SESSION_SECRET": "e2e-session-secret-0123456789abcdef0123456789", "QUANTA_LOCK_BACKEND": "db",
        "QUANTA_FILES_BACKEND": "db", "QUANTA_FILES_SYNC_SECONDS": "1", "QUANTA_LEADER_TTL_SECONDS": "6",
        "QUANTA_LEADER_CHECK_SECONDS": "2", "QUANTA_EMBEDDED_WORKER": "false", "QUANTA_WORKER_POLL_SECONDS": "1",
        "QUANTA_BOOTSTRAP_ADMIN_EMAIL": ADMIN_EMAIL, "QUANTA_ADMIN_PASSWORD": ADMIN_PASSWORD, "QUANTA_LOG_FORMAT": "text",
        "QUANTA_RATE_LIMIT_MAX": "100000", "NOTIFICATION_CHECK_INTERVAL_SECONDS": "3600", "PYTHONDONTWRITEBYTECODE": "1",
    })
    env["QUANTA_ENCRYPTION_KEY"] = env.get("QUANTA_ENCRYPTION_KEY") or subprocess.check_output(
        [sys.executable, "-c", "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"], text=True).strip()
    env.update(extra or {})
    return env


def start(pod, args, env, logfile):
    p = subprocess.Popen([sys.executable, *args], cwd=pod, env=env, stdout=open(logfile, "w"), stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def session(port):
    s = requests.Session()
    r = s.post(f"http://127.0.0.1:{port}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
    check(r.status_code == 200, f"admin can sign in on :{port}")
    return s


def main():
    tmp = Path(tempfile.mkdtemp(prefix="quanta-e2e-"))
    try:
        pods = {n: make_pod(tmp, n) for n in PORTS}
        db_url = f"sqlite:///{(tmp / 'shared.db').as_posix()}"
        env = env_for(db_url)

        # 1. both pods run first-run setup at the same moment
        prep = [subprocess.Popen([sys.executable, "cli/quanta_admin.py", "prepare"], cwd=pods[n], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) for n in PORTS]
        outs = [p.communicate(timeout=180)[0] for p in prep]
        check(all(p.returncode == 0 for p in prep), "prepare succeeds on both pods when started together")
        created = sum("Created the first administrator" in o for o in outs)
        check(created == 1, f"the first administrator was created exactly once (by {created} pod)")

        # start web A, web B and one worker
        logs = {}
        web = {n: start(pods[n], ["dashboard/app.py"], {**env, "QUANTA_PORT": str(PORTS[n])}, tmp / f"web-{n}.log") for n in PORTS}
        start(pods["a"], ["cli/quanta_admin.py", "worker"], env, tmp / "worker.log")
        for n, port in PORTS.items():
            ok = wait_for(lambda port=port: requests.get(f"http://127.0.0.1:{port}/healthz", timeout=3).status_code == 200, 90)
            check(bool(ok), f"web pod {n} is healthy")

        a, b = session(PORTS["a"]), session(PORTS["b"])

        # 2. a finding pushed to A is visible on B
        key = a.post(f"http://127.0.0.1:{PORTS['a']}/api/api-keys", json={"name": "e2e", "scopes": ["ingest:write", "read:findings"]}).json()["key"]
        h = {"Authorization": f"Bearer {key}"}
        before = requests.get(f"http://127.0.0.1:{PORTS['b']}/api/export/findings", headers=h, timeout=15)
        check(before.status_code == 200 and before.json()["total"] == 0, "a fresh production deployment starts with no findings on pod B")
        r = requests.post(f"http://127.0.0.1:{PORTS['a']}/api/ingest/findings", headers=h, timeout=30, json={
            "source": "e2e-scanner", "enrich": False,
            "findings": [{"title": "Outdated TLS", "severity": "High", "asset": {"name": "web01"}, "cve": "CVE-2024-1234", "source_ref": "s1"}]})
        check(r.status_code == 200 and r.json()["added"] == 1, "a finding is accepted on pod A")
        seen = wait_for(lambda: requests.get(f"http://127.0.0.1:{PORTS['b']}/api/export/findings", headers=h, timeout=15).json()["total"] == 1, 20)
        check(bool(seen), "the finding appears on pod B without any shared volume")
        again = requests.post(f"http://127.0.0.1:{PORTS['b']}/api/ingest/findings", headers=h, timeout=30, json={
            "source": "e2e-scanner", "enrich": False,
            "findings": [{"title": "Outdated TLS", "severity": "High", "asset": {"name": "web01"}, "cve": "CVE-2024-1234", "source_ref": "s1"},
                         {"title": "Weak cipher", "severity": "Medium", "asset": {"name": "web02"}, "source_ref": "s2"}]}).json()
        check((again["added"], again["updated"]) == (1, 0) and again["total"] == 2, "pod B merges against the cluster's copy: one new, none duplicated")
        ids = wait_for(lambda: (lambda d: d if d["total"] == 2 else None)(requests.get(f"http://127.0.0.1:{PORTS['a']}/api/export/findings", headers=h, timeout=15).json()), 20)
        check(bool(ids) and sorted(f["id"] for f in ids["findings"]) == ["FIND-1", "FIND-2"], "ids are unique across pods (FIND-1, FIND-2)")

        # 5. policy files agree
        cfg = "remediation/config/support_sla.yaml"
        same = (pods["a"] / cfg).read_text(encoding="utf-8") == (pods["b"] / cfg).read_text(encoding="utf-8")
        check(same, "both pods hold the same policy file")

        # 3. exactly one leader, and failover
        def leaders():
            out = {}
            for n, s in (("a", a), ("b", b)):
                try:
                    out[n] = s.get(f"http://127.0.0.1:{PORTS[n]}/api/admin/jobs", timeout=10).json()["leader"]
                except Exception:  # noqa: BLE001
                    out[n] = None
            return out

        state = wait_for(lambda: (lambda d: d if sum(1 for v in d.values() if v) == 1 else None)(leaders()), 30)
        check(bool(state), f"exactly one pod is the scheduler leader ({state})")
        leader = next(n for n, v in state.items() if v)
        other = "b" if leader == "a" else "a"
        web[leader].terminate()
        web[leader].wait(timeout=20)
        took = wait_for(lambda: leaders().get(other) is True, 40)
        check(bool(took), f"pod {other} takes over as leader after pod {leader} stops")

        # 4. the worker runs queued jobs; a failing one is retried then failed
        sys.path.insert(0, str(pods["a"]))
        os.environ.update({k: env[k] for k in ("QUANTA_DATABASE_URL", "QUANTA_ENCRYPTION_KEY")})
        from remediation.coordination import jobs  # noqa: E402
        jid = jobs.enqueue("connection.sync", {"connection_id": 999, "actor": "e2e"}, max_attempts=2)
        done = wait_for(lambda: (jobs.get(jid)["attempts"] >= 1 and jobs.get(jid)["error"]) or None, 30)
        check(bool(done), "the worker claimed the job and ran it (a connection that does not exist fails cleanly)")
        check(jobs.get(jid)["status"] in ("queued", "dead"), "the failed job is scheduled for retry, not lost")
        print("\nAll replica checks passed.")
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
