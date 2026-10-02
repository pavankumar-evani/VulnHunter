"""
Checks a Quanta release that is already installed in a Kubernetes namespace (used by the kind job
in .github/workflows/helm-kind.yml, and runnable against any cluster you can `kubectl` into).

    python scripts/e2e_cluster.py --namespace quanta --release quanta --admin-email a@b --admin-password ...

It port-forwards two different web pods and checks, against the real running pods, that:
  1. secrets reached the pods as files and are NOT in the environment
  2. a finding pushed to one pod is served by the other (no shared volume)
  3. exactly one pod is the scheduler leader, and a new one takes over when it is deleted
  4. the queue worker pods are running and can reach the queue
  5. data survives replacing every web pod (a rolling restart)
Exits 0 with PASS lines, or 1 on the first failure.
"""
import argparse
import json
import subprocess
import sys
import time

import requests


def sh(*args, check=True, capture=True):
    r = subprocess.run(args, capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}\n{r.stdout}\n{r.stderr}")
    return r.stdout.strip() if capture else ""


def check(ok, message):
    print(("PASS  " if ok else "FAIL  ") + message, flush=True)
    if not ok:
        raise SystemExit(1)


def wait_for(fn, timeout, interval=2):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except Exception:  # noqa: BLE001
            pass
        time.sleep(interval)
    return None


class Cluster:
    def __init__(self, ns, release):
        self.ns, self.release, self.forwards = ns, release, []

    def pods(self, component):
        """Names of Running, not-terminating pods of one component."""
        out = sh("kubectl", "-n", self.ns, "get", "pods", "-l",
                 f"app.kubernetes.io/instance={self.release},app.kubernetes.io/component={component}", "-o", "json")
        names = []
        for item in json.loads(out)["items"]:
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in item["status"].get("conditions", []))
            if ready and not item["metadata"].get("deletionTimestamp"):
                names.append(item["metadata"]["name"])
        return sorted(names)

    def forward(self, pod, local_port):
        p = subprocess.Popen(["kubectl", "-n", self.ns, "port-forward", f"pod/{pod}", f"{local_port}:5050"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.forwards.append(p)
        ok = wait_for(lambda: requests.get(f"http://127.0.0.1:{local_port}/healthz", timeout=3).status_code == 200, 40, 1)
        check(bool(ok), f"port-forward to {pod} works")

    def stop_forwards(self):
        for p in self.forwards:
            p.terminate()
        self.forwards = []


def login(port, email, password):
    s = requests.Session()
    r = s.post(f"http://127.0.0.1:{port}/api/auth/login", json={"email": email, "password": password}, timeout=15)
    check(r.status_code == 200, f"administrator can sign in through :{port}")
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", default="quanta")
    ap.add_argument("--release", default="quanta")
    ap.add_argument("--admin-email", required=True)
    ap.add_argument("--admin-password", required=True)
    a = ap.parse_args()
    c = Cluster(a.namespace, a.release)
    try:
        web = wait_for(lambda: (lambda p: p if len(p) >= 2 else None)(c.pods("web")), 120)
        check(bool(web), f"at least two web pods are running ({web})")
        pod_a, pod_b = web[0], web[1]

        # 1. secrets are files, not environment values
        env = sh("kubectl", "-n", a.namespace, "exec", pod_a, "--", "env")
        check("QUANTA_SESSION_SECRET=" not in env and "QUANTA_ENCRYPTION_KEY=" not in env and "QUANTA_DATABASE_URL=" not in env,
              "session secret, encryption key and database URL are not in the pod's environment")
        check("QUANTA_SESSION_SECRET_FILE=" in env, "the app is pointed at secret files (QUANTA_*_FILE)")
        files = sh("kubectl", "-n", a.namespace, "exec", pod_a, "--", "ls", "/var/run/secrets/quanta")
        check("QUANTA_SESSION_SECRET" in files and "QUANTA_ENCRYPTION_KEY" in files, "the secret files are mounted from the vault-backed Secret")

        c.forward(pod_a, 5081)
        c.forward(pod_b, 5082)
        sa, sb = login(5081, a.admin_email, a.admin_password), login(5082, a.admin_email, a.admin_password)

        # 2. a finding pushed through one pod is served by the other
        key = sa.post("http://127.0.0.1:5081/api/api-keys", json={"name": "e2e", "scopes": ["ingest:write", "read:findings"]}).json()["key"]
        h = {"Authorization": f"Bearer {key}"}
        r = requests.post("http://127.0.0.1:5081/api/ingest/findings", headers=h, timeout=30, json={
            "source": "e2e-scanner", "enrich": False,
            "findings": [{"title": "Outdated TLS", "severity": "High", "asset": {"name": "web01"}, "source_ref": "s1"}]})
        check(r.status_code == 200 and r.json()["total"] >= 1, "a finding is accepted through pod A")
        seen = wait_for(lambda: requests.get("http://127.0.0.1:5082/api/export/findings", headers=h, timeout=15).json()["total"] >= 1, 30)
        check(bool(seen), "pod B serves the finding (no shared volume)")

        # 3. exactly one leader; a new one is elected when it is deleted
        def leaders():
            res = {}
            for pod, s, port in ((pod_a, sa, 5081), (pod_b, sb, 5082)):
                res[pod] = s.get(f"http://127.0.0.1:{port}/api/admin/jobs", timeout=10).json()["leader"]
            return res

        state = wait_for(lambda: (lambda d: d if sum(1 for v in d.values() if v) == 1 else None)(leaders()), 60)
        check(bool(state), f"exactly one web pod is the scheduler leader ({state})")
        leader = next(p for p, v in state.items() if v)
        survivor = pod_b if leader == pod_a else pod_a
        sport, ssession = (5082, sb) if survivor == pod_b else (5081, sa)
        c.stop_forwards()
        c.forward(survivor, sport)
        ssession = login(sport, a.admin_email, a.admin_password)
        sh("kubectl", "-n", a.namespace, "delete", "pod", leader, "--wait=false")
        took = wait_for(lambda: ssession.get(f"http://127.0.0.1:{sport}/api/admin/jobs", timeout=10).json()["leader"], 120)
        check(bool(took), f"the surviving pod takes over as leader after {leader} is deleted")

        # 4. workers
        workers = wait_for(lambda: c.pods("worker"), 60)
        check(bool(workers), f"queue worker pods are running ({workers})")
        out = sh("kubectl", "-n", a.namespace, "exec", workers[0], "--", "python", "cli/quanta_admin.py", "jobs")
        check(out.startswith("Jobs:"), "a worker can reach the queue")

        # 5. replace every web pod; data must survive
        c.stop_forwards()
        sh("kubectl", "-n", a.namespace, "rollout", "restart", f"deploy/{a.release}-web")
        sh("kubectl", "-n", a.namespace, "rollout", "status", f"deploy/{a.release}-web", "--timeout=300s")
        new = wait_for(lambda: (lambda p: p if p and not set(p) & {pod_a, pod_b} else None)(c.pods("web")), 120)
        check(bool(new), f"the web pods were replaced ({new})")
        c.forward(new[0], 5083)
        total = wait_for(lambda: requests.get("http://127.0.0.1:5083/api/export/findings", headers=h, timeout=15).json()["total"] >= 1, 60)
        check(bool(total), "the finding is still there on a brand-new pod")
        print("\nAll cluster checks passed.")
    finally:
        c.stop_forwards()


if __name__ == "__main__":
    main()
