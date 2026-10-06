#!/usr/bin/env python3
"""Release preflight and rollback tooling for Quanta.

    python cli/quanta_release.py info
    python cli/quanta_release.py check --target dev|test|prod [--env-file FILE] [--backup-dir DIR] [--max-backup-age-hours N]
    python cli/quanta_release.py backup [--out DIR]
    python cli/quanta_release.py rollback-plan --environment prod --from 1.3.0 --to 1.2.4 [--revision N] [--release quanta] [--namespace quanta]

`check` exits 1 on any FAIL. `rollback-plan` only prints; this tool never runs helm, kubectl or a restore.
Kept apart from quanta_admin.py (which operates one running instance) because this is about releasing a build.
"""
import argparse
import datetime
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from remediation.utils import environment  # noqa: E402

TARGETS = ("dev", "test", "prod")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
_TRUE = ("1", "true", "yes", "on")


def _truthy(env, key):
    return (env.get(key) or "").strip().lower() in _TRUE


def read_env_file(path):
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


# --------------------------------------------------------------------------------------------- individual checks
# Each returns a list of (level, name, detail); level is PASS, WARN or FAIL.

def check_version(root):
    p = Path(root) / "VERSION"
    try:
        v = p.read_text(encoding="utf-8").strip()
    except OSError:
        return [("FAIL", "version", "VERSION file is missing")]
    if not SEMVER.match(v):
        return [("FAIL", "version", f"VERSION {v!r} is not valid SemVer (MAJOR.MINOR.PATCH)")]
    out = [("PASS", "version", f"{v} is valid SemVer")]
    try:
        log = (Path(root) / "CHANGELOG.md").read_text(encoding="utf-8")
    except OSError:
        return out + [("FAIL", "changelog", "CHANGELOG.md is missing")]
    if re.search(rf"^##\s*\[{re.escape(v)}\]", log, re.M):
        out.append(("PASS", "changelog", f"has a heading for {v}"))
    else:
        m = re.search(r"^##\s*\[Unreleased\]\s*\n(.*?)(?=^##\s*\[|\Z)", log, re.M | re.S)
        if m and re.search(r"^\s*(-|\*)\s+\S", m.group(1), re.M):
            out.append(("PASS", "changelog", f"no heading for {v} yet, but [Unreleased] has entries to be released as {v}"))
        else:
            out.append(("FAIL", "changelog", f"no [{v}] heading and nothing under [Unreleased]: a release needs a recorded change"))
    return out


def check_migrations():
    try:
        from remediation.utils import db as db_module
        from remediation.utils import migrations
        engine = db_module.get_engine()
        db_module.ensure_schema(engine)
        pend = migrations.pending(engine)
    except Exception as exc:  # noqa: BLE001
        return [("WARN", "migrations", f"could not read the migration state ({type(exc).__name__}: {exc})")]
    if not pend:
        return [("PASS", "migrations", "none pending")]
    names = ", ".join(f"{v}:{n}" for v, n in pend)
    return [("WARN", "migrations", f"{len(pend)} pending, applied automatically at startup (expand-only): {names}")]


def check_backup(target, backup_dir, max_age_hours, now=None):
    if target != "prod":
        return [("PASS", "backup", f"not required for {target}")]
    d = Path(backup_dir)
    files = sorted(d.glob("quanta-backup-*.zip"), key=lambda f: f.stat().st_mtime, reverse=True) if d.is_dir() else []
    if not files:
        return [("FAIL", "backup", f"no quanta-backup-*.zip in {d}: take one first (python cli/quanta_release.py backup)")]
    age_h = ((now or time.time()) - files[0].stat().st_mtime) / 3600
    if age_h > max_age_hours:
        return [("FAIL", "backup", f"newest backup {files[0].name} is {age_h:.1f}h old (limit {max_age_hours}h)")]
    return [("PASS", "backup", f"{files[0].name} is {age_h:.1f}h old")]


def _helm_replicas(root, target):
    import yaml
    try:
        data = yaml.safe_load((Path(root) / "deploy" / "helm" / "quanta" / f"values-{target}.yaml").read_text(encoding="utf-8")) or {}
        return int((data.get("web") or {}).get("replicas", 1))
    except Exception:  # noqa: BLE001
        return 1


def check_config(target, env, root):
    out = []

    def add(level, name, detail):
        out.append((level, name, detail))
    declared = (env.get("QUANTA_ENV") or "").strip().lower()
    if declared and declared not in TARGETS:
        add("FAIL", "QUANTA_ENV", f"{declared!r} is not dev, test or prod")
    elif declared and declared != target:
        add("FAIL", "QUANTA_ENV", f"is {declared} but the target is {target}")
    if target != "prod":
        add("PASS", "config", f"{target}: production-only rules are not applied")
        return out
    secret = env.get("QUANTA_SESSION_SECRET") or ""
    add("PASS" if len(secret) >= 32 else "FAIL", "session secret", "set, 32+ characters" if len(secret) >= 32 else "QUANTA_SESSION_SECRET must be at least 32 characters")
    add("PASS" if (env.get("QUANTA_ENCRYPTION_KEY") or env.get("QUANTA_ENCRYPTION_KEY_FILE")) else "FAIL", "encryption key",
        "set" if (env.get("QUANTA_ENCRYPTION_KEY") or env.get("QUANTA_ENCRYPTION_KEY_FILE")) else "QUANTA_ENCRYPTION_KEY is not set: stored credentials cannot be encrypted")
    if _truthy(env, "QUANTA_DISABLE_TLS"):
        ok = _truthy(env, "QUANTA_BEHIND_INGRESS")
        add("PASS" if ok else "FAIL", "TLS", "plain HTTP behind a TLS-terminating ingress (QUANTA_BEHIND_INGRESS)" if ok
            else "QUANTA_DISABLE_TLS is on and QUANTA_BEHIND_INGRESS is not: production must terminate TLS somewhere")
    else:
        add("PASS", "TLS", "not disabled")
    try:
        import quanta_admin
        from auth import users
        demo = [e for e in quanta_admin.DEMO_ACCOUNTS if users.verify_login(e, quanta_admin.DEMO_PASSWORD)]
        add("FAIL" if demo else "PASS", "demo accounts", f"still have the published password: {', '.join(demo)}" if demo else "none with the published password")
        sample = quanta_admin.is_sample_dataset()
        add("FAIL" if sample else "PASS", "sample data", "the bundled sample findings are present: run clear-sample-data" if sample else "bundled sample data is absent")
    except Exception as exc:  # noqa: BLE001
        add("WARN", "demo accounts / sample data", f"could not check ({type(exc).__name__}: {exc})")
    if _truthy(env, "QUANTA_ALLOW_SIMULATION"):
        add("WARN", "simulation", "QUANTA_ALLOW_SIMULATION is on: simulated data will be shown, and the banner says so. Only for a hosted demonstration site")
    else:
        add("PASS", "simulation", "off")
    mode = (env.get("QUANTA_LICENSE_MODE") or "").strip().lower()
    add("PASS" if mode in ("off", "warn", "enforce") else "FAIL", "licence mode", mode if mode in ("off", "warn", "enforce") else "QUANTA_LICENSE_MODE must be set to off, warn or enforce on purpose")
    replicas = int(env.get("QUANTA_REPLICAS") or _helm_replicas(root, target))
    url = (env.get("QUANTA_DATABASE_URL") or "").strip()
    if replicas > 1 and (not url or url.startswith("sqlite")):
        add("FAIL", "database", f"{replicas} replicas need a shared PostgreSQL in QUANTA_DATABASE_URL, not SQLite")
    else:
        add("PASS", "database", f"{replicas} replica(s), {'PostgreSQL or other shared database' if url and not url.startswith('sqlite') else 'single-writer SQLite'}")
    return out


def check_deployment_files(target, root):
    import yaml
    root = Path(root)
    out = []
    vals = root / "deploy" / "helm" / "quanta" / f"values-{target}.yaml"
    if not vals.is_file():
        out.append(("FAIL", "helm values", f"{vals.relative_to(root)} is missing"))
    else:
        try:
            data = yaml.safe_load(vals.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            data = {}
            out.append(("FAIL", "helm values", f"{vals.name} does not parse: {exc}"))
        env = (data.get("config") or {}).get("environment")
        if env == target:
            out.append(("PASS", "helm values", f"{vals.name} sets config.environment={target}"))
        elif data:
            out.append(("FAIL", "helm values", f"{vals.name} sets config.environment={env!r}, expected {target!r}"))
    try:
        v = (root / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return out
    chart = root / "deploy" / "helm" / "quanta" / "Chart.yaml"
    if chart.is_file():
        app = str((yaml.safe_load(chart.read_text(encoding="utf-8")) or {}).get("appVersion", ""))
        out.append(("PASS" if app == v else "FAIL", "chart appVersion", f"{app} matches VERSION" if app == v else f"Chart.yaml appVersion {app} differs from VERSION {v}"))
    df = root / "Dockerfile"
    if df.is_file():
        m = re.search(r"^ARG\s+VERSION=(\S+)", df.read_text(encoding="utf-8"), re.M)
        if not m:
            out.append(("FAIL", "Dockerfile", "has no ARG VERSION"))
        else:
            out.append(("PASS" if m.group(1) == v else "FAIL", "Dockerfile", f"ARG VERSION={m.group(1)} matches VERSION" if m.group(1) == v else f"ARG VERSION={m.group(1)} differs from VERSION {v}"))
    for name in ("docker-compose.yml", "docker-compose.dev.yml", "docker-compose.test.yml"):
        f = root / name
        if f.is_file():
            stale = sorted({x for x in re.findall(r"quanta:(\d+\.\d+\.\d+\S*)", f.read_text(encoding="utf-8")) if x != v})
            out.append(("FAIL", name, f"references version(s) {', '.join(stale)} but VERSION is {v}") if stale else ("PASS", name, "no stale version reference"))
    return out


def run_checks(target, env=None, root=ROOT, backup_dir=None, max_backup_age_hours=24, now=None):
    env = os.environ if env is None else env
    backup_dir = backup_dir or env.get("QUANTA_BACKUP_DIR") or "backups"
    out = []
    out += check_version(root)
    out += check_migrations()
    out += check_backup(target, backup_dir, max_backup_age_hours, now)
    out += check_config(target, env, root)
    out += check_deployment_files(target, root)
    return out


# --------------------------------------------------------------------------------------------- commands

def cmd_info(_a):
    i = environment.info()
    for k in ("version", "environment", "build_sha", "build_time", "simulation_allowed"):
        print(f"{k:<20}{i[k]}")
    return 0


def cmd_check(a):
    env = dict(os.environ)
    if a.env_file:
        env.update(read_env_file(a.env_file))
    results = run_checks(a.target, env=env, backup_dir=a.backup_dir, max_backup_age_hours=a.max_backup_age_hours)
    width = max(len(n) for _, n, _ in results)
    for level, name, detail in results:
        print(f"[{level}] {name:<{width}}  {detail}")
    fails = sum(1 for r in results if r[0] == "FAIL")
    print(f"\n{a.target}: {fails} failure(s), {sum(1 for r in results if r[0] == 'WARN')} warning(s).")
    return 1 if fails else 0


def cmd_backup(a):
    import quanta_admin
    quanta_admin.cmd_backup(argparse.Namespace(out=a.out))
    return 0


def rollback_plan(environment_name, from_version, to_version, revision=None, release="quanta", namespace="quanta"):
    rev = str(revision) if revision else "<REVISION from helm history>"
    steps = [
        f"ROLLBACK PLAN  {environment_name}: {from_version} -> {to_version}   (printed only, nothing has been run)",
        "",
        "0. Decide and record. Stop further promotion. Note the time and reason in the release's change record.",
        "",
        "1. APPLICATION (the image and chart)",
        f"   helm history {release} -n {namespace}                 # find the last good revision (the one running {to_version})",
        f"   helm rollback {release} {rev} -n {namespace} --wait   # --wait returns only when the pods are ready again",
        f"   kubectl rollout status deploy/{release} -n {namespace}",
        "   Helm restores the previous chart and the values that release was installed with.",
        "",
        "2. CONFIGURATION (the saved values)",
        f"   helm get values {release} -n {namespace} --revision {rev}   # what that revision ran with",
        "   The pipeline stores `helm get values` and `helm history` as artifacts before every deploy; if values were changed outside Helm,",
        "   re-apply them from that artifact: helm upgrade --reuse-values is NOT enough, use -f <saved-values.yaml>.",
        "",
        "3. DATABASE",
        "   Migrations are expand-only (new nullable columns and tables, backfills): the previous version still works on the migrated schema,",
        f"   so rolling the application back to {to_version} does NOT need a database restore.",
        "   Restore the pre-upgrade backup ONLY if this release included a contract step (a column or table was dropped or renamed),",
        "   or if data was damaged. Restoring loses everything written since the backup:",
        "     - stop the application (scale to 0), restore with your platform tooling or quanta_admin restore --yes <backup.zip>,",
        "       then start the previous version. Keep the failed state's own backup first.",
        "",
        "4. VERIFY",
        f"   GET /readyz returns 200, GET /api/status shows version {to_version} and the right environment,",
        "   a login works, the Connections page lists the connections, one sync runs, the queue shows the expected finding count.",
        "",
        "5. RECORD: revision rolled back to, who approved, what was verified, and open a fix-forward issue for the defect.",
    ]
    return "\n".join(steps)


def cmd_rollback_plan(a):
    print(rollback_plan(a.environment, a.from_version, a.to_version, a.revision, a.release, a.namespace))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="quanta_release", description="Quanta release preflight and rollback tooling")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("info", help="version, environment, build").set_defaults(func=cmd_info)
    c = sub.add_parser("check", help="preflight for a target environment; exit 1 on any FAIL")
    c.add_argument("--target", required=True, choices=TARGETS)
    c.add_argument("--env-file", help="KEY=VALUE file of the target's settings, added to the process environment")
    c.add_argument("--backup-dir", help="where backups live (default $QUANTA_BACKUP_DIR or ./backups)")
    c.add_argument("--max-backup-age-hours", type=float, default=24)
    c.set_defaults(func=cmd_check)
    b = sub.add_parser("backup", help="take a backup (same as quanta_admin backup)")
    b.add_argument("--out", default="backups")
    b.set_defaults(func=cmd_backup)
    r = sub.add_parser("rollback-plan", help="print the ordered rollback steps; runs nothing")
    r.add_argument("--environment", required=True, choices=TARGETS)
    r.add_argument("--from", dest="from_version", required=True)
    r.add_argument("--to", dest="to_version", required=True)
    r.add_argument("--revision", help="the helm revision to roll back to")
    r.add_argument("--release", default="quanta")
    r.add_argument("--namespace", default="quanta")
    r.set_defaults(func=cmd_rollback_plan)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
