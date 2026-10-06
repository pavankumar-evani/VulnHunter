#!/usr/bin/env python3
"""
Quanta administration: the commands you need to install, run and look after a deployment.

    python cli/quanta_admin.py gen-key            # a new QUANTA_ENCRYPTION_KEY
    python cli/quanta_admin.py gen-secret         # a new QUANTA_SESSION_SECRET
    python cli/quanta_admin.py init               # create the database schema (no demo data)
    python cli/quanta_admin.py clear-sample-data --yes   # start empty: set the bundled sample data aside
    python cli/quanta_admin.py migrate [--check]  # apply (or list) pending schema migrations
    python cli/quanta_admin.py create-admin --email you@corp.com --name "You"
    python cli/quanta_admin.py bootstrap          # container first run: admin from environment, only if none exists
    python cli/quanta_admin.py reset-password --email you@corp.com
    python cli/quanta_admin.py list-users
    python cli/quanta_admin.py check              # is this deployment configured safely?
    python cli/quanta_admin.py backup --out ./backups
    python cli/quanta_admin.py restore --from ./backups/quanta-backup-....zip --yes
    python cli/quanta_admin.py integrity-manifest # baseline of the code and shipped config (build time)
    python cli/quanta_admin.py check-integrity [--heal [--confirm]]   # code drift + store consistency; safe repairs preview unless --confirm
    python cli/quanta_admin.py rotate-keys        # re-encrypt stored credentials under the newest key
    python cli/quanta_admin.py seed-appsec-demo   # a demo application, SBOM and findings for the Applications pages (--remove undoes it)

Passwords are read from QUANTA_ADMIN_PASSWORD or prompted for; never put one on the command line.
"""
import argparse
import datetime
import getpass
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(REPO_ROOT), str(REPO_ROOT / "dashboard")]

from sqlalchemy import select, text, update  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

from remediation.utils import secret_files  # noqa: E402

secret_files.load_file_env()

from remediation.connections import crypto  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from remediation.utils import migrations  # noqa: E402

FINDINGS = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
CONFIG_DIR = REPO_ROOT / "remediation" / "config"
PLAN_FILE = REPO_ROOT / "REMEDIATION_PLAN.md"
SAMPLE_BACKUP = REPO_ROOT / "remediation" / ".sample-backup"
DEMO_ACCOUNTS = ("admin@quanta.local", "analyst@quanta.local")
DEMO_PASSWORD = "ChangeMe123!"


def _flag(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def _password(prompt_label="Password"):
    pw = os.environ.get("QUANTA_ADMIN_PASSWORD")
    if pw:
        return pw
    if not sys.stdin.isatty():
        raise SystemExit("Set QUANTA_ADMIN_PASSWORD (no terminal to prompt on).")
    a, b = getpass.getpass(f"{prompt_label}: "), getpass.getpass("Repeat: ")
    if a != b:
        raise SystemExit("Passwords do not match.")
    return a


def mask_url(url):
    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001
        return "(unparseable)"


# ------------------------------------------------------------------ commands
def cmd_gen_key(_a):
    print(crypto.generate_key())


def cmd_gen_secret(_a):
    import secrets
    print(secrets.token_hex(32))


def cmd_init(_a):
    engine = db_module.get_engine()
    db_module.ensure_schema(engine)
    print(f"Database ready: {mask_url(db_module.database_url())}")
    print("No demo accounts were created. Next: create-admin.")


def cmd_migrate(a):
    engine = db_module.get_engine()
    pending = migrations.pending(engine)
    if a.check:
        print("Pending migrations: " + (", ".join(f"{v} {n}" for v, n in pending) if pending else "none"))
        return 1 if pending else 0
    ran = migrations.apply(engine)
    print("Applied: " + (", ".join(f"{v} {n}" for v, n in ran) if ran else "nothing to do"))
    return 0


def cmd_create_admin(a):
    from auth import users
    db_module.ensure_schema(db_module.get_engine())
    users.create_user(a.email, _password("New admin password"), a.name or a.email, role=a.role)
    print(f"Created {a.role} {a.email}.")


def cmd_bootstrap(_a):
    """Idempotent first-run admin for containers: creates the admin named by
    QUANTA_BOOTSTRAP_ADMIN_EMAIL (password from QUANTA_ADMIN_PASSWORD) only when no admin exists."""
    from auth import users
    db_module.ensure_schema(db_module.get_engine())
    if any(u["role"] == "admin" for u in users.list_users()):
        print("An administrator already exists; nothing to do.")
        return
    email, pw = os.environ.get("QUANTA_BOOTSTRAP_ADMIN_EMAIL", "").strip(), os.environ.get("QUANTA_ADMIN_PASSWORD", "")
    if not email or not pw:
        print("No administrator yet. Set QUANTA_BOOTSTRAP_ADMIN_EMAIL and QUANTA_ADMIN_PASSWORD, or run create-admin.")
        return
    users.create_user(email, pw, os.environ.get("QUANTA_BOOTSTRAP_ADMIN_NAME", email), role="admin")
    print(f"Created the first administrator {email}. Change the password after signing in.")


def is_sample_dataset(path=None):
    """True only for the sample findings that ship with the repository (recognised by its
    first record), never for data pulled from a real source."""
    path = Path(path or FINDINGS)
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    first = data[0] if data else {}
    return first.get("id") == "FIND-1" and first.get("source_ref") == "57608" and (first.get("asset") or {}).get("name") == "WIN-DC01"


def cmd_clear_sample_data(a):
    """Starts a production deployment empty: moves the bundled sample findings, sample
    playbooks and sample plan aside (kept under remediation/.sample-backup) so real data is
    never mixed with demo data. A no-op when the findings are not the shipped sample."""
    if not is_sample_dataset():
        print("No bundled sample data found (or the findings are real); nothing to clear.")
        return
    if not a.yes:
        raise SystemExit("This moves the bundled sample findings, playbooks and plan aside. Re-run with --yes.")
    backup = SAMPLE_BACKUP
    backup.mkdir(parents=True, exist_ok=True)
    moved = []
    for f in [FINDINGS, *sorted(FINDINGS.parent.glob("FIND-*.yml")), PLAN_FILE]:
        if f.exists():
            shutil.move(str(f), str(backup / f.name))
            moved.append(f.name)
    FINDINGS.write_text("[]", encoding="utf-8")
    print(f"Moved {len(moved)} sample file(s) to {backup}. The queue now starts empty.")


def cmd_reset_password(a):
    from auth import users
    users.set_password(a.email, _password("New password"))
    print(f"Password reset for {a.email}.")


def cmd_list_users(_a):
    from auth import users
    for u in users.list_users():
        print(f"{u['email']:40} {u['role']:6} team={u.get('team') or '-'}")


def run_checks():
    """[(level, name, detail)] where level is PASS / WARN / FAIL."""
    out = []

    def add(level, name, detail):
        out.append((level, name, detail))
    prod = _flag("QUANTA_PRODUCTION")
    add("PASS" if prod else "WARN", "production mode", "QUANTA_PRODUCTION is on" if prod else "off: reads are public, demo behaviour. Set QUANTA_PRODUCTION=true")
    add("PASS" if os.environ.get("QUANTA_SESSION_SECRET") else "FAIL", "session secret",
        "set" if os.environ.get("QUANTA_SESSION_SECRET") else "QUANTA_SESSION_SECRET is not set: every restart signs everyone out")
    if prod and _flag("QUANTA_ALLOW_PUBLIC_READS"):
        add("WARN", "public reads", "QUANTA_ALLOW_PUBLIC_READS is on: anyone who can reach the app can read findings")
    keys = crypto._keys()
    if not keys:
        add("WARN", "credential encryption", "QUANTA_ENCRYPTION_KEY not set: stored connections are disabled")
    else:
        add("PASS" if crypto.available() else "FAIL", "credential encryption", f"{len(keys)} key(s) configured" if crypto.available() else "QUANTA_ENCRYPTION_KEY is not a valid key")
    try:
        engine = db_module.get_engine()
        db_module.ensure_schema(engine)
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
        add("PASS", "database", mask_url(db_module.database_url()))
        pend = migrations.pending(engine)
        add("PASS" if not pend else "WARN", "migrations", "up to date" if not pend else f"{len(pend)} pending: run migrate")
        from auth import users
        demo = [e for e in DEMO_ACCOUNTS if users.verify_login(e, DEMO_PASSWORD)]
        add("FAIL" if demo else "PASS", "demo accounts", f"still have the published password: {', '.join(demo)}" if demo else "none with the published password")
        admins = [u for u in users.list_users() if u["role"] == "admin"]
        add("PASS" if admins else "FAIL", "administrators", f"{len(admins)} admin account(s)" if admins else "no admin yet: run create-admin")
        if db_module.database_url().startswith("sqlite") and prod:
            add("WARN", "database engine", "SQLite is fine for a single host; use PostgreSQL (QUANTA_DATABASE_URL) for anything larger")
    except Exception as exc:  # noqa: BLE001
        add("FAIL", "database", f"{type(exc).__name__}: {exc}")
    if is_sample_dataset():
        add("WARN" if not prod else "FAIL", "findings data", "this is the bundled SAMPLE data, not yours: run clear-sample-data --yes, then add a connection")
    else:
        add("PASS" if FINDINGS.exists() else "WARN", "findings data", "present" if FINDINGS.exists() else "none yet: add a connection on the Connections page")
    smtp = all(os.environ.get(v) for v in ("SMTP_HOST", "SMTP_PORT", "SMTP_FROM_ADDRESS"))
    add("PASS" if smtp else "WARN", "email (SMTP)", "configured" if smtp else "not configured: scheduled reports, alerts and SLA emails are recorded but not sent")
    add("PASS" if shutil.which("claude") else "WARN", "Claude Code CLI",
        "found" if shutil.which("claude") else "not found: AI fixers (playbooks, upgrade plans) and AI Assist are unavailable; everything else works")
    add("PASS" if os.environ.get("QUANTA_METRICS_TOKEN") else "WARN", "metrics", "enabled" if os.environ.get("QUANTA_METRICS_TOKEN") else "off (set QUANTA_METRICS_TOKEN to expose /metrics)")
    return out


def cmd_check(_a):
    results = run_checks()
    width = max(len(n) for _, n, _ in results)
    for level, name, detail in results:
        print(f"[{level}] {name:<{width}}  {detail}")
    fails = [r for r in results if r[0] == "FAIL"]
    print(f"\n{len(fails)} failure(s), {sum(1 for r in results if r[0] == 'WARN')} warning(s).")
    return 1 if fails else 0


def _sqlite_path():
    url = make_url(db_module.database_url())
    return Path(url.database) if url.drivername.startswith("sqlite") and url.database not in (None, ":memory:") else None


def cmd_backup(a):
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = out_dir / f"quanta-backup-{stamp}.zip"
    manifest = {"created": stamp, "database": mask_url(db_module.database_url()), "files": []}
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        sqlite_file = _sqlite_path()
        if sqlite_file:
            snap = Path(tmp) / "quanta.db"
            src, dst = sqlite3.connect(sqlite_file), sqlite3.connect(snap)
            with dst:
                src.backup(dst)  # a consistent copy even while the app is writing
            src.close()
            dst.close()
            z.write(snap, "database/quanta.db")
            manifest["files"].append("database/quanta.db")
        elif db_module.database_url().startswith("postgresql"):
            if not shutil.which("pg_dump"):
                raise SystemExit("pg_dump not found on PATH: install the PostgreSQL client tools, or back the database up with your platform's tooling.")
            dump = Path(tmp) / "quanta.sql"
            subprocess.run(["pg_dump", "--no-owner", "--format=plain", "--file", str(dump), db_module.database_url().replace("+psycopg2", "")], check=True)
            z.write(dump, "database/quanta.sql")
            manifest["files"].append("database/quanta.sql")
        else:
            raise SystemExit("Unsupported database for backup; back it up with your platform's tooling.")
        if FINDINGS.exists():
            z.write(FINDINGS, "data/normalized-findings.json")
            manifest["files"].append("data/normalized-findings.json")
        for f in sorted(CONFIG_DIR.glob("*.yaml")):
            z.write(f, f"config/{f.name}")
            manifest["files"].append(f"config/{f.name}")
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
    print(f"Backup written: {target}")
    print("It contains your findings, tickets and users but NOT QUANTA_ENCRYPTION_KEY: store that key separately, or stored credentials cannot be restored.")


def cmd_restore(a):
    if not a.yes:
        raise SystemExit("Restore overwrites the current database and findings. Stop the app, then re-run with --yes.")
    sqlite_file = _sqlite_path()
    with zipfile.ZipFile(a.source) as z:
        names = set(z.namelist())
        if "database/quanta.db" in names:
            if not sqlite_file:
                raise SystemExit("This backup is a SQLite file but the configured database is not SQLite.")
            if sqlite_file.exists():
                shutil.copy2(sqlite_file, sqlite_file.with_name(sqlite_file.name + ".pre-restore"))
            sqlite_file.write_bytes(z.read("database/quanta.db"))
            print(f"Database restored to {sqlite_file} (previous copy kept as .pre-restore).")
        elif "database/quanta.sql" in names:
            print("This is a PostgreSQL dump. Restore it with: psql \"$QUANTA_DATABASE_URL\" < quanta.sql (extracted below).")
            Path("quanta-restore.sql").write_bytes(z.read("database/quanta.sql"))
        if "data/normalized-findings.json" in names:
            FINDINGS.parent.mkdir(parents=True, exist_ok=True)
            FINDINGS.write_bytes(z.read("data/normalized-findings.json"))
            print("Findings restored.")
        for n in sorted(x for x in names if x.startswith("config/")):
            (CONFIG_DIR / Path(n).name).write_bytes(z.read(n))
        print("Config restored. Start the app and run: check")


def cmd_rotate_keys(_a):
    engine = db_module.get_engine()
    db_module.ensure_schema(engine)
    t = db_module.connections
    n = 0
    with engine.begin() as conn:
        for row in conn.execute(select(t.c.id, t.c.secrets_blob)).mappings().all():
            if row["secrets_blob"]:
                conn.execute(update(t).where(t.c.id == row["id"]).values(secrets_blob=crypto.rotate(row["secrets_blob"])))
                n += 1
    print(f"Re-encrypted {n} connection(s) under the newest key. You can now remove the old key from QUANTA_ENCRYPTION_KEY.")


def cmd_prepare(_a):
    """First-run work for a deployment with several replicas: create the schema, set sample data
    aside and create the first admin, exactly once. Every replica's init container runs this; a
    database lease makes the others wait for the first to finish, and each step is idempotent."""
    from remediation.coordination import leases
    from remediation.utils import file_sync
    with leases.lease_lock("prepare", ttl=600, timeout=900):
        cmd_init(None)
        file_sync.sync_if_enabled(force=True)   # QUANTA_FILES_BACKEND=db: seed or pull the working files first
        if os.environ.get("QUANTA_PRODUCTION", "").strip().lower() in ("1", "true", "yes") and os.environ.get("QUANTA_KEEP_SAMPLE_DATA") != "true":
            cmd_clear_sample_data(argparse.Namespace(yes=True))
        file_sync.sync_if_enabled(force=True)   # publish the cleared state
        cmd_bootstrap(None)
    return 0


def cmd_scan_pipelines(a):
    """Checks CI/CD pipeline files (GitHub Actions, GitLab CI, Jenkinsfile) under PATH and prints the result as SARIF
    (default) or JSON, so a CI job can upload it with an API key. Exit status 1 when anything at or above --fail-on is found."""
    from remediation.scanners import cicd
    findings, files = cicd.scan_path(a.path)
    out = json.dumps(cicd.to_sarif(findings) if a.format == "sarif" else findings, indent=2)
    if a.out:
        Path(a.out).write_text(out, encoding="utf-8")
        print(f"{files} pipeline file(s) scanned, {len(findings)} finding(s) written to {a.out}")
    else:
        print(out)
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    return 1 if a.fail_on and any(rank[f["severity"]] >= rank[a.fail_on] for f in findings) else 0


def cmd_import_sarif(a):
    from remediation.ingest import merge, sarif
    findings, skipped = sarif.parse(Path(a.file).read_text(encoding="utf-8"), a.source, scan_type=a.scan_type, asset=a.asset)
    print(json.dumps({"parsed": len(findings), "skipped": skipped, **merge.merge(findings, a.source, reconcile=a.reconcile)}))
    return 0


def cmd_import_coverage(a):
    from remediation.ingest import coverage, merge
    findings, summary = coverage.analyse(Path(a.file).read_text(encoding="utf-8"), a.format, a.threshold, a.source, a.asset)
    print(json.dumps({"coverage": summary, **merge.merge(findings, a.source, reconcile=True)}))
    return 0


def cmd_seed_appsec_demo(a):
    from remediation.appsec import demo
    if a.remove:
        print(json.dumps(demo.remove(a.name)))
        return 0
    out = demo.seed(a.name, actor="quanta-admin")
    snippet = out.pop("topology_snippet")
    print(json.dumps(out))
    print()
    print("To make the graph show a path from the internet, add this to remediation/config/network_topology.yaml (replacing `assets: []`):")
    print()
    print(snippet)
    return 0


def cmd_seed_demo(a):
    """Demonstration data through the real connector code (recorded vendor-format responses replayed through each connector, then merged and stored like live data)."""
    from remediation.simulation import service
    try:
        if a.remove:
            print("Removing the simulation connections and every record marked source_mode=simulation (live records are untouched).")
            print(json.dumps(service.remove("quanta-admin")))
            return 0
        print("Loading demonstration data: one simulation connection per available connector, each run through the normal sync path.")
        print(json.dumps(service.plan()))
        out = service.load("quanta-admin")
    except service.SimulationNotAllowed as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    for r in out["results"]:
        print(f"  {r['name']}: {'ok' if r['ok'] else 'FAILED'}  {r['message']}")
    return 0 if all(r["ok"] for r in out["results"]) else 1


def cmd_integrity_manifest(a):
    from remediation.integrity import manifest
    path, data = manifest.write(REPO_ROOT, path=a.out)
    n = sum(1 for m in data["files"].values() if m["kind"] == "policy")
    print(f"Wrote {path}: {len(data['files'])} files ({len(data['files']) - n} code, {n} policy).")
    return 0


def cmd_check_integrity(a):
    from remediation.integrity import heal, service
    report = service.full_report()
    m = report["manifest"]
    print(f"Code baseline: {m['state']}  {m['message']}")
    for kind in ("modified", "missing", "unexpected"):
        for rel in m["code"][kind]:
            print(f"  code {kind}: {rel}")
    for kind in ("modified", "missing", "unexpected"):
        for rel in m["policy"][kind]:
            who = m["policy"]["editors"].get(rel)
            print(f"  policy {kind} (expected to change): {rel}" + (f"  by {who['actor']} ({who['action']}, {who['at']})" if who else ""))
    print()
    tag = {"ok": "PASS", "info": "INFO", "warn": "WARN", "fail": "FAIL"}
    for c in report["checks"]:
        print(f"[{tag[c['level']]}] {c['title']}: {c['detail']}" + (f"  (fix: {c['fix']})" if c.get("fix") else ""))
        if c.get("manual") and c["level"] in ("warn", "fail"):
            print(f"       manual: {c['manual']}")
    rc = 1 if report["counts"]["fail"] or m["state"] == "code-modified" else 0
    if a.heal:
        print()
        out = heal.run(confirm=bool(a.confirm), actor="cli")
        print("Repairs applied:" if a.confirm else "Repairs previewed (add --confirm to apply):")
        for r in out["results"]:
            print(f"  {r['action']}: {r['status']}" + (f" - {json.dumps(r['planned'])[:300]}" if r["planned"] else ""))
        for mm in out["manual"]:
            print(f"  manual: {mm['title']}: {mm['manual']}")
        print(f"After: {out['after']['status']}")
    elif a.confirm:
        print("--confirm has no effect without --heal.", file=sys.stderr)
    return rc


def cmd_worker(_a):
    from remediation.coordination import worker
    worker.main()
    return 0


def cmd_jobs(_a):
    from remediation.coordination import jobs
    s = jobs.stats()
    print("Jobs: " + ", ".join(f"{k} {v}" for k, v in s.items()))
    for j in jobs.recent(10):
        print(f"  #{j['id']} {j['kind']} {j['status']} attempts={j['attempts']}" + (f"  error: {j['error']}" if j["error"] else ""))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="quanta-admin", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    for name, fn in (("gen-key", cmd_gen_key), ("gen-secret", cmd_gen_secret), ("init", cmd_init), ("bootstrap", cmd_bootstrap), ("list-users", cmd_list_users),
                     ("check", cmd_check), ("rotate-keys", cmd_rotate_keys), ("worker", cmd_worker), ("jobs", cmd_jobs), ("prepare", cmd_prepare)):
        sub.add_parser(name).set_defaults(fn=fn)
    cs = sub.add_parser("clear-sample-data")
    cs.add_argument("--yes", action="store_true")
    cs.set_defaults(fn=cmd_clear_sample_data)
    m = sub.add_parser("migrate")
    m.add_argument("--check", action="store_true")
    m.set_defaults(fn=cmd_migrate)
    c = sub.add_parser("create-admin")
    c.add_argument("--email", required=True)
    c.add_argument("--name")
    c.add_argument("--role", default="admin", choices=["admin", "user"])
    c.set_defaults(fn=cmd_create_admin)
    r = sub.add_parser("reset-password")
    r.add_argument("--email", required=True)
    r.set_defaults(fn=cmd_reset_password)
    b = sub.add_parser("backup")
    b.add_argument("--out", default="./backups")
    b.set_defaults(fn=cmd_backup)
    sp = sub.add_parser("scan-pipelines")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--format", choices=["sarif", "json"], default="sarif")
    sp.add_argument("--out")
    sp.add_argument("--fail-on", choices=["Critical", "High", "Medium", "Low"])
    sp.set_defaults(fn=cmd_scan_pipelines)
    isr = sub.add_parser("import-sarif")
    isr.add_argument("file")
    isr.add_argument("--source", required=True)
    isr.add_argument("--scan-type")
    isr.add_argument("--asset")
    isr.add_argument("--reconcile", action="store_true")
    isr.set_defaults(fn=cmd_import_sarif)
    icv = sub.add_parser("import-coverage")
    icv.add_argument("file")
    icv.add_argument("--source", default="coverage")
    icv.add_argument("--asset")
    icv.add_argument("--format")
    icv.add_argument("--threshold", type=float, default=60.0)
    icv.set_defaults(fn=cmd_import_coverage)
    sd = sub.add_parser("seed-appsec-demo", help="register a demo application with its SBOM and a few findings (source appsec-demo); --remove undoes it")
    sd.add_argument("--name", default="orders-service")
    sd.add_argument("--remove", action="store_true")
    sd.set_defaults(fn=cmd_seed_appsec_demo)
    sdm = sub.add_parser("seed-demo", help="load demonstration data by replaying recorded vendor responses through the real connectors; --remove undoes it")
    sdm.add_argument("--remove", action="store_true")
    sdm.set_defaults(fn=cmd_seed_demo)
    im = sub.add_parser("integrity-manifest", help="write the SHA-256 baseline of the application's code and shipped config (run at build time)")
    im.add_argument("--out", default=None, help="manifest path (default remediation/integrity/manifest.json, or QUANTA_INTEGRITY_MANIFEST)")
    im.set_defaults(fn=cmd_integrity_manifest)
    ci = sub.add_parser("check-integrity", help="compare the code with its baseline and run store consistency checks; --heal previews safe repairs, --heal --confirm applies them")
    ci.add_argument("--heal", action="store_true")
    ci.add_argument("--confirm", action="store_true")
    ci.set_defaults(fn=cmd_check_integrity)
    s = sub.add_parser("restore")
    s.add_argument("--from", dest="source", required=True)
    s.add_argument("--yes", action="store_true")
    s.set_defaults(fn=cmd_restore)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
