"""
A SHA-256 manifest of the application's own files, so a deployment can say whether the code it is running is the code that was released.

Two kinds of file are tracked:
  code    python, static JS/CSS/HTML, agent and command prompts, deploy files, non-config YAML. Must not change after the manifest is built.
  policy  remediation/config/*.yaml. Administrators edit these from the dashboard, so a change is EXPECTED: it is reported, never called tampering,
          and the activity log is searched for who changed it where it records that.

No manifest on disk means "no baseline", never "ok": nothing can be said about a deployment that has nothing to compare against.
This detects accidental drift and casual tampering. It is not a defence against an attacker who can also rewrite the manifest (sign it in your
release pipeline and keep a copy off the host for that).
"""
import datetime
import hashlib
import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_NAME = "manifest.json"
FORMAT_VERSION = 1

# directories never walked: caches, vendored/demo code, tests, docs and generated runtime output
_PRUNE = {".git", "__pycache__", "node_modules", ".venv", "venv", "tests", "vulnerable-demo-app", "vulnerable-demo-multilang", "docs", ".pytest_cache",
          "worktrees", "live-data", "output", "backups", "certs", "sample-data", ".sample-backup"}
_CODE_SUFFIXES = {".py", ".js", ".css", ".html", ".yml", ".yaml", ".sh", ".tpl", ".json"}
_ROOT_FILES = ("Dockerfile", "docker-compose.yml", "VERSION")
_AREAS = ("dashboard", "remediation", "cli", "scripts", "deploy", ".claude")   # top-level areas that count as the application
_NEVER = {"manifest.json", "users.json"}                                      # runtime data that lives inside an area
_NEVER_SUFFIX = (".pyc", ".lock", ".bak", ".db", ".tmp")


def manifest_path(root=None):
    env = os.environ.get("QUANTA_INTEGRITY_MANIFEST", "").strip()
    if env:
        return Path(env)
    return Path(root or REPO_ROOT) / "remediation" / "integrity" / MANIFEST_NAME


def classify(rel):
    """'policy' for admin-editable config, else 'code'."""
    parts = rel.split("/")
    if len(parts) == 3 and parts[:2] == ["remediation", "config"] and parts[2].endswith((".yaml", ".yml")):
        return "policy"
    return "code"


def _wanted(rel):
    name = rel.rsplit("/", 1)[-1]
    if name in _NEVER or name.endswith(_NEVER_SUFFIX):
        return False
    if "/" not in rel:
        return rel in _ROOT_FILES
    top = rel.split("/", 1)[0]
    if top == ".claude":
        return rel.startswith((".claude/agents/", ".claude/commands/")) and rel.endswith(".md")
    suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    return suffix in _CODE_SUFFIXES or top == "deploy"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(root=None):
    """{relative posix path: {sha256, size, kind}} for every tracked file currently on disk."""
    root = Path(root or REPO_ROOT)
    out = {}
    for area in ("",) + _AREAS:
        base = root / area if area else root
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            if area == "":
                dirnames[:] = []          # top level: only the named root files
            else:
                dirnames[:] = [d for d in dirnames if d not in _PRUNE]
            for fn in filenames:
                full = Path(dirpath) / fn
                rel = full.relative_to(root).as_posix()
                if not _wanted(rel):
                    continue
                try:
                    out[rel] = {"sha256": _sha256(full), "size": full.stat().st_size, "kind": classify(rel)}
                except OSError:
                    continue
    return out


def build(root=None, now=None):
    files = scan(root)
    version = ""
    try:
        version = (Path(root or REPO_ROOT) / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return {"format": FORMAT_VERSION, "generated_at": (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "quanta_version": version, "files": files}


def write(root=None, path=None, now=None):
    data = build(root, now)
    path = Path(path) if path else manifest_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    return path, data


def load(root=None, path=None):
    """The stored manifest, or None when there is none or it cannot be read."""
    p = Path(path) if path else manifest_path(root)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and isinstance(data.get("files"), dict) else None
    except (OSError, ValueError):
        return None


def _policy_editors(rels, activity):
    """Best effort: for each changed policy file, the newest activity-log entry that names it. Many policy saves are not logged, so absence means unknown."""
    out = {}
    for rel in rels:
        stem = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
        variants = {stem, stem.replace("_", "-"), stem.replace("_", " ")}
        for e in activity or []:                       # newest first
            hay = f"{e.get('action', '')} {e.get('target') or ''} {json.dumps(e.get('details') or {})}".lower()
            if any(v in hay for v in variants):
                out[rel] = {"actor": e.get("actor"), "action": e.get("action"), "at": e.get("timestamp")}
                break
    return out


def verify(root=None, manifest=None, activity=None):
    """Compare the files on disk with the baseline. `activity` is the activity log newest first (optional).

    state: 'no-baseline' | 'ok' (nothing differs) | 'policy-changed' (only admin-editable config differs, expected) | 'code-modified' (must not happen)."""
    if manifest is None:
        manifest = load(root)
    empty = {"modified": [], "missing": [], "unexpected": []}
    if manifest is None:
        return {"state": "no-baseline", "baseline": None, "files_checked": 0,
                "message": "No manifest has been built, so nothing can be compared. Run: python cli/quanta_admin.py integrity-manifest",
                "code": dict(empty), "policy": {**empty, "editors": {}}}
    base = manifest["files"]
    now = scan(root)
    code = {k: [] for k in empty}
    policy = {k: [] for k in empty}
    for rel, meta in base.items():
        bucket = policy if meta.get("kind") == "policy" else code
        cur = now.get(rel)
        if cur is None:
            bucket["missing"].append(rel)
        elif cur["sha256"] != meta.get("sha256"):
            bucket["modified"].append(rel)
    for rel, meta in now.items():
        if rel not in base:
            (policy if meta["kind"] == "policy" else code)["unexpected"].append(rel)
    for b in (code, policy):
        for k in empty:
            b[k].sort()
    policy["editors"] = _policy_editors(policy["modified"] + policy["unexpected"], activity)
    state = "code-modified" if any(code.values()) else ("policy-changed" if any(policy[k] for k in empty) else "ok")
    msg = {"ok": "Every tracked file matches the baseline.",
           "policy-changed": "Only administrator-editable policy files differ from the baseline, which is expected.",
           "code-modified": "Application code differs from the baseline. If you did not deploy a change, treat this as a possible tampering or a partial deploy."}[state]
    return {"state": state, "baseline": {"generated_at": manifest.get("generated_at"), "quanta_version": manifest.get("quanta_version"), "files": len(base)},
            "message": msg, "code": code, "policy": policy, "files_checked": len(now)}
