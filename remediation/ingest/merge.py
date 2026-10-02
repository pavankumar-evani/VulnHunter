"""
Merge freshly pulled findings into the system of record
(`remediation/output/normalized-findings.json`) without an agent session.

Identity: a finding is "the same finding" when source, asset name, source_ref (or title when
there is no ref) and CVE match. A re-seen finding keeps its id and first_seen and gets a new
last_seen (and refreshed severity/cvss/title/fix text); a new one gets the next FIND-N.

`reconcile=True` is for a source whose pull is a COMPLETE export of everything it knows:
findings of that source that were not seen this time are removed, which is how a fixed
vulnerability leaves the queue (and how closed-loop verification sees the fix). Never use it
for a partial pull. Every write is atomic (temp file + replace) under a lock, and the
previous version is kept as `normalized-findings.json.bak`.
"""
import json
import os
import re
import tempfile
from pathlib import Path

from remediation.utils.file_lock import FileLock

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "output" / "normalized-findings.json"
_NUM = re.compile(r"FIND-(\d+)$")
_REFRESH = ("severity", "cvss", "title", "description", "recommended_fix", "remediation_domain", "scan_type", "location", "cwe", "rule_id", "tool",
            "suggested_patch", "dependency")


def key_of(f):
    a = f.get("asset") or {}
    return (f.get("source"), (a.get("name") or "").lower(), str(f.get("source_ref") or f.get("title") or "").lower(), (f.get("cve") or "").upper())


def _next_number(findings):
    nums = [int(m.group(1)) for f in findings if (m := _NUM.match(f.get("id", "")))]
    return max(nums, default=0) + 1


def load(path=None):
    path = Path(path or DEFAULT_PATH)  # resolved at call time so the location can be redirected
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def _atomic_write(path, findings):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        (path.with_name(path.name + ".bak")).write_bytes(path.read_bytes())
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def merge(new_findings, source, path=None, reconcile=False):
    """Returns {added, updated, removed, total}. Nothing is written when there is no change."""
    path = Path(path or DEFAULT_PATH)
    from remediation.utils import file_sync
    with FileLock(str(path), timeout=60.0):
        file_sync.sync_if_enabled(force=True)  # QUANTA_FILES_BACKEND=db: start from the cluster's latest copy
        existing = load(path)
        index = {key_of(f): i for i, f in enumerate(existing) if f.get("source") == source}
        seen, added, updated = set(), 0, 0
        next_n = _next_number(existing)
        for n in new_findings:
            k = key_of({**n, "source": source})
            seen.add(k)
            if k in index:
                cur = existing[index[k]]
                changed = False
                if n.get("last_seen") and n["last_seen"] != cur.get("last_seen"):
                    cur["last_seen"] = n["last_seen"]
                    changed = True
                if n.get("first_seen") and cur.get("first_seen") and n["first_seen"] < cur["first_seen"]:
                    cur["first_seen"] = n["first_seen"]
                    changed = True
                for field in _REFRESH:
                    if n.get(field) not in (None, "") and n.get(field) != cur.get(field):
                        cur[field] = n[field]
                        changed = True
                updated += 1 if changed else 0
            else:
                existing.append({"id": f"FIND-{next_n}", **{**n, "source": source}})
                next_n += 1
                added += 1
        removed = 0
        if reconcile:
            keep = [f for f in existing if f.get("source") != source or key_of(f) in seen]
            removed = len(existing) - len(keep)
            existing = keep
        if added or updated or removed:
            _atomic_write(path, existing)
            file_sync.sync_if_enabled(force=True)  # publish it to the other replicas before releasing the lock
        return {"added": added, "updated": updated, "removed": removed, "total": len(existing)}
