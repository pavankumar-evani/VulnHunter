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


def merge(new_findings, source, path=None, reconcile=False, source_mode=None):
    """Returns {added, updated, removed, total}. Nothing is written when there is no change.

    `source_mode` is the provenance of this pull: "live" or "simulation" (records carry it as `source_mode`; a record without it is live).
    A simulated pull never changes a live record that has the same identity (live wins; the count is returned as `kept_live`), a live pull
    that meets a simulated record replaces it with the real one, and `reconcile` only ever removes records of the same mode."""
    path = Path(path or DEFAULT_PATH)
    from remediation.utils import file_sync
    with FileLock(str(path), timeout=60.0):
        file_sync.sync_if_enabled(force=True)  # QUANTA_FILES_BACKEND=db: start from the cluster's latest copy
        existing = load(path)
        index = {key_of(f): i for i, f in enumerate(existing) if f.get("source") == source}
        run_mode = source_mode or "live"
        seen, added, updated, kept_live = set(), 0, 0, 0
        next_n = _next_number(existing)
        for n in new_findings:
            k = key_of({**n, "source": source})
            seen.add(k)
            if source_mode:
                n = {**n, "source_mode": source_mode}
            if k in index:
                cur = existing[index[k]]
                cur_mode = cur.get("source_mode") or "live"
                if run_mode == "simulation" and cur_mode != "simulation":
                    kept_live += 1
                    continue
                changed = False
                if cur_mode == "simulation" and run_mode != "simulation":
                    cur["source_mode"] = "live"
                    changed = True
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
                # a connector that normalises straight into the Finding schema (Prisma Cloud, Cortex XSIAM, CrowdStrike) leaves id None: number it here
                existing.append({**n, "id": n.get("id") or f"FIND-{next_n}", "source": source})
                if not n.get("id"):
                    next_n += 1
                added += 1
        removed = 0
        if reconcile:
            keep = [f for f in existing if f.get("source") != source or key_of(f) in seen or (f.get("source_mode") or "live") != run_mode]
            removed = len(existing) - len(keep)
            existing = keep
        if added or updated or removed:
            _atomic_write(path, existing)
            file_sync.sync_if_enabled(force=True)  # publish it to the other replicas before releasing the lock
        result = {"added": added, "updated": updated, "removed": removed, "total": len(existing)}
        if kept_live:
            result["kept_live"] = kept_live
        return result


def remove_simulated(path=None):
    """Removes every record whose source_mode is "simulation" (live records are never touched). Returns how many were removed."""
    path = Path(path or DEFAULT_PATH)
    from remediation.utils import file_sync
    with FileLock(str(path), timeout=60.0):
        file_sync.sync_if_enabled(force=True)
        existing = load(path)
        keep = [f for f in existing if f.get("source_mode") != "simulation"]
        removed = len(existing) - len(keep)
        if removed:
            _atomic_write(path, keep)
            file_sync.sync_if_enabled(force=True)
        return removed
