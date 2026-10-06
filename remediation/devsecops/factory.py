"""
The remediation queue for code-level findings (static analysis, dependencies, secrets, infrastructure as code, containers).

A finding is queued, worked by a developer or by the repository's own fix tooling, and tracked until a later scan no longer reports it. Quanta
does not edit repositories or open pull requests: for each queued finding it produces a fix brief (what, where, why, the steps and how to verify) that
a developer or the `vuln-fixer` subagent can act on, and it records the state a person reports (queued, in progress, pull request opened, merged).

"Verified" is not something a person claims: a finding that is no longer in the current findings has been resolved in the latest scan, and the queue
shows that automatically. A merged fix whose finding is still reported is shown as such, because that is the result worth knowing.
"""
import datetime

from sqlalchemy import insert, select, update

from remediation.guidance import engine as guidance
from remediation.utils import db as db_module

CODE_TYPES = ("sast", "sca", "secrets", "iac", "container")
STATES = ("queued", "in-progress", "pr-opened", "merged", "wont-fix")
SEV = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def is_code(f):
    return f.get("scan_type") in CODE_TYPES


def _stored(engine):
    t = db_module.remediation_factory
    with engine.connect() as conn:
        return {r["finding_id"]: dict(r) for r in conn.execute(select(t)).mappings().all()}


def queue(finding_ids, findings, actor, engine=None):
    engine, t = _engine(engine), db_module.remediation_factory
    by_id = {f["id"]: f for f in findings}
    have = _stored(engine)
    added, skipped = [], []
    with engine.begin() as conn:
        for fid in finding_ids[:500]:
            f = by_id.get(fid)
            if not f or not is_code(f):
                skipped.append({"id": fid, "reason": "not a code-level finding in the current queue"})
            elif fid in have:
                skipped.append({"id": fid, "reason": "already queued"})
            else:
                conn.execute(insert(t), {"finding_id": fid, "state": "queued", "assignee": None, "pr_url": None, "notes": "", "queued_by": actor, "queued_at": _now(), "updated_at": _now()})
                added.append(fid)
    return {"queued": added, "skipped": skipped}


def update_item(finding_id, fields, engine=None):
    engine, t = _engine(engine), db_module.remediation_factory
    if _stored(engine).get(finding_id) is None:
        raise KeyError("That finding is not in the queue")
    vals = {"updated_at": _now()}
    if fields.get("state") is not None:
        if fields["state"] not in STATES:
            raise ValueError(f"state must be one of {', '.join(STATES)}")
        vals["state"] = fields["state"]
    if fields.get("pr_url") is not None:
        url = fields["pr_url"].strip()
        if url and not url.lower().startswith(("https://", "http://")):
            raise ValueError("The pull request link must start with https://")
        vals["pr_url"] = url[:500] or None
    for k in ("assignee", "notes"):
        if fields.get(k) is not None:
            vals[k] = fields[k][:500]
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.finding_id == finding_id).values(**vals))
    return _stored(engine)[finding_id]


def items(findings, engine=None):
    engine = _engine(engine)
    by_id = {f["id"]: f for f in findings}
    out = []
    for fid, row in _stored(engine).items():
        f = by_id.get(fid)
        if f is None:
            shown = "resolved-in-latest-scan"
        elif row["state"] == "merged":
            shown = "merged-still-reported"
        else:
            shown = row["state"]
        out.append({**row, "shown_state": shown, "title": f.get("title") if f else None, "severity": f.get("severity") if f else None, "repository": (f.get("asset") or {}).get("name") if f else None,
                    "scan_type": f.get("scan_type") if f else None, "location": f.get("location") if f else None})
    out.sort(key=lambda r: (r["shown_state"] == "resolved-in-latest-scan", SEV.get(r["severity"], 9), r["finding_id"]))
    return out


def candidates(findings, engine=None, limit=200):
    engine = _engine(engine)
    have = set(_stored(engine))
    c = [f for f in findings if is_code(f) and f["id"] not in have and f.get("status") not in ("resolved", "closed")]
    c.sort(key=lambda f: (SEV.get(f.get("severity"), 9), 0 if (f.get("kev") or {}).get("listed") else 1, f["id"]))
    return [{"id": f["id"], "title": f["title"], "severity": f["severity"], "repository": (f.get("asset") or {}).get("name"), "scan_type": f.get("scan_type"),
             "location": f.get("location"), "kev": bool((f.get("kev") or {}).get("listed"))} for f in c[:limit]]


def summary(findings, engine=None):
    its = items(findings, engine)
    counts = {}
    for i in its:
        counts[i["shown_state"]] = counts.get(i["shown_state"], 0) + 1
    return {"queued_total": len(its), "by_state": counts, "candidates": len(candidates(findings, engine, limit=10**6))}


def brief(finding):
    """A markdown brief a developer (or the repository's own fix tooling) can act on."""
    g = guidance.build(finding, client_controls=False)
    loc = finding.get("location")
    where = f"{loc}" if isinstance(loc, str) else (f"{loc.get('file')}:{loc.get('line')}" if isinstance(loc, dict) and loc.get("file") else "see the finding")
    L = [f"# Fix: {finding['title']}", "", f"- Repository / asset: {(finding.get('asset') or {}).get('name', 'unknown')}", f"- Finding: {finding['id']} ({finding.get('scan_type')}), severity {finding['severity']}",
         f"- Where: {where}"]
    if finding.get("cve"):
        L.append(f"- CVE: {finding['cve']}" + (" (CISA known-exploited)" if (finding.get("kev") or {}).get("listed") else ""))
    if finding.get("rule_id"):
        L.append(f"- Rule: {finding['rule_id']}" + (f", {', '.join(finding['cwe'])}" if finding.get("cwe") else ""))
    dep = finding.get("dependency") or {}
    if dep.get("package"):
        L.append(f"- Package: {dep['package']} {dep.get('version', '')}" + (f", fixed in {dep['fixed_version']}" if dep.get("fixed_version") else ""))
    L += ["", "## Why it matters", g["why_it_matters"], "", "## What to do", *[f"{i}. {s}" for i, s in enumerate(g["steps"], 1)], "", "## Prove it is fixed", *[f"- {v}" for v in g["verify"]],
          "", f"Effort: {g['effort']}", "", "## When you are done", "Rescan. Quanta marks this finding resolved when the next scan no longer reports it; do not close it by hand.",
          "", "Generated by Quanta from curated guidance. It is a brief, not a patch: review any change before it is merged."]
    return "\n".join(L) + "\n"
