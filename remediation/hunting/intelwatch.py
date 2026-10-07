"""
The threat-intelligence report watcher: polls the report sources an administrator added (public RSS/Atom/JSON feeds and TAXII 2.1 collections), stores each new report
once, and turns the relevant ones into hunts.

For every new item:
  1. dedupe: the same (source, external id) is never read twice, and the same content hash (the existing unique key on stored reports) is never stored twice, even
     if two sources carry the same report;
  2. extract and score it with the existing code (remediation/hunting/intel.py: CVEs, ATT&CK techniques, actors, indicators; relevance to THIS estate, 0-100);
  3. when its priority reaches `hunting.auto_create_hunt_at_or_above` (soc_triage.yaml), create the hunt (the same function the manual "start a hunt" button uses) and
     refresh the hunt engine so the report also appears as a suggestion; below that, the report is stored and shown, nothing more;
  4. record WHY: the score, the threshold, the reasons and what matched the estate, on the report ("why this triggered"), together with the decision taken.

The watcher never runs a search. A hunt it creates is an ordinary proposed hunt: a person accepts it and confirms any run in the SIEM, as for every other hunt.
The report's time-to-report clock starts at its arrival (its published date when the source gave one, else when Quanta fetched it): see service.clock_start_for.

Everything outside this module that the watcher needs is passed in (`Deps`), so it runs the same in the dashboard, the CLI and the tests, and a poll never needs
a request context.
"""
import datetime
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from remediation.hunting import intel, service

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "intel_watch.yaml"
PRIORITY_RANK = {"low": 0, "medium": 1, "high": 2}


def config(path=None):
    with open(path or CONFIG_PATH, encoding="utf-8") as fh:
        c = yaml.safe_load(fh) or {}
    return {"interval_minutes": int(c.get("interval_minutes", 60)), "max_items_per_poll": int(c.get("max_items_per_poll", 50)),
            "max_new_reports_per_poll": int(c.get("max_new_reports_per_poll", 25)), "max_bytes": int(c.get("max_bytes", 2_000_000))}


def enabled():
    """The scheduled polling switch: QUANTA_INTEL_WATCH=false turns it off (default on, but with no source added there is nothing to poll)."""
    return os.environ.get("QUANTA_INTEL_WATCH", "true").strip().lower() not in ("0", "false", "no", "off")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Deps:
    findings: Callable[[], list]                     # the live queue the relevance score is computed against
    make_hunt: Callable[[dict, str], dict]           # (stored report, actor) -> hunt; raises ValueError when there is nothing to hunt
    refresh_engine: Callable[[list], dict] = None    # hunt-engine refresh(findings); optional
    hunt_floor: Callable[[], str] = lambda: "high"   # hunting.auto_create_hunt_at_or_above
    build_feed: Callable = None                      # (source) -> ReportFeedConnector
    build_taxii: Callable = None                     # (source) -> (TaxiiConnector)
    engine: object = None


def _decide(rec, floor, hunt_id_before):
    """'created' | 'below-threshold' | 'no-threshold' | 'exists'."""
    if hunt_id_before:
        return "exists"
    if floor not in PRIORITY_RANK:
        return "no-threshold"
    return "created" if PRIORITY_RANK[rec["priority"]] >= PRIORITY_RANK[floor] else "below-threshold"


def trigger_record(rec, matches, floor, decision, source_name, extra=None):
    """The "why this triggered" record kept on the report."""
    why = {"decision": decision, "priority": rec["priority"], "relevance": rec["relevance"], "threshold": floor or None, "reasons": list(rec.get("reasons") or []),
           "matched_hosts": sorted((matches or {}).get("hosts") or [])[:20], "matched_cves": sorted((matches or {}).get("cves") or [])[:20], "source": source_name, **(extra or {})}
    why["text"] = {"created": f"Relevance {rec['relevance']} ({rec['priority']}) reached the '{floor}' threshold, so a hunt was created. ",
                   "below-threshold": f"Relevance {rec['relevance']} ({rec['priority']}) is below the '{floor}' threshold; the report is stored and no hunt was created. ",
                   "no-threshold": "No hunt threshold is configured; the report is stored only. ",
                   "exists": "A hunt already exists for this report. "}[decision] + ("; ".join(why["reasons"][:3]) or "No match with the estate was found.")
    return why


def ingest_item(item, source, deps, actor="report-watcher"):
    """Stores one item as a report and applies the hunt rule. Returns {created, report_id, decision, hunt_id}; a repeat returns created False and changes nothing."""
    ext = item.get("external_id") or ""
    if ext and service.intel_seen(source["id"], ext, deps.engine):
        return {"created": False, "report_id": None, "decision": "seen", "hunt_id": None}
    content = f"{item.get('title') or ''}\n{item.get('content') or ''}".strip()
    if not content:
        return {"created": False, "report_id": None, "decision": "empty", "hunt_id": None}
    findings = deps.findings()
    ex = intel.extract(item["content"] if str(item.get("content") or "").lstrip().startswith("{") else content)
    if item.get("title") and (not ex.get("title") or ex.get("format") == "text"):
        ex["title"] = item["title"][:160]
    score, prio, reasons, matches = intel.relevance(ex, findings)
    rid, created = service.save_intel(ex["title"] or item.get("title") or "Untitled report", f"watcher:{source['name']}", intel.content_hash(content), ex, score, prio, reasons, actor, deps.engine,
                                      published_at=item.get("published_at"), source_id=source["id"], external_id=ext, url=item.get("url"))
    if not created:
        return {"created": False, "report_id": rid, "decision": "duplicate", "hunt_id": None}
    rec = service.get_intel(rid, deps.engine)
    floor = (deps.hunt_floor() or "").lower()
    decision = _decide(rec, floor, rec.get("hunt_id"))
    hunt_id, extra = None, {}
    if decision == "created":
        try:
            hunt_id = deps.make_hunt(rec, actor)["id"]
        except ValueError as exc:
            decision, extra = "exists", {"note": f"No hunt was created: {str(exc)[:160]}"}
    service.set_intel_trigger(rid, trigger_record(rec, matches, floor, decision, source["name"], extra), deps.engine)
    return {"created": True, "report_id": rid, "decision": decision, "hunt_id": hunt_id}


def _items(source, deps, cfg):
    """-> (items, state updates). Raises on a source error (the caller records it)."""
    if source["kind"] == "feed":
        r = deps.build_feed(source).fetch(source.get("etag"), source.get("last_modified"))
        return r["items"], {"etag": r.get("etag"), "last_modified": r.get("last_modified")}, r["status"]
    c = deps.build_taxii(source)
    r = c.poll(source["collection_id"], source.get("added_after"), limit=min(cfg["max_items_per_poll"], 200))
    return r["items"], {"added_after": r.get("added_after")}, "ok"


def poll_source(source, deps, cfg=None, actor="report-watcher", now=None):
    """Polls one source now. Never raises: a failure is recorded on the source (last_status 'error', last_error) and returned."""
    cfg = cfg or config()
    now = now or _now()
    out = {"source_id": source["id"], "name": source["name"], "status": "ok", "error": None, "new": 0, "seen": 0, "hunts_created": 0, "reports": []}
    try:
        items, state, status = _items(source, deps, cfg)
        out["status"] = status
        fresh = []
        for it in items[: cfg["max_items_per_poll"]]:
            if len(fresh) >= cfg["max_new_reports_per_poll"]:
                break
            r = ingest_item(it, source, deps, actor)
            if r["created"]:
                fresh.append(r)
            else:
                out["seen"] += 1
        out["new"] = len(fresh)
        out["hunts_created"] = sum(1 for r in fresh if r["hunt_id"])
        out["reports"] = [{"report_id": r["report_id"], "decision": r["decision"], "hunt_id": r["hunt_id"]} for r in fresh]
        if out["hunts_created"] and deps.refresh_engine:
            try:
                deps.refresh_engine(deps.findings())
            except Exception as exc:  # noqa: BLE001 - the hunts exist; a failed suggestion refresh is reported, not fatal
                out["engine_refresh_error"] = str(exc)[:160]
        service.update_source(source["id"], {**{k: v for k, v in state.items() if v}, "last_poll_at": _iso(now), "last_status": status, "last_error": None, "last_new": out["new"],
                                              "total_reports": int(source.get("total_reports") or 0) + out["new"]}, deps.engine)
    except Exception as exc:  # noqa: BLE001 - one bad source must not stop the others
        out.update(status="error", error=_safe_error(exc))
        service.update_source(source["id"], {"last_poll_at": _iso(now), "last_status": "error", "last_error": out["error"], "last_new": 0}, deps.engine)
    return out


def _safe_error(exc):
    return f"{type(exc).__name__}: {str(exc)[:200]}"


def due(source, cfg, now):
    if not source["enabled"]:
        return False
    if not source.get("last_poll_at"):
        return True
    last = datetime.datetime.strptime(source["last_poll_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    return now - last >= datetime.timedelta(minutes=cfg["interval_minutes"])


def poll_due(deps, now=None, cfg=None, force=False):
    """The leader tick: polls every enabled source that is due. Does nothing when QUANTA_INTEL_WATCH=false (unless `force`) or when no source exists."""
    if not (force or enabled()):
        return {"skipped": "QUANTA_INTEL_WATCH is off", "polled": []}
    cfg, now = cfg or config(), now or _now()
    sources = [s for s in service.list_sources(deps.engine) if s["enabled"] and (force or due(s, cfg, now))]
    return {"skipped": None, "polled": [poll_source(s, deps, cfg, now=now) for s in sources]}
