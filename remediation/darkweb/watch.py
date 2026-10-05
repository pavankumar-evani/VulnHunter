"""
Dark Web Watch: match what is published about the world against YOUR names, and turn a match into a hit, an alert and, through the SOC queue, a case.

Inputs (see catalog.yaml for every source and how it is used):
  feeds     public ransomware leak-site lists, fetched on a schedule, matched locally against your watch terms;
  lookups   credential-exposure services asked about your own domains (counts, breach names, masked identifiers; never a password);
  imports   text, JSON or CSV produced by crawlers and monitoring platforms that analysts run in their own isolated environment.

Matching is deliberate and simple, and the reason for each hit is stored with it:
  domain    your domain equals the victim's website, or appears as a whole host name in the text;
  brand / vendor / keyword
            a whole-word, case-insensitive match; a term shorter than 4 characters must be the entire victim name, because short words match everything.
A vendor (a supplier or partner you list) is a supply-chain hit and rates one level lower than a hit on you.

A hit is stored once (a stable key per source, kind, term and subject), starts 'new', and is worked like any other lead: reviewing, actioned or dismissed with a note.
With auto-alerts on (watch settings), a new hit also creates a Quanta SOC alert from source 'darkweb', which flows into triage, cases and playbooks.
Quanta never visits a leak site and never stores a password.
"""
import datetime
import hashlib
import json
import re
from pathlib import Path

import yaml
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from remediation.hunting import ocsf, store as hunt_store
from remediation.utils import db as db_module

CATALOG_PATH = Path(__file__).with_name("catalog.yaml")
WATCH_PATH = Path(__file__).resolve().parents[1] / "config" / "darkweb_watch.yaml"
STATUSES = ("new", "reviewing", "actioned", "dismissed")
ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I)
MAX_IMPORT_CHARS = 400_000
SEV_DOWN = {"Critical": "High", "High": "Medium", "Medium": "Low", "Low": "Low", "Informational": "Informational"}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def catalog():
    with open(CATALOG_PATH, encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("sources") or []


def config():
    with open(WATCH_PATH, encoding="utf-8") as fh:
        c = yaml.safe_load(fh) or {}
    s = {"auto_alert": True, "ransomware_severity": "High", "credential_severity": "High", "credential_min_records": 1, "mention_severity": "Medium", "poll_minutes": 60,
         "lookup_hours": 24}
    s.update(c.get("settings") or {})
    return {"domains": [str(x).lower().strip() for x in c.get("domains") or [] if str(x).strip()], "brands": [str(x).strip() for x in c.get("brands") or [] if str(x).strip()],
            "vendors": [str(x).strip() for x in c.get("vendors") or [] if str(x).strip()], "keywords": [str(x).strip() for x in c.get("keywords") or [] if str(x).strip()], "settings": s}


def has_terms(cfg=None):
    cfg = cfg or config()
    return any(cfg[k] for k in ("domains", "brands", "vendors", "keywords"))


# ---------------------------------------------------------------- matching
def _word(term):
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])", re.I)


def match_text(text, website="", cfg=None):
    """-> [(kind, term)] for every watch term the text names."""
    cfg = cfg or config()
    text = text or ""
    low, site = text.lower(), (website or "").lower().strip()
    site = re.sub(r"^https?://", "", site).split("/")[0]
    found = []
    for d in cfg["domains"]:
        if site == d or site.endswith("." + d) or re.search(r"(?<![a-z0-9.-])" + re.escape(d) + r"(?![a-z0-9-])", low):
            found.append(("domain", d))
    for kind, key in (("brand", "brands"), ("vendor", "vendors"), ("keyword", "keywords")):
        for t in cfg[key]:
            if len(t) < 4:
                if low.strip() == t.lower():
                    found.append((kind, t))
            elif _word(t).search(text):
                found.append((kind, t))
    return found


RANK = {"domain": 0, "brand": 1, "vendor": 2, "keyword": 3}


def best_match(matches):
    """One subject, several terms: report the strongest and say which others matched."""
    matches = sorted(set(matches), key=lambda m: (RANK[m[0]], m[1]))
    return matches[0], [f"{k} '{t}'" for k, t in matches[1:]]


def _key(*parts):
    return hashlib.sha1("|".join(str(p).lower() for p in parts).encode()).hexdigest()[:24]


def hits_from_victims(victims, cfg=None):
    cfg = cfg or config()
    s = cfg["settings"]
    out = []
    for v in victims:
        found = match_text(v["victim"], v.get("website"), cfg)
        if found:
            (kind, term), also = best_match(found)
            sev = s["ransomware_severity"] if kind in ("domain", "brand") else SEV_DOWN.get(s["ransomware_severity"], "Medium") if kind == "vendor" else s["mention_severity"]
            out.append({"source": v["feed"], "kind": "leak-site-post" if kind != "vendor" else "supply-chain-post", "term": term, "term_kind": kind,
                        "title": f"{v['group'] or 'A ransomware group'} listed '{v['victim']}'", "severity": sev, "url": v.get("post_url") or "",
                        "detail": f"{v['feed']} shows '{v['victim']}' (website {v.get('website') or 'not given'}) posted by {v['group'] or 'an unnamed group'} on {v.get('discovered') or 'an unknown date'}. "
                                  f"It matched your {kind} '{term}'" + (f" (also {', '.join(also)})" if also else "") + f". Confirm it is you (or your supplier) before acting.",
                        "key": _key(v["feed"], "post", v["victim"], v["group"]), "technique": "T1486"})
    return out


def hits_from_exposure(source, domain, result, cfg=None):
    cfg = cfg or config()
    s = cfg["settings"]
    if result["total"] < s["credential_min_records"]:
        return []
    names = sorted({r["source"] for r in result["records"] if r.get("source")})
    dates = sorted({r["date"] for r in result["records"] if r.get("date")})
    detail = (f"{source} reports {result['total']} record(s) for {domain}" + (f" across {len(names)} source(s): {', '.join(names[:8])}" if names else "")
              + (f", dated {dates[0]} to {dates[-1]}" if dates else "") + ". Identifiers are masked and no password is kept. Compare with your identity team's reset and MFA records.")
    return [{"source": source, "kind": "credential-exposure", "term": domain, "term_kind": "domain", "title": f"{result['total']} exposed credential record(s) for {domain} ({source})",
             "severity": s["credential_severity"], "url": "", "detail": detail, "key": _key(source, "cred", domain, result["total"]), "technique": "T1078"}]


_TERM_LINE = 400


def hits_from_import(source_id, text, cfg=None):
    cfg = cfg or config()
    s = cfg["settings"]
    out, seen = [], set()
    for line in (text or "")[:MAX_IMPORT_CHARS].splitlines():
        line = line.strip()
        if not line:
            continue
        found = match_text(line[:2000], "", cfg)
        if found:
            (kind, term), _also = best_match(found)
            k = _key(source_id, "mention", line[:_TERM_LINE], term)
            if k in seen:
                continue
            seen.add(k)
            onions = ONION.findall(line)
            out.append({"source": source_id, "kind": "mention", "term": term, "term_kind": kind,
                        "title": f"'{term}' named in imported {source_id} output", "severity": s["mention_severity"] if kind != "vendor" else SEV_DOWN[s["mention_severity"]],
                        "url": "", "detail": line[:_TERM_LINE] + (f"  [onion: {', '.join(onions[:3])}]" if onions else ""), "key": k, "technique": None})
    return out[:500]


# ---------------------------------------------------------------- store
def _row(r):
    return dict(r)


def record_hits(hits, engine=None, auto_alert=None):
    """Stores new hits (a repeat is ignored). Returns {new, known, alerts}."""
    engine, t = _engine(engine), db_module.darkweb_hits
    cfg = config()
    auto = cfg["settings"]["auto_alert"] if auto_alert is None else auto_alert
    new = known = alerts = 0
    for h in hits:
        row = {"dedupe_key": h["key"], "source": h["source"], "kind": h["kind"], "term": h["term"], "term_kind": h["term_kind"], "title": h["title"][:300], "severity": h["severity"],
               "detail": h["detail"][:4000], "url": h.get("url") or None, "status": "new", "note": None, "alert_id": None, "first_seen": _now(), "updated_at": _now()}
        try:
            with engine.begin() as conn:
                hid = conn.execute(insert(t), row).inserted_primary_key[0]
        except IntegrityError:
            known += 1
            continue
        new += 1
        if auto:
            ent = ocsf.scan_text(h["detail"])
            alert, _ = hunt_store.receive_alert({"source": "darkweb", "external_id": h["key"], "title": h["title"], "severity": h["severity"], "technique": h.get("technique"),
                                                 "detail": h["detail"], "rule_name": f"Dark Web Watch: {h['kind']}", "entities": ent}, engine)
            with engine.begin() as conn:
                conn.execute(update(t).where(t.c.id == hid).values(alert_id=alert["id"]))
            alerts += 1
    return {"new": new, "known": known, "alerts": alerts}


def list_hits(engine=None, status=None):
    engine, t = _engine(engine), db_module.darkweb_hits
    q = select(t).order_by(t.c.id.desc()).limit(500)
    if status:
        q = q.where(t.c.status == status)
    with engine.connect() as conn:
        return [_row(r) for r in conn.execute(q).mappings()]


def set_hit_status(hit_id, status, note, engine=None):
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    if status in ("actioned", "dismissed") and not (note or "").strip():
        raise ValueError("Write a note with the decision (what you did, or why it is not you)")
    engine, t = _engine(engine), db_module.darkweb_hits
    with engine.begin() as conn:
        if not conn.execute(select(t.c.id).where(t.c.id == int(hit_id))).first():
            raise KeyError("No such hit")
        conn.execute(update(t).where(t.c.id == int(hit_id)).values(status=status, note=(note or "").strip() or None, updated_at=_now()))
    return next(h for h in list_hits(engine) if h["id"] == int(hit_id))


# ---------------------------------------------------------------- source state
def _state(engine):
    engine, t = _engine(engine), db_module.darkweb_sources
    with engine.connect() as conn:
        return {r["source_id"]: dict(r) for r in conn.execute(select(t)).mappings()}


def _touch(engine, source_id, status, count, enabled=None):
    engine, t = _engine(engine), db_module.darkweb_sources
    with engine.begin() as conn:
        cur = conn.execute(select(t).where(t.c.source_id == source_id)).mappings().first()
        vals = {"last_run_at": _now(), "last_status": status[:300], "last_count": count}
        if enabled is not None:
            vals["enabled"] = 1 if enabled else 0
        if cur:
            conn.execute(update(t).where(t.c.source_id == source_id).values(**vals))
        else:
            conn.execute(insert(t), {"source_id": source_id, "enabled": 1 if enabled is None else int(enabled), **vals})


def set_enabled(source_id, enabled, engine=None):
    if source_id not in {s["id"] for s in catalog()}:
        raise KeyError("No such source")
    engine, t = _engine(engine), db_module.darkweb_sources
    with engine.begin() as conn:
        cur = conn.execute(select(t.c.source_id).where(t.c.source_id == source_id)).first()
        if cur:
            conn.execute(update(t).where(t.c.source_id == source_id).values(enabled=1 if enabled else 0))
        else:
            conn.execute(insert(t), {"source_id": source_id, "enabled": 1 if enabled else 0, "last_run_at": None, "last_status": None, "last_count": None})


def sources(engine=None, connected=()):
    """The catalog with live state. `connected` is the set of lookup source ids that have a stored connection."""
    st = _state(engine)
    out = []
    for s in catalog():
        cur = st.get(s["id"])
        enabled = bool(cur["enabled"]) if cur else bool(s.get("active_default"))
        if s["mode"] == "lookup" and s["id"] not in connected:
            enabled = False
        out.append({**s, "enabled": enabled, "connected": s["id"] in connected if s["mode"] == "lookup" else None,
                    "last_run_at": cur and cur["last_run_at"], "last_status": cur and cur["last_status"], "last_count": cur and cur["last_count"]})
    return out


# ---------------------------------------------------------------- runners
def run_feed(source_id, fetcher, engine=None):
    """Fetches one feed and records matches. `fetcher` is a connector instance with fetch()."""
    cfg = config()
    if not has_terms(cfg):
        _touch(engine, source_id, "No watch terms set; add your domains and brands first", 0)
        return {"fetched": 0, "new": 0, "known": 0, "alerts": 0, "note": "No watch terms are set, so nothing was matched."}
    try:
        victims = fetcher.fetch()
    except Exception as exc:  # noqa: BLE001 - recorded, not hidden
        _touch(engine, source_id, f"Error: {exc}", 0)
        raise
    r = record_hits(hits_from_victims(victims, cfg), engine)
    _touch(engine, source_id, f"OK: {len(victims)} posts read, {r['new']} new match(es)", len(victims))
    return {"fetched": len(victims), **r}


def run_lookup(source_id, connector, engine=None):
    cfg = config()
    if not cfg["domains"]:
        _touch(engine, source_id, "No domains set in the watch terms", 0)
        return {"domains": 0, "new": 0, "known": 0, "alerts": 0, "note": "Add your domains to the watch terms first."}
    all_hits, total = [], 0
    try:
        for d in cfg["domains"][:20]:
            res = connector.lookup_domain(d)
            total += res["total"]
            all_hits += hits_from_exposure(source_id, d, res, cfg)
    except Exception as exc:  # noqa: BLE001
        _touch(engine, source_id, f"Error: {exc}", 0)
        raise
    r = record_hits(all_hits, engine)
    _touch(engine, source_id, f"OK: {total} record(s) across {len(cfg['domains'][:20])} domain(s), {r['new']} new hit(s)", total)
    return {"domains": len(cfg["domains"][:20]), "records": total, **r}


def run_import(source_id, text, engine=None):
    if source_id not in {s["id"] for s in catalog()}:
        raise KeyError("No such source")
    cfg = config()
    if not has_terms(cfg):
        raise ValueError("Set your watch terms first: imported text is matched against them")
    if len(text or "") > MAX_IMPORT_CHARS:
        text = text[:MAX_IMPORT_CHARS]
    r = record_hits(hits_from_import(source_id, text, cfg), engine)
    _touch(engine, source_id, f"Import: {r['new']} new hit(s)", r["new"])
    return {"lines": len((text or "").splitlines()), "onion_addresses": len(set(ONION.findall(text or ""))), **r}
