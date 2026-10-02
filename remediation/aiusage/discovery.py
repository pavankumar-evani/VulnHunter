"""
Finding AI use nobody reviewed ("shadow AI").

The reliable signals sit outside the AI services themselves: web proxy and DNS logs show which AI domains people reach, identity-provider
and OAuth consent records show which AI apps were granted access, a CASB shows SaaS use, cloud billing shows API spend. Quanta takes
those as input rather than watching the network. Give it a proxy or DNS export (CSV with a `domain` column and optionally `user` and
`count`, or any text log that mentions hostnames) and it matches the hostnames against a list of known AI services
(remediation/config/ai_domains.yaml). Each service found becomes an application record, "unreviewed" until an administrator marks it
sanctioned or blocked; the counts of distinct users and requests show how much it is used.

It only recognises services on its list, so an unknown new AI tool is not flagged until it is added. Quanta records and reports; it
does not block anything.
"""
import csv
import datetime
import io
import json
import re
from pathlib import Path

import yaml
from sqlalchemy import insert, select, update

from remediation.utils import db as db_module

PATH = Path(__file__).resolve().parent.parent / "config" / "ai_domains.yaml"
STATUSES = ("sanctioned", "unreviewed", "blocked")
_HOST = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
MAX_ROWS = 200000


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def services():
    return (yaml.safe_load(PATH.read_text(encoding="utf-8")) or {}).get("services", [])


def classify(host, svcs=None):
    """The known service whose domain this host is, or None."""
    host = (host or "").lower().strip(".")
    for s in (svcs if svcs is not None else services()):
        for d in s["domains"]:
            if host == d or host.endswith("." + d):
                return s["name"], d
    return None


def parse_log(text, svcs=None):
    """{domain: {"name", "requests", "users": set()}} from a CSV (domain[,user[,count]]) or a free-form log."""
    svcs = svcs if svcs is not None else services()
    found = {}

    def add(host, user, n):
        hit = classify(host, svcs)
        if not hit:
            return
        e = found.setdefault(hit[1], {"name": hit[0], "requests": 0, "users": set()})
        e["requests"] += n
        if user:
            e["users"].add(user)

    head = text.lstrip()[:400].lower()
    lines = text.splitlines()
    if len(lines) > MAX_ROWS:
        raise ValueError(f"More than {MAX_ROWS} lines; split the export.")
    if head.startswith("domain") or head.startswith("host") or head.startswith("url"):
        for row in csv.DictReader(io.StringIO(text)):
            host = row.get("domain") or row.get("host") or row.get("url") or ""
            m = _HOST.search(host)
            add(m.group(1) if m else host, (row.get("user") or "").strip() or None, int(float(row.get("count") or 1)) if str(row.get("count") or "1").replace(".", "", 1).isdigit() else 1)
    else:
        for ln in lines:
            for m in _HOST.finditer(ln):
                add(m.group(1), None, 1)
    return found


def record(found, source, engine=None):
    """Stores what parse_log found. Returns {services, new}. A service already recorded keeps its status and owner."""
    engine, t, stamp = _engine(engine), db_module.ai_apps, _now()
    new = 0
    with engine.begin() as conn:
        for domain, e in found.items():
            row = conn.execute(select(t).where(t.c.domain == domain)).mappings().first()
            if row:
                sig = sorted(set(json.loads(row["signals"] or "[]")) | {source})
                conn.execute(update(t).where(t.c.id == row["id"]).values(
                    users_seen=max(row["users_seen"], len(e["users"])), requests_seen=row["requests_seen"] + e["requests"], signals=json.dumps(sig), last_seen=stamp))
            else:
                conn.execute(insert(t), {"name": e["name"], "domain": domain, "status": "unreviewed", "owner": None, "users_seen": len(e["users"]),
                                         "requests_seen": e["requests"], "signals": json.dumps([source]), "first_seen": stamp, "last_seen": stamp, "note": None})
                new += 1
    return {"services": len(found), "new": new}


def add_app(name, domain, engine=None, status="unreviewed"):
    domain = (domain or "").strip().lower()
    if not re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", domain):
        raise ValueError("domain must look like example.com")
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    engine, t, stamp = _engine(engine), db_module.ai_apps, _now()
    with engine.begin() as conn:
        if conn.execute(select(t.c.id).where(t.c.domain == domain)).first():
            raise ValueError("That domain is already listed")
        return conn.execute(insert(t), {"name": (name or domain)[:120], "domain": domain, "status": status, "owner": None, "users_seen": 0,
                                        "requests_seen": 0, "signals": json.dumps(["manual"]), "first_seen": stamp, "last_seen": stamp, "note": None}).inserted_primary_key[0]


def set_status(app_id, status, owner=None, note=None, engine=None):
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    engine, t = _engine(engine), db_module.ai_apps
    with engine.begin() as conn:
        n = conn.execute(update(t).where(t.c.id == int(app_id)).values(status=status, owner=owner, note=note)).rowcount
    if not n:
        raise KeyError("No such application")


def list_apps(engine=None):
    engine, t = _engine(engine), db_module.ai_apps
    with engine.connect() as conn:
        rows = [dict(r) for r in conn.execute(select(t).order_by(t.c.requests_seen.desc(), t.c.name)).mappings().all()]
    for r in rows:
        r["signals"] = json.loads(r["signals"] or "[]")
    return rows
