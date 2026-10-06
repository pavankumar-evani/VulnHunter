"""
Store and estate matching for the Anthropic CVD feed (table `cvd_advisories`, unique per source + advisory id; a refresh updates the row in place).

Matching (see matching.py) reuses the zero-day watch vocabulary (asset OS strings, finding titles, SBOM components):
  - CVE match: an advisory CVE equals the CVE of a finding in the queue. This is exact.
  - Name match: every product word of the advisory appears in the estate vocabulary (and a vendor word too when a vendor is given).
    It is a name match, NOT a version check: it says "you appear to run something with this name; check whether your version is affected".
Ledger entries that have not yet revealed a project or CVE cannot match anything and are never matched on a guess.
"""
import datetime
import json

from sqlalchemy import insert, select, update

from remediation.cvd.matching import match_estate
from remediation.utils import db as db_module

NOTE = ("A name match is not a version check: it says you appear to run something with this name. A CVE match is exact. Check the advisory and your version; "
        "your scanner and the maintainer decide. Ledger entries that have not yet revealed a project or CVE cannot match.")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def upsert(records, engine=None):
    """-> {"fetched", "new", "updated"}. A record unchanged since the last refresh is not counted as updated."""
    engine, t = _engine(engine), db_module.cvd_advisories
    new = updated = 0
    now = _now()
    with engine.begin() as conn:
        for r in records:
            vals = {"title": r["title"], "cves": json.dumps(r["cves"]), "vendor": r["vendor"], "product": r["product"], "severity": r["severity"],
                    "published": r["published"], "state": r["state"], "url": r["url"]}
            row = conn.execute(select(t).where(t.c.source == r["source"], t.c.advisory_id == r["id"])).mappings().first()
            if row is None:
                conn.execute(insert(t).values(source=r["source"], advisory_id=r["id"], first_seen=now, updated_at=now, **vals))
                new += 1
            elif any(row[k] != v for k, v in vals.items()):
                conn.execute(update(t).where(t.c.id == row["id"]).values(updated_at=now, **vals))
                updated += 1
    return {"fetched": len(records), "new": new, "updated": updated}


def list_advisories(engine=None, limit=5000):
    engine, t = _engine(engine), db_module.cvd_advisories
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.published.desc(), t.c.id.desc()).limit(limit)).mappings().all()
    return [{"id": r["advisory_id"], "source": r["source"], "title": r["title"] or "", "cves": json.loads(r["cves"] or "[]"), "vendor": r["vendor"] or "", "product": r["product"] or "",
             "severity": r["severity"] or "", "published": r["published"] or "", "state": r["state"] or "", "url": r["url"] or "", "first_seen": r["first_seen"], "updated_at": r["updated_at"]}
            for r in rows]


def summary(advisories, findings, sbom_components=()):
    matches = match_estate(advisories, findings, sbom_components)
    return {"total": len(advisories), "with_cve": sum(1 for a in advisories if a["cves"]), "matched": len(matches), "matches": matches[:200], "note": NOTE}
