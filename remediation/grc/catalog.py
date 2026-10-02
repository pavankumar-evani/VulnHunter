"""
Framework catalogs and their controls.

Quanta ships small built-in catalogs (the controls it can evidence; see builtin.yaml) and imports the full ones from OSCAL, NIST's
machine-readable format: upload a catalog JSON (NIST publishes SP 800-53 and CSF as OSCAL) and every control, with its title, family
and statement text, becomes available for mapping, evidence and attestation. Licensed standards are not shipped; import your licensed
copy in OSCAL form.

OSCAL ids are lowercase (`ac-2`, `ac-2.1`); they are stored upper case (`AC-2`, `AC-2(1)`) the way auditors write them, so the built-in
and imported controls of the same framework line up.
"""
import datetime
import json
import re
from pathlib import Path

import yaml
from sqlalchemy import delete, insert, select

from remediation.utils import db as db_module

BUILTIN = Path(__file__).resolve().parent / "builtin.yaml"
MAX_CONTROLS = 5000
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,59}$")


class CatalogError(ValueError):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def display_id(oscal_id):
    """ac-2.1 -> AC-2(1); ID.RA-01 stays as is."""
    s = str(oscal_id).strip()
    m = re.match(r"^([A-Za-z]{2}-\d+)\.(\d+)$", s)
    return f"{m.group(1).upper()}({m.group(2)})" if m else (s.upper() if re.match(r"^[a-z]{2}-\d", s) else s)


def _prose(parts):
    out = []
    for p in parts or []:
        if p.get("prose"):
            out.append(p["prose"])
        out.append(_prose(p.get("parts")))
    return " ".join(x for x in out if x).strip()


def _walk(controls, family, out):
    for c in controls or []:
        parts = c.get("parts") or []
        stmt = _prose([p for p in parts if p.get("name") == "statement"]) or _prose(parts)
        out.append({"id": display_id(c.get("id", "")), "title": c.get("title", ""), "family": family, "statement": re.sub(r"\{\{[^}]*\}\}", "_", stmt)[:4000]})
        _walk(c.get("controls"), family, out)


def parse_oscal(doc):
    """Controls from an OSCAL catalog document: [{id, title, family, statement}]."""
    if isinstance(doc, (str, bytes)):
        try:
            doc = json.loads(doc)
        except ValueError as exc:
            raise CatalogError(f"Not valid JSON: {exc}") from exc
    cat = (doc or {}).get("catalog") if isinstance(doc, dict) else None
    if not isinstance(cat, dict):
        raise CatalogError("This is not an OSCAL catalog: there is no top-level 'catalog' object.")
    out = []
    for g in cat.get("groups") or []:
        _walk(g.get("controls"), g.get("title", g.get("id", "")), out)
        for sub in g.get("groups") or []:
            _walk(sub.get("controls"), g.get("title", ""), out)
    _walk(cat.get("controls"), "", out)
    if not out:
        raise CatalogError("The catalog contains no controls.")
    if len(out) > MAX_CONTROLS:
        raise CatalogError(f"More than {MAX_CONTROLS} controls in one catalog.")
    meta = cat.get("metadata") or {}
    return out, {"title": meta.get("title"), "version": meta.get("version")}


def _store(framework_id, name, version, source, controls, engine):
    engine, stamp = _engine(engine), _now()
    fw, ct = db_module.grc_frameworks, db_module.grc_controls
    seen, unique = set(), []
    for c in controls:
        if c["id"] in seen or not c["id"]:
            continue
        seen.add(c["id"])
        unique.append(c)
    with engine.begin() as conn:
        conn.execute(delete(ct).where(ct.c.framework_id == framework_id))
        conn.execute(delete(fw).where(fw.c.id == framework_id))
        conn.execute(insert(fw), {"id": framework_id, "name": name, "version": version, "source": source, "control_count": len(unique), "imported_at": stamp})
        for i in range(0, len(unique), 500):
            conn.execute(insert(ct), [{"framework_id": framework_id, "control_id": c["id"], "title": (c["title"] or c["id"])[:300], "family": c.get("family"),
                                       "statement": c.get("statement")} for c in unique[i:i + 500]])
    return len(unique)


def import_oscal(framework_id, doc, name=None, engine=None):
    """Imports (or replaces) a framework from an OSCAL catalog. Returns the number of controls."""
    if not _ID.match(framework_id or ""):
        raise CatalogError("The framework id must be 2 to 60 lowercase letters, digits or dashes, for example nist-800-53-r5.")
    controls, meta = parse_oscal(doc)
    return _store(framework_id, name or meta.get("title") or framework_id, meta.get("version"), "oscal", controls, engine)


def ensure_builtin(engine=None):
    """Loads the built-in catalogs the first time (and never overwrites a catalog that has been imported)."""
    engine = _engine(engine)
    have = {f["id"]: f for f in list_frameworks(engine)}
    for fw in yaml.safe_load(BUILTIN.read_text(encoding="utf-8"))["frameworks"]:
        if fw["id"] not in have:
            _store(fw["id"], fw["name"], fw.get("version"), "builtin",
                   [{"id": c["id"], "title": c["title"], "family": c.get("family"), "statement": c.get("statement")} for c in fw["controls"]], engine)


def list_frameworks(engine=None):
    engine = _engine(engine)
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(db_module.grc_frameworks).order_by(db_module.grc_frameworks.c.name)).mappings().all()]


def controls_of(framework_id, engine=None):
    engine, t = _engine(engine), db_module.grc_controls
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t).where(t.c.framework_id == framework_id).order_by(t.c.id)).mappings().all()]


def delete_framework(framework_id, engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        conn.execute(delete(db_module.grc_controls).where(db_module.grc_controls.c.framework_id == framework_id))
        return conn.execute(delete(db_module.grc_frameworks).where(db_module.grc_frameworks.c.id == framework_id)).rowcount == 1
