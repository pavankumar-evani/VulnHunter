"""
Applications and their software bills of materials.

An application is the unit a development team owns: a name (the same name its findings carry as `asset.name`), the deployment context a CMDB would hold
(environment, platform, owner, team, business criticality, whether it faces the internet), where its code lives (Git provider, repository, default
branch, the dependency files) and the connection Quanta uses to open pull requests for it. The SBOM stored beside it is the parsed dependency graph
(see sbom_parse.py); a new upload replaces the previous one.

Nothing here reaches out to a repository: it only records what a person or a CI job supplied.
"""
import datetime
import json
import re

from sqlalchemy import delete, insert, select, update

from remediation.appsec import sbom_parse
from remediation.utils import db as db_module

ENVIRONMENTS = ("production", "staging", "development", "test")
CRITICALITY = ("critical", "high", "medium", "low")
PROVIDERS = ("github", "gitlab")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/@-]{0,119}$")
_REPO = re.compile(r"^(?!\.)[A-Za-z0-9._-]+(?:/(?!\.)[A-Za-z0-9._-]+){1,9}$")  # no segment may start with "." (so no "." or "..")
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
_PATH = re.compile(r"^[A-Za-z0-9._/@+-]{1,200}$")
FIELDS = ("environment", "platform", "os", "owner", "team", "business_criticality", "internet_facing", "data_classification", "repo_provider", "repo",
          "default_branch", "manifest_paths", "connection_id", "notes")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def norm(name):
    return (name or "").strip().lower()


def _row(r):
    d = dict(r)
    d["manifest_paths"] = json.loads(d["manifest_paths"]) if d.get("manifest_paths") else []
    return d


def clean(fields):
    """Validated, trimmed values for the fields given. Raises ValueError with a readable message."""
    out = {}
    for k in FIELDS:
        if k not in fields:
            continue
        v = fields[k]
        if k == "internet_facing":
            out[k] = None if v in (None, "") else bool(v)
        elif k == "connection_id":
            out[k] = None if v in (None, "") else int(v)
        elif k == "manifest_paths":
            paths = [p.strip() for p in (v if isinstance(v, list) else str(v or "").replace(",", "\n").split("\n")) if str(p).strip()]
            for p in paths:
                if not _PATH.match(p) or ".." in p.split("/") or p.startswith("/"):
                    raise ValueError(f"manifest path {p!r} must be a relative path inside the repository")
            out[k] = json.dumps(paths[:20])
        else:
            v = (v or "").strip() if isinstance(v, str) or v is None else str(v)
            if k == "environment" and v and v.lower() not in ENVIRONMENTS:
                raise ValueError(f"environment must be one of {', '.join(ENVIRONMENTS)}")
            if k == "business_criticality" and v and v.lower() not in CRITICALITY:
                raise ValueError(f"business criticality must be one of {', '.join(CRITICALITY)}")
            if k == "repo_provider" and v and v.lower() not in PROVIDERS:
                raise ValueError(f"repository provider must be one of {', '.join(PROVIDERS)}")
            if k == "repo" and v and not _REPO.match(v):
                raise ValueError("repository must look like group/project (or owner/repo)")
            if k == "default_branch" and v and (not _BRANCH.match(v) or ".." in v):
                raise ValueError("default branch is not a valid branch name")
            out[k] = (v.lower() if k in ("environment", "business_criticality", "repo_provider") else v)[:500] or None
    return out


def upsert_application(name, fields, actor, engine=None):
    name = (name or "").strip()
    if not _NAME.match(name):
        raise ValueError("Name the application with letters, digits, spaces and . _ : / @ - (up to 120 characters)")
    engine, t = _engine(engine), db_module.applications
    vals = {**clean(fields), "updated_by": actor, "updated_at": _now()}
    known = get_application(name, engine)  # names match the way findings match them, ignoring case: one record per application
    if known:
        name = known["name"]
    with engine.begin() as conn:
        existing = conn.execute(select(t.c.name).where(t.c.name == name)).first()
        if existing:
            conn.execute(update(t).where(t.c.name == name).values(**vals))
        else:
            conn.execute(insert(t), {"name": name, **vals})
    return get_application(name, engine)


def get_application(name, engine=None):
    engine, t = _engine(engine), db_module.applications
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.name == name)).mappings().first()
        if r is None:  # names are matched the way findings match them: ignoring case
            for cand in conn.execute(select(t)).mappings().all():
                if norm(cand["name"]) == norm(name):
                    r = cand
                    break
    return _row(r) if r else None


def list_applications(engine=None):
    engine, t = _engine(engine), db_module.applications
    with engine.connect() as conn:
        return [_row(r) for r in conn.execute(select(t).order_by(t.c.name)).mappings().all()]


def delete_application(name, engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        n = conn.execute(delete(db_module.applications).where(db_module.applications.c.name == name)).rowcount
        conn.execute(delete(db_module.app_sboms).where(db_module.app_sboms.c.application == name))
    return bool(n)


def set_sbom(application, data, source, actor, engine=None, notes=None):
    """Parses `data` (CycloneDX or SPDX JSON, or an already-parsed graph) and stores it for `application`, replacing any earlier one. Creates the
    application record if there is none, so an SBOM pushed from CI is never turned away for want of a form. Raises SbomError."""
    graph = data if isinstance(data, dict) and "components" in data and "edges" in data and "has_graph" in data else sbom_parse.parse(data)
    engine, t = _engine(engine), db_module.app_sboms
    if get_application(application, engine) is None:
        upsert_application(application, {}, actor, engine)
    app_name = get_application(application, engine)["name"]
    vals = {"format": graph["format"], "source": (source or "")[:120], "graph_json": json.dumps(graph, separators=(",", ":")), "component_count": len(graph["components"]),
            "notes_json": json.dumps(notes or []), "uploaded_by": actor, "uploaded_at": _now()}
    with engine.begin() as conn:
        if conn.execute(update(t).where(t.c.application == app_name).values(**vals)).rowcount == 0:
            conn.execute(insert(t), {"application": app_name, **vals})
    return {"application": app_name, "format": graph["format"], "components": len(graph["components"]), "has_graph": graph["has_graph"], "notes": notes or []}


def get_sbom(application, engine=None):
    """{"graph", "format", "source", "uploaded_at", "uploaded_by", "notes"} or None."""
    app = get_application(application, engine)
    if app is None:
        return None
    engine, t = _engine(engine), db_module.app_sboms
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.application == app["name"])).mappings().first()
    if not r:
        return None
    return {"graph": json.loads(r["graph_json"]), "format": r["format"], "source": r["source"], "uploaded_at": r["uploaded_at"], "uploaded_by": r["uploaded_by"],
            "notes": json.loads(r["notes_json"] or "[]")}


def sbom_summaries(engine=None):
    """{application name: {format, components, uploaded_at}} without loading any graph."""
    engine, t = _engine(engine), db_module.app_sboms
    with engine.connect() as conn:
        return {r["application"]: {"format": r["format"], "components": r["component_count"], "uploaded_at": r["uploaded_at"], "source": r["source"]}
                for r in conn.execute(select(t.c.application, t.c.format, t.c.component_count, t.c.uploaded_at, t.c.source)).mappings().all()}
