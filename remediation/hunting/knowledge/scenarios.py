"""
Threat scenario packs: hand-authored hunt hypotheses under `scenarios/*.yaml`, each tied to techniques that exist in the catalog (a test enforces it).

A scenario carries a hypothesis template, the ATT&CK / ATLAS techniques, the Lockheed Martin kill-chain phases, Diamond Model hints, the data classes it needs,
LEADS (queries, rendered per language), what malicious and benign look like, tuning notes, severity and priority hints and a recommended response playbook id.

A lead is either
  * a `selection` (Sigma-style field -> value map): Quanta renders it as Sigma, Splunk SPL, KQL and EQL from the same selection, so the four always agree; or
  * explicit `spl` / `kql` / `eql` / `sigma` text, for what a single-event selection cannot say (counts, baselines, joins over time). A language the lead does not
    give is reported as "not-expressible" (with the reason) when the lead says so, or "not-provided" otherwise: never filled in with a guess.

Field names are Sigma's; map them to your data model. Quanta runs none of these queries.
"""
import datetime
from pathlib import Path

import yaml

from remediation.hunting import translate, usecases
from remediation.hunting.engine import render
from remediation.hunting.knowledge import catalog as cat
from remediation.utils.digest import dedup_sha1

DIR = Path(__file__).with_name("scenarios")
LANGUAGES = ("sigma", "splunk-spl", "kql", "eql")
CATEGORIES = ("phishing", "social-engineering", "insider-threat", "drive-by", "cloud", "identity", "system-services", "user-activity", "network", "ransomware", "supply-chain",
              "ai-ml", "malware", "ot-mobile")
KILL_CHAIN = ("reconnaissance", "weaponization", "delivery", "exploitation", "installation", "command-and-control", "actions-on-objectives")
DATA_CLASSES = ("endpoint", "host-auth", "identity-provider", "email", "proxy", "dns", "network-flow", "cloud-audit", "cloud-billing", "saas-audit", "file-activity", "vcs-ci",
                "ai-gateway", "external-exposure", "directory", "ot-network", "mobile-mdm", "web-server")
SEVERITIES = ("low", "medium", "high", "critical")
PRIORITIES = ("low", "medium", "high")
MAX_QUERY = 6000

_cache = {}


def _load_yaml(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


def playbooks(dir_=None):
    return (_load_yaml(Path(dir_ or DIR) / "_playbooks.yaml") or {}).get("playbooks", {})


def load(dir_=None):
    """All scenarios, in file order. Cached per directory."""
    d = Path(dir_ or DIR)
    key = str(d)
    if key not in _cache:
        out = []
        for p in sorted(d.glob("*.yaml")):
            if p.name.startswith("_"):
                continue
            for s in _load_yaml(p):
                s["pack"] = p.stem
                out.append(s)
        _cache[key] = out
    return _cache[key]


def reload():
    _cache.clear()


def get(sid, dir_=None):
    return next((s for s in load(dir_) if s["id"] == sid), None)


# ---------------------------------------------------------------- EQL (selection -> Event Query Language search)
def _eq(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def to_eql(selection):
    """An EQL `any where` search from a Sigma-style selection (contains/startswith/endswith as case-insensitive wildcard `like~`, lists as OR, fields as AND)."""
    if not selection:
        raise ValueError("A detection needs at least one field")
    parts = []
    for key, value in selection.items():
        field, _, mod = key.partition("|")
        if mod and mod not in ("contains", "startswith", "endswith"):
            raise ValueError(f"Unsupported modifier: {mod}")
        vals = value if isinstance(value, list) else [value]
        if all(isinstance(v, (int, float)) for v in vals) and not mod:
            parts.append(f"{field} == {vals[0]}" if len(vals) == 1 else f"{field} in ({', '.join(str(v) for v in vals)})")
            continue
        pats = [(f"*{v}*" if mod == "contains" else f"{v}*" if mod == "startswith" else f"*{v}" if mod == "endswith" else str(v)) for v in vals]
        parts.append(f"{field} like~ {_eq(pats[0])}" if len(pats) == 1 else f"{field} like~ ({', '.join(_eq(p) for p in pats)})")
    return "any where " + " and ".join(parts)


# ---------------------------------------------------------------- leads
def _status(text, why=None):
    return {"status": "provided", "query": text.strip()} if text else {"status": "not-provided", "reason": why or "No query was written for this lead in this language; adapt another language's form."}


def render_lead(lead, scenario=None, hosts=(), today=None, hyp_text=""):
    """-> {name, technique, logsource, notes, languages: {sigma, splunk-spl, kql, eql: {status, query|reason}}, selection}. Never raises for an unexpressible language."""
    today = today or datetime.date.today()
    ne = lead.get("not_expressible") or {}
    sel = lead.get("selection")
    langs = {}
    if sel:
        key = f"scn-{(scenario or {}).get('id', 'x')}-{dedup_sha1(lead['name'].encode()).hexdigest()[:8]}"
        langs["sigma"] = _status(usecases.sigma_draft(key, f"Quanta hunt - {lead['name']}", hyp_text or (scenario or {}).get("title", lead["name"]), [lead["technique"]], sel,
                                                      lead.get("logsource") or {"category": "process_creation"}, (scenario or {}).get("severity", "medium"), today))
        langs["splunk-spl"] = _status(translate.to_spl(sel, sorted(hosts)[:50] or None))
        langs["kql"] = _status(render.to_kql(sel, sorted(hosts)[:50] or None))
        langs["eql"] = _status(to_eql(sel))
    else:
        for lang, field in (("sigma", "sigma"), ("splunk-spl", "spl"), ("kql", "kql"), ("eql", "eql")):
            txt = lead.get(field)
            if txt:
                langs[lang] = _status(txt)
            elif lang in ne:
                langs[lang] = {"status": "not-expressible", "reason": ne[lang]}
            elif lang == "sigma":
                langs[lang] = {"status": "not-expressible", "reason": ne.get("sigma") or "Needs counting, a baseline or a join over time; a single-event Sigma rule cannot say it. Use the SPL or KQL form."}
            else:
                langs[lang] = {"status": "not-provided", "reason": "No query was written for this lead in this language; adapt another language's form."}
    for lang, v in ne.items():   # an explicit statement wins over a generated one
        if lang in langs and langs[lang]["status"] != "provided":
            langs[lang] = {"status": "not-expressible", "reason": v}
    return {"name": lead["name"], "technique": lead["technique"], "logsource": lead.get("logsource"), "notes": lead.get("notes", ""), "languages": langs, "selection": sel,
            "expressible": [k for k, v in langs.items() if v["status"] == "provided"]}


def engine_queries(scenario, hosts=(), today=None):
    """The scenario's leads in the shape the hunt engine's `queries` use (one per lead that has an SPL form), so accepting a hypothesis creates a normal hunt."""
    out = []
    for lead in scenario.get("leads", []):
        r = render_lead(lead, scenario, hosts, today, scenario.get("hypothesis", ""))
        spl = r["languages"]["splunk-spl"]
        if spl["status"] != "provided":
            continue
        L = r["languages"]
        out.append({"technique": lead["technique"], "name": lead["name"], "domain": scenario.get("category", "endpoint"), "source": "SIEM", "language": "splunk-spl", "query": spl["query"],
                    "kql": L["kql"].get("query") or "", "sigma": L["sigma"].get("query") or "", "eql": L["eql"].get("query") or "",
                    "description": (lead.get("notes") or scenario["title"])[:300], "result": None, "notes": "", "scenario": scenario["id"]})
    return out


def hypothesis_text(scenario, scope_text="the systems in scope"):
    return scenario["hypothesis"].replace("{scope}", scope_text)


# ---------------------------------------------------------------- validation (used by the tests and by `problems()`)
def validate(s, catalog=None, playbook_ids=None):
    """List of plain-sentence problems with one scenario (empty = fine)."""
    from remediation.connectors import siem_search_connector as siem
    c = catalog or cat.get()
    errs = []
    sid = s.get("id", "?")

    def bad(msg):
        errs.append(f"{sid}: {msg}")

    for f in ("id", "title", "category", "hypothesis", "techniques", "kill_chain", "diamond", "data_sources", "leads", "malicious", "benign", "tuning", "severity", "priority", "playbook", "response"):
        if not s.get(f):
            bad(f"missing {f}")
    if s.get("category") not in CATEGORIES:
        bad(f"unknown category {s.get('category')}")
    if "{scope}" not in (s.get("hypothesis") or "") or not str(s.get("hypothesis", "")).startswith("If "):
        bad("the hypothesis must start 'If ' and contain {scope}")
    for t in s.get("techniques") or []:
        if not c.exists(t):
            bad(f"technique {t} is not in the catalog")
    for ph in s.get("kill_chain") or []:
        if ph not in KILL_CHAIN:
            bad(f"unknown kill-chain phase {ph}")
    for ds in s.get("data_sources") or []:
        if ds not in DATA_CLASSES:
            bad(f"unknown data class {ds}")
    for k in ("adversary", "capability", "infrastructure", "victim"):
        if k not in (s.get("diamond") or {}) and k != "adversary":
            bad(f"diamond hint {k} missing")
    if s.get("severity") not in SEVERITIES:
        bad("bad severity")
    if s.get("priority") not in PRIORITIES:
        bad("bad priority")
    if playbook_ids is not None and s.get("playbook") not in playbook_ids:
        bad(f"playbook {s.get('playbook')} is not defined in _playbooks.yaml")
    has_pair = False
    for lead in s.get("leads") or []:
        if lead.get("technique") not in (s.get("techniques") or []) and not c.exists(lead.get("technique") or ""):
            bad(f"lead '{lead.get('name')}' names unknown technique {lead.get('technique')}")
        if not lead.get("name") or not (lead.get("selection") or lead.get("spl") or lead.get("kql") or lead.get("eql")):
            bad("a lead needs a name and a selection or explicit query")
            continue
        try:
            r = render_lead(lead, s)
        except ValueError as exc:
            bad(f"lead '{lead['name']}' does not render: {exc}")
            continue
        spl = r["languages"]["splunk-spl"]
        if spl["status"] == "provided":
            try:
                siem.check_query(spl["query"])
            except Exception as exc:  # noqa: BLE001
                bad(f"lead '{lead['name']}' SPL is refused by the read-only validator: {exc}")
        if spl["status"] == "provided" and r["languages"]["sigma"]["status"] in ("provided", "not-expressible"):
            has_pair = True   # SPL, and a Sigma rule or an honest statement of why Sigma cannot say it
        for lang, v in r["languages"].items():
            if v["status"] == "provided" and len(v["query"]) > MAX_QUERY:
                bad(f"lead '{lead['name']}' {lang} query is too long")
            if v["status"] == "provided" and not v["query"].strip():
                bad(f"lead '{lead['name']}' {lang} is empty")
    if not has_pair:
        bad("no lead gives SPL together with a Sigma rule or an honest not-expressible statement")
    return errs


def problems(dir_=None, catalog=None):
    pb = set(playbooks(dir_))
    ids, errs = set(), []
    for s in load(dir_):
        if s.get("id") in ids:
            errs.append(f"duplicate scenario id {s.get('id')}")
        ids.add(s.get("id"))
        errs += validate(s, catalog, pb)
    return errs


def summary(s, catalog=None):
    c = catalog or cat.get()
    return {"id": s["id"], "title": s["title"], "category": s["category"], "pack": s.get("pack"), "severity": s["severity"], "priority": s["priority"], "kill_chain": s["kill_chain"],
            "techniques": [{"id": t, "name": (c.technique(t, detail=False) or {}).get("name")} for t in s["techniques"]], "data_sources": s["data_sources"],
            "languages": sorted({l for ld in s["leads"] for l, v in render_lead(ld, s)["languages"].items() if v["status"] == "provided"}), "leads": len(s["leads"]),
            "frameworks": sorted({(c.technique(t, detail=False) or {}).get("framework", "?") for t in s["techniques"]}), "hypothesis": hypothesis_text(s), "playbook": s["playbook"]}
