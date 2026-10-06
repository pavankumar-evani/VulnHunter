"""
External attack surface store: what imported discovery output says exists, what changed since the last import, and what is yours.

Quanta never scans. An import is the output of a tool a person ran (see parsers.py). Every asset has a stable key `kind:value` (kinds: domain, subdomain, ip,
service `host:port/proto`, url `scheme://host[:port]`), so importing the same data twice changes nothing and importing newer data produces a DELTA:

  new          first time this key is seen (or seen again after it had disappeared: change 'reappeared');
  changed      an existing asset gained a port, a technology or a different certificate;
  disappeared  absent from a COMPLETE import of the same tool and scope. An import is complete only when the sender says so: a partial list never
               makes anything disappear, and a tool that never saw an asset cannot make it disappear.

Scope is what the customer declares (domains and CIDR ranges, administrator only). An asset outside the declared scope is recorded and flagged (in_scope
false), counted separately, never raises a finding and never joins the graph. With no scope declared everything is treated as in scope and the summary says
that scope is not declared. An IP address is in scope when it sits in a declared range OR was seen with a host name that is in scope.
"""
import datetime
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import delete, func, insert, select, update

from remediation.asm import parsers
from remediation.utils import db as db_module
from remediation.utils.file_lock import FileLock

LOCK_PATH = Path(__file__).with_name(".asm_import")
MAX_ASSETS = 100_000
MAX_CHANGES_PER_RUN = 5000
MAX_LIST = 30
MAX_VULNS_PER_ASSET = 50
# For each tool, the kinds of asset it can speak for: a COMPLETE import by that tool that omits an asset it had seen makes the asset 'gone'.
AUTHORITY = {"subfinder": {"subdomain"}, "dnsx": {"subdomain"}, "httpx": {"url"}, "naabu": {"service"}}
KINDS = ("domain", "subdomain", "ip", "service", "url")


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


# ---------------------------------------------------------------- scope
class Scope:
    def __init__(self, domains=(), cidrs=()):
        self.domains = sorted({d.lower() for d in domains})
        self.nets = []
        for c in cidrs:
            try:
                self.nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                continue

    @property
    def declared(self):
        return bool(self.domains or self.nets)

    def host_in(self, host):
        h = (host or "").lower()
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def ip_in(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in self.nets)

    def check(self, names=(), ips=()):
        """In scope when nothing is declared, or when any of the host names / addresses involved is covered."""
        if not self.declared:
            return True
        return any(self.host_in(n) for n in names if n and not parsers.is_ip(n)) or any(self.ip_in(i) for i in [*ips, *[n for n in names if parsers.is_ip(n)]] if i)

    def domain_for(self, host):
        h = (host or "").lower()
        for d in sorted(self.domains, key=len, reverse=True):
            if h == d or h.endswith("." + d):
                return d
        return None


def get_scope(engine=None):
    engine, t = _engine(engine), db_module.asm_scope
    with engine.connect() as conn:
        rows = [dict(r) for r in conn.execute(select(t).order_by(t.c.kind, t.c.value)).mappings()]
    return {"domains": [r["value"] for r in rows if r["kind"] == "domain"], "cidrs": [r["value"] for r in rows if r["kind"] == "cidr"], "entries": rows}


def scope_object(engine=None):
    s = get_scope(engine)
    return Scope(s["domains"], s["cidrs"])


def set_scope(domains, cidrs, actor=None, engine=None, now=None):
    """Replaces the declared scope. Validates every entry; recomputes in_scope for every stored asset. Returns the scope and how many assets changed side."""
    engine, t = _engine(engine), db_module.asm_scope
    ds, cs = [], []
    for d in domains or []:
        h = parsers.norm_host(str(d))
        if not h or parsers.is_ip(h):
            raise ValueError(f"{d!r} is not a domain name")
        ds.append(h)
    for c in cidrs or []:
        try:
            cs.append(parsers.parse_cidr(str(c)))
        except parsers.ParseError as exc:
            raise ValueError(str(exc)) from exc
    if len(ds) + len(cs) > 2000:
        raise ValueError("At most 2000 scope entries")
    with FileLock(str(LOCK_PATH), timeout=120.0):
        with engine.begin() as conn:
            conn.execute(delete(t))
            ts = _now(now)
            rows = [{"kind": "domain", "value": v, "added_by": actor, "added_at": ts} for v in sorted(set(ds))] + [{"kind": "cidr", "value": v, "added_by": actor, "added_at": ts} for v in sorted(set(cs))]
            if rows:
                conn.execute(insert(t), rows)
        changed = rescope(engine)
    out = get_scope(engine)
    out["rescoped"] = changed
    return out


def _asset_names_ips(a):
    d = a["data"]
    names = [*(d.get("hosts") or [])]
    ips = [*(d.get("ips") or [])]
    if a["kind"] in ("domain", "subdomain"):
        names.append(a["value"])
    elif a["kind"] == "ip":
        ips.append(a["value"])
    elif d.get("host"):
        (ips if parsers.is_ip(d["host"]) else names).append(d["host"])
    if d.get("ip"):
        ips.append(d["ip"])
    return names, ips


def rescope(engine=None):
    """Recomputes in_scope for every asset from the declared scope. Returns how many assets changed side."""
    engine, t = _engine(engine), db_module.asm_assets
    scope = scope_object(engine)
    n = 0
    with engine.begin() as conn:
        for a in [_decode(r) for r in conn.execute(select(t)).mappings()]:
            names, ips = _asset_names_ips(a)
            ok = scope.check(names, ips)
            if ok != a["in_scope"]:
                conn.execute(update(t).where(t.c.key == a["key"]).values(in_scope=int(ok)))
                n += 1
    return n


# ---------------------------------------------------------------- settings
def get_setting(name, default=None, engine=None):
    engine, t = _engine(engine), db_module.asm_settings
    with engine.connect() as conn:
        v = conn.execute(select(t.c.value).where(t.c.name == name)).scalar()
    return default if v is None else v


def set_setting(name, value, engine=None):
    engine, t = _engine(engine), db_module.asm_settings
    with engine.begin() as conn:
        conn.execute(delete(t).where(t.c.name == name))
        if value is not None:
            conn.execute(insert(t), {"name": name, "value": str(value)})


def get_cadence_hours(engine=None):
    v = get_setting("expected_cadence_hours", None, engine)
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        return None


def set_cadence_hours(hours, engine=None):
    if hours in (None, "", 0):
        set_setting("expected_cadence_hours", None, engine)
        return None
    try:
        h = float(hours)
    except (TypeError, ValueError):
        raise ValueError("The expected cadence must be a number of hours") from None
    if not 1 <= h <= 24 * 365:
        raise ValueError("The expected cadence must be between 1 hour and one year")
    set_setting("expected_cadence_hours", h, engine)
    return h


# ---------------------------------------------------------------- rows
def _decode(r):
    r = dict(r)
    return {"key": r["key"], "kind": r["kind"], "value": r["value"], "first_seen": r["first_seen"], "last_seen": r["last_seen"], "status": r["status"], "in_scope": bool(r["in_scope"]),
            "sources": json.loads(r["sources_json"]), "tags": json.loads(r["tags_json"]), "technologies": json.loads(r["tech_json"]), "ports": json.loads(r["ports_json"]),
            "data": json.loads(r["data_json"]), "gone_at": r.get("gone_at")}


def _encode(a):
    return {"key": a["key"], "kind": a["kind"], "value": a["value"], "first_seen": a["first_seen"], "last_seen": a["last_seen"], "status": a["status"], "in_scope": int(a["in_scope"]),
            "sources_json": json.dumps(a["sources"]), "tags_json": json.dumps(a["tags"]), "tech_json": json.dumps(a["technologies"]), "ports_json": json.dumps(a["ports"]),
            "data_json": json.dumps(a["data"]), "gone_at": a.get("gone_at")}


def all_assets(engine=None, in_scope=None, status=None):
    engine, t = _engine(engine), db_module.asm_assets
    q = select(t)
    if in_scope is not None:
        q = q.where(t.c.in_scope == int(in_scope))
    if status:
        q = q.where(t.c.status == status)
    with engine.connect() as conn:
        return [_decode(r) for r in conn.execute(q).mappings()]


def _add(lst, items, cap=MAX_LIST):
    added = []
    for i in items:
        if i and i not in lst and len(lst) < cap:
            lst.append(i)
            added.append(i)
    return added


def _origin(url):
    try:
        u = urlsplit(url)
        host = parsers.norm_host(u.hostname or "")
        port = u.port
    except ValueError:
        return None, None
    if not host or u.scheme not in ("http", "https"):
        return None, None
    default = 443 if u.scheme == "https" else 80
    netloc = f"[{host}]" if ":" in host else host
    if port and port != default:
        netloc += f":{port}"
    return f"{u.scheme}://{netloc}", host


# ---------------------------------------------------------------- import
class _Run:
    """One import in memory: loads the assets once, applies observations, collects the delta."""

    def __init__(self, tool, assets, scope, now_s, max_assets=MAX_ASSETS):
        self.tool, self.assets, self.scope, self.now = tool, assets, scope, now_s
        self.touched, self.new_keys, self.dirty = set(), set(), set()
        self.changes = []  # (key, kind, change, detail, in_scope)
        self.pending = {}  # key -> [detail,...] attribute changes for an existing asset
        self.skipped_cap = 0
        self.max_assets = max_assets

    def name_kind(self, host):
        if parsers.is_ip(host):
            return "ip"
        return "domain" if host in self.scope.domains else "subdomain"

    def touch(self, kind, value, hosts=(), ips=(), ports=(), tech=(), tags=(), data=None, track=False, host=None):
        key = f"{kind}:{value}"
        a = self.assets.get(key)
        if a is None:
            if len(self.assets) >= self.max_assets:
                self.skipped_cap += 1
                return None
            a = {"key": key, "kind": kind, "value": value, "first_seen": self.now, "last_seen": self.now, "status": "active", "in_scope": True, "sources": [], "tags": [], "technologies": [],
                 "ports": [], "data": {}, "gone_at": None}
            self.assets[key] = a
            self.new_keys.add(key)
            fresh = True
        else:
            fresh = False
            if a["status"] == "gone":
                a["status"], a["gone_at"] = "active", None
                self.changes.append((key, kind, "reappeared", "Seen again after it had disappeared", None))
        a["last_seen"] = self.now
        _add(a["sources"], [self.tool], 10)
        d = a["data"]
        if host:
            d["host"] = host
        _add(d.setdefault("hosts", []), [h for h in hosts if h and h != value])
        _add(d.setdefault("ips", []), [i for i in ips if i and i != value])
        new_ports = _add(a["ports"], [p for p in ports])
        new_tech = _add(a["technologies"], [t for t in tech], 40)
        _add(a["tags"], tags, 20)
        tls_changed = None
        for k, v in (data or {}).items():
            if v in (None, "", [], {}):
                continue
            if k == "tls":
                old = d.get("tls") or {}
                if old and (old.get("fingerprint") or old.get("not_after")) and (old.get("fingerprint"), old.get("not_after"), old.get("issuer_cn")) != (v.get("fingerprint"), v.get("not_after"), v.get("issuer_cn")):
                    tls_changed = f"certificate changed (expires {old.get('not_after') or '?'} -> {v.get('not_after') or '?'})"
            if k == "cname":
                _add(d.setdefault("cname", []), v)
                continue
            if k == "vulns":
                vs = d.setdefault("vulns", [])
                for x in v:
                    if len(vs) < MAX_VULNS_PER_ASSET and not any(y["template_id"] == x["template_id"] and y.get("matched_at") == x.get("matched_at") for y in vs):
                        vs.append(x)
                continue
            d[k] = v
        names, ipl = _asset_names_ips(a)
        a["in_scope"] = self.scope.check(names, ipl)
        self.touched.add(key)
        self.dirty.add(key)
        if fresh:
            self.changes.append((key, kind, "new", "First seen", a["in_scope"]))
        elif track:
            parts = [f"new port {p}" for p in new_ports] + [f"new technology {t}" for t in new_tech] + ([tls_changed] if tls_changed else [])
            if parts:
                self.pending.setdefault(key, []).extend(parts)
        return a

    # one handler per observation type
    def host(self, o):
        self.touch(self.name_kind(o["host"]), o["host"], tags=[], data={"found_by": o.get("found_by")})

    def dns(self, o):
        ips = o["a"] + o["aaaa"]
        self.touch(self.name_kind(o["host"]), o["host"], ips=ips, data={"cname": o["cname"], "dns_status": o["status"], "mx": o["mx"][:5], "ns": o["ns"][:5]})
        for ip in ips:
            self.touch("ip", ip, hosts=[o["host"]])

    def web(self, o):
        origin, host = _origin(o["url"])
        if not origin:
            return
        ips = [i for i in ([o["ip"]] if o["ip"] else []) + o["a"] if i]
        self.touch("url", origin, hosts=[o["host"]] if not parsers.is_ip(o["host"]) else [], ips=ips, tech=o["tech"] + ([o["webserver"]] if o["webserver"] else []), host=o["host"],
                   data={"title": o["title"], "status_code": o["status_code"], "webserver": o["webserver"], "cdn": o["cdn"], "tls": o["tls"], "cname": o["cname"], "scheme": o["scheme"], "port": o["port"]}, track=True)
        self.touch(self.name_kind(o["host"]), o["host"], ips=ips, ports=[f"{o['port']}/tcp"] if o["port"] else [], tech=o["tech"], data={"cname": o["cname"]})
        for ip in ips:
            self.touch("ip", ip, hosts=[o["host"]] if not parsers.is_ip(o["host"]) else [], ports=[f"{o['port']}/tcp"] if o["port"] else [])
        if o["port"]:
            self.touch("service", f"{ips[0] if ips else o['host']}:{o['port']}/tcp", hosts=[o["host"]] if not parsers.is_ip(o["host"]) else [], ips=ips, host=ips[0] if ips else o["host"],
                       ports=[f"{o['port']}/tcp"], data={"port": o["port"], "protocol": "tcp", "service": o["scheme"]}, track=True)

    def port(self, o):
        host = o["ip"] or o["host"]
        proto = o["protocol"]
        self.touch("service", f"{host}:{o['port']}/{proto}", hosts=[o["host"]] if o["host"] else [], ips=[o["ip"]] if o["ip"] else [], host=host, ports=[f"{o['port']}/{proto}"],
                   data={"port": o["port"], "protocol": proto}, track=True)
        if o["ip"]:
            self.touch("ip", o["ip"], hosts=[o["host"]] if o["host"] else [], ports=[f"{o['port']}/{proto}"])
        if o["host"]:
            self.touch(self.name_kind(o["host"]), o["host"], ips=[o["ip"]] if o["ip"] else [], ports=[f"{o['port']}/{proto}"])

    def vuln(self, o):
        v = {k: o[k] for k in ("template_id", "name", "severity", "tags", "matched_at", "cves", "cvss", "description", "references", "matcher", "timestamp", "check_type")}
        origin, _ = _origin(o["matched_at"]) if o["matched_at"].startswith(("http://", "https://")) else (None, None)
        if origin:
            self.touch("url", origin, hosts=[o["host"]] if not parsers.is_ip(o["host"]) else [], ips=[o["ip"]] if o["ip"] else [], host=o["host"], data={"vulns": [v]})
        elif o["port"]:
            self.touch("service", f"{o['ip'] or o['host']}:{o['port']}/tcp", hosts=[o["host"]] if not parsers.is_ip(o["host"]) else [], ips=[o["ip"]] if o["ip"] else [], host=o["ip"] or o["host"],
                       ports=[f"{o['port']}/tcp"], data={"port": o["port"], "protocol": "tcp", "vulns": [v]})
        else:
            self.touch(self.name_kind(o["host"]), o["host"], ips=[o["ip"]] if o["ip"] else [], data={"vulns": [v]})

    def seed(self, o):
        if o["seed_kind"] == "domain":
            self.touch("domain", o["value"], tags=["seed"])


def _label_matches(label, a):
    label = (label or "").strip().lower()
    if not label:
        return True
    names, ips = _asset_names_ips(a)
    try:
        net = ipaddress.ip_network(label, strict=False)
        return any(ipaddress.ip_address(i) in net for i in ips if parsers.is_ip(i) and ipaddress.ip_address(i).version == net.version)
    except ValueError:
        return any(n == label or n.endswith("." + label) for n in names)


def import_text(tool, text, scope_label=None, complete=False, actor=None, engine=None, now=None, allow_seeds=True):
    """Parses and applies one import. Returns the run summary (new / changed / disappeared / out_of_scope counts and the run id)."""
    tool = (tool or "").strip().lower()
    if tool == "seeds" and not allow_seeds:
        raise parsers.ParseError("The scope is declared by an administrator in the Quanta page; it cannot be changed through the ingest API")
    parsed = parsers.parse(tool, text)
    return apply(parsed, scope_label=scope_label, complete=complete, actor=actor, engine=engine, now=now)


def apply(parsed, scope_label=None, complete=False, actor=None, engine=None, now=None):
    engine = _engine(engine)
    tool, obs = parsed["tool"], parsed["observations"]
    now_s = _now(now)
    with FileLock(str(LOCK_PATH), timeout=120.0):
        if tool == "seeds":
            cur = get_scope(engine)
            ds = sorted({*cur["domains"], *[o["value"] for o in obs if o["seed_kind"] == "domain"]})
            cs = sorted({*cur["cidrs"], *[o["value"] for o in obs if o["seed_kind"] == "cidr"]})
            if len(ds) + len(cs) > 2000:
                raise parsers.ParseError("At most 2000 scope entries")
            t = db_module.asm_scope
            with engine.begin() as conn:
                conn.execute(delete(t))
                rows = [{"kind": "domain", "value": v, "added_by": actor, "added_at": now_s} for v in ds] + [{"kind": "cidr", "value": v, "added_by": actor, "added_at": now_s} for v in cs]
                conn.execute(insert(t), rows)
        scope = scope_object(engine)
        assets = {a["key"]: a for a in all_assets(engine)}
        run = _Run(tool, assets, scope, now_s)
        for o in obs:
            getattr(run, {"host": "host", "dns": "dns", "web": "web", "port": "port", "vuln": "vuln", "seed": "seed"}[o["type"]])(o)
        gone = []
        label_note = None
        if complete:
            auth = AUTHORITY.get(tool)
            if not auth:
                label_note = f"{tool} output cannot make an asset disappear, so 'complete' was ignored"
            else:
                for a in assets.values():
                    if a["status"] == "active" and a["kind"] in auth and tool in a["sources"] and a["key"] not in run.touched and _label_matches(scope_label, a):
                        a["status"], a["gone_at"] = "gone", now_s
                        run.dirty.add(a["key"])
                        gone.append(a["key"])
                        run.changes.append((a["key"], a["kind"], "disappeared", f"Absent from a complete {tool} import" + (f" for {scope_label}" if scope_label else ""), a["in_scope"]))
        for key, parts in run.pending.items():
            run.changes.append((key, assets[key]["kind"], "changed", "; ".join(parts[:6]), assets[key]["in_scope"]))
        counts = {"new": sum(1 for c in run.changes if c[2] in ("new", "reappeared")), "changed": sum(1 for c in run.changes if c[2] == "changed"), "gone": len(gone)}
        out_of_scope = sum(1 for k in run.touched if not assets[k]["in_scope"])
        notes = []
        if label_note:
            notes.append(label_note)
        if run.skipped_cap:
            notes.append(f"{run.skipped_cap} new assets were not stored: the limit of {MAX_ASSETS:,} assets was reached")
        if len(run.changes) > MAX_CHANGES_PER_RUN:
            notes.append(f"The change list was cut at {MAX_CHANGES_PER_RUN:,} of {len(run.changes):,} entries; the counts are complete")
        if not scope.declared and tool != "seeds":
            notes.append("No scope is declared, so everything is treated as in scope")
        ta, tr, tc = db_module.asm_assets, db_module.asm_runs, db_module.asm_changes
        with engine.begin() as conn:
            rid = conn.execute(insert(tr), {"imported_at": now_s, "tool": tool, "scope_label": (scope_label or None), "complete": int(bool(complete) and bool(AUTHORITY.get(tool))), "records": len(obs),
                                            "skipped": parsed["skipped"], "new_count": counts["new"], "changed_count": counts["changed"], "gone_count": counts["gone"], "out_of_scope": out_of_scope,
                                            "actor": actor, "note": "; ".join(notes) or None}).inserted_primary_key[0]
            new_rows = [_encode(assets[k]) for k in run.dirty if k in run.new_keys]
            for i in range(0, len(new_rows), 500):
                conn.execute(insert(ta), new_rows[i:i + 500])
            for k in run.dirty:
                if k not in run.new_keys:
                    e = _encode(assets[k])
                    conn.execute(update(ta).where(ta.c.key == k).values(**{c: v for c, v in e.items() if c != "key"}))
            ch = [{"run_id": rid, "at": now_s, "asset_key": k, "kind": kd, "change": c, "detail": (d or "")[:500], "in_scope": int(bool(s) if s is not None else assets[k]["in_scope"])}
                  for k, kd, c, d, s in run.changes[:MAX_CHANGES_PER_RUN]]
            for i in range(0, len(ch), 500):
                conn.execute(insert(tc), ch[i:i + 500])
        if tool == "seeds":
            rescope(engine)  # a wider scope may bring stored assets in
    return {"run_id": rid, "tool": tool, "records": len(obs), "skipped": parsed["skipped"], "errors": parsed["errors"], "new": counts["new"], "changed": counts["changed"], "disappeared": counts["gone"],
            "out_of_scope": out_of_scope, "complete": bool(complete) and bool(AUTHORITY.get(tool)), "notes": notes, "scope_declared": scope.declared, "imported_at": now_s}


# ---------------------------------------------------------------- reading
def ownership(engine=None):
    engine = _engine(engine)
    try:
        from remediation.inventory import asset_inventory
        return {k.lower(): v for k, v in asset_inventory.load_ownership(engine).items()}
    except Exception:  # noqa: BLE001 - ownership is optional context
        return {}


def with_owner(a, owners):
    names, ips = _asset_names_ips(a)
    for n in [a["value"], *names, *ips]:
        o = owners.get(str(n).lower())
        if o:
            return {"owner": o.get("owner") or None, "team": o.get("team") or None}
    return {"owner": None, "team": None}


def list_assets(engine=None, kind=None, status=None, in_scope=None, q=None, tag=None, tool=None, limit=500, offset=0, now=None):
    engine = _engine(engine)
    owners = ownership(engine)
    rows = []
    for a in all_assets(engine, in_scope=in_scope, status=status):
        if kind and a["kind"] != kind:
            continue
        if tag and tag not in a["tags"]:
            continue
        if tool and tool not in a["sources"]:
            continue
        if q and q.lower() not in json.dumps([a["value"], a["technologies"], a["data"].get("title"), a["data"].get("hosts")]).lower():
            continue
        rows.append(a)
    rows.sort(key=lambda a: (a["kind"] != "domain", a["kind"], a["value"]))
    total = len(rows)
    out = []
    for a in rows[offset:offset + max(1, min(int(limit), 2000))]:
        d = a["data"]
        out.append({**{k: a[k] for k in ("key", "kind", "value", "first_seen", "last_seen", "status", "in_scope", "sources", "tags", "technologies", "ports", "gone_at")}, **with_owner(a, owners),
                    "age_days": _age_days(a["last_seen"], now), "title": d.get("title"), "status_code": d.get("status_code"), "ips": (d.get("ips") or [])[:5], "hosts": (d.get("hosts") or [])[:5],
                    "cname": d.get("cname") or [], "tls_expires": (d.get("tls") or {}).get("not_after"), "vulns": len(d.get("vulns") or [])})
    return {"assets": out, "total": total}


def _age_days(ts, now=None):
    t = _parse_ts(ts)
    if not t:
        return None
    return max(0, ((now or datetime.datetime.now(datetime.timezone.utc)) - t).days)


def list_changes(engine=None, days=None, change=None, limit=500, now=None, in_scope=None):
    engine, t = _engine(engine), db_module.asm_changes
    q = select(t).order_by(t.c.id.desc())
    if days:
        q = q.where(t.c.at >= _now((now or datetime.datetime.now(datetime.timezone.utc)) - datetime.timedelta(days=days)))
    if change:
        q = q.where(t.c.change == change)
    if in_scope is not None:
        q = q.where(t.c.in_scope == int(in_scope))
    with engine.connect() as conn:
        return [dict(r, in_scope=bool(r["in_scope"])) for r in conn.execute(q.limit(max(1, min(int(limit), 5000)))).mappings()]


def list_runs(engine=None, limit=50):
    engine, t = _engine(engine), db_module.asm_runs
    with engine.connect() as conn:
        return [dict(r, complete=bool(r["complete"])) for r in conn.execute(select(t).order_by(t.c.id.desc()).limit(limit)).mappings()]


def data_age(engine=None, now=None):
    """When data last arrived, per tool and overall, against the expected cadence. Never reports 'fresh' for data that is old or missing."""
    engine, t = _engine(engine), db_module.asm_runs
    now = now or datetime.datetime.now(datetime.timezone.utc)
    with engine.connect() as conn:
        rows = conn.execute(select(t.c.tool, func.max(t.c.imported_at)).where(t.c.tool != "seeds").group_by(t.c.tool)).all()
        last_id = conn.execute(select(func.max(t.c.id)).where(t.c.tool != "seeds")).scalar()
    per_tool = {tool: ts for tool, ts in rows}
    last = max(per_tool.values()) if per_tool else None
    age_h = round((now - _parse_ts(last)).total_seconds() / 3600, 1) if last and _parse_ts(last) else None
    cadence = get_cadence_hours(engine)
    stale = bool(cadence) and (age_h is None or age_h > cadence)
    return {"last_import_at": last, "age_hours": age_h, "age_days": round(age_h / 24, 1) if age_h is not None else None, "cadence_hours": cadence, "stale": stale, "never_imported": last is None,
            "per_tool": {k: {"last_import_at": v, "age_hours": round((now - _parse_ts(v)).total_seconds() / 3600, 1) if _parse_ts(v) else None} for k, v in sorted(per_tool.items())}, "last_run_id": last_id,
            "message": ("No attack-surface data has been imported yet. Nothing here says anything about your exposure." if last is None else
                        (f"The newest attack-surface data is {age_h:g} hours old, past the expected {cadence:g} hours. Treat this view as out of date, not as clean." if stale else
                         f"The newest attack-surface data is {age_h:g} hours old." + (f" It is expected at least every {cadence:g} hours." if cadence else " No expected import cadence is set.")))}


def check_stale(engine=None, now=None):
    """Raises ONE SOC alert per stale episode (per newest import) when data is older than the expected cadence. Returns the alert or None."""
    engine = _engine(engine)
    age = data_age(engine, now)
    if not age["stale"]:
        return None
    marker = str(age["last_run_id"] or "never")
    if get_setting("stale_alerted_run", None, engine) == marker:
        return None
    from remediation.hunting import store as hunt_store
    body = ("No attack-surface import has been received." if age["never_imported"] else f"The newest import was {age['age_hours']:g} hours ago ({age['last_import_at']}).")
    alert, _ = hunt_store.receive_alert({"source": "asm", "external_id": f"asm-stale:{marker}", "title": "Stale attack-surface data", "severity": "Medium",
                                         "detail": body + f" Quanta expected data at least every {age['cadence_hours']:g} hours. Until new output arrives the external view may be missing new exposure; do not read it as clean. "
                                                          "Run your discovery tools and import their output.", "rule_name": "Attack surface: expected import missing", "entities": []}, engine)
    set_setting("stale_alerted_run", marker, engine)
    return alert


def counts(engine=None):
    engine, t = _engine(engine), db_module.asm_assets
    with engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(t)).scalar() or 0


def clear(engine=None):
    """Removes every stored asset, change and run (the scope and settings stay). For starting over."""
    engine = _engine(engine)
    with FileLock(str(LOCK_PATH), timeout=120.0), engine.begin() as conn:
        for t in (db_module.asm_assets, db_module.asm_changes, db_module.asm_runs):
            conn.execute(delete(t))
