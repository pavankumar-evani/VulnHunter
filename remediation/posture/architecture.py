"""Architecture review: what the recorded estate says about how it is built. Is the exposure small, is risk concentrated in one package, team or asset, does
every asset and urgent finding have an owner, is the network segmented, and can this Quanta deployment survive losing a node?

Everything is read from recorded data and from the deployment's environment settings. What cannot be observed (backups, for one) is reported as `unknown`
with the step to take, never assumed good. Environment settings are reported as present or absent; a secret value is never put in evidence.
"""
import datetime

from remediation.posture import model

FRAMEWORK = {
    "id": "architecture",
    "title": "Architecture review",
    "summary": "How exposed the estate is, where risk concentrates, who owns it, how it is segmented and how resilient this Quanta deployment is, from recorded findings, firewall rules, topology, SBOMs, assignments and settings.",
    "areas": [("exposure", "Exposure"), ("concentration", "Concentration and shared dependencies"), ("ownership", "Ownership"), ("segmentation", "Segmentation"), ("resilience", "Resilience")],
    "refs": [],
}
FW = FRAMEWORK["id"]
CLOSED = {"resolved", "closed", "fixed", "remediated"}
MIN_URGENT = 4   # fewer urgent findings than this is too few to say anything about concentration


def _chk(cid, area, title, status, **kw):
    return model.check(f"arch-{cid}", FW, area, title, status, refs=FRAMEWORK["refs"], **kw)


def _unknown(cid, area, title, why, data_used, recommendation, weight=3, change=None, n=0):
    return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"{why} Records that could answer this: {n}."], recommendation=recommendation, data_used=data_used, change=change,
                detail="Quanta cannot answer this from what is recorded, so it is left out of the score.")


def _cov(ctx, ok, total):
    share = ok / total
    if share >= ctx.thr["coverage_good"]:
        return "pass", None
    if share >= ctx.thr["coverage_partial"]:
        return "partial", share
    return "fail", None


def _date(value):
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def _open(ctx):
    return [f for f in ctx.findings if str(f.get("status") or "").lower() not in CLOSED]


def _name(f):
    a = f.get("asset") or {}
    return a.get("name") or a.get("hostname")


def _is_kev(f):
    return bool((f.get("kev") or {}).get("listed"))


def _urgent(ctx):
    return [f for f in _open(ctx) if f.get("severity") == "Critical" or _is_kev(f)]


def _assets(ctx):
    return sorted({n for n in (_name(f) for f in ctx.findings) if n})


def _inventory(ctx):
    def load():
        from remediation.inventory import asset_inventory
        return asset_inventory.build_asset_inventory(ctx.findings, ownership=asset_inventory.load_ownership(ctx.engine))
    return ctx.get("inventory", load) if ctx.findings else None


def _topology(ctx):
    from remediation.enrichment import network_reachability
    return ctx.get("topology", lambda: network_reachability.load_topology())


def _firewall(ctx):
    def load():
        from remediation.firewall import analysis, store
        rules = store.rules(engine=ctx.engine)
        if not rules:
            return {"rules": [], "finds": [], "exposure": None}
        pol = analysis.policy()
        return {"rules": rules, "finds": analysis.analyse(rules, pol=pol, today=ctx.now.date()), "exposure": analysis.exposure(rules, pol=pol, today=ctx.now.date())}
    return ctx.get("firewall", load)


def _assignments(ctx):
    from remediation.assignments import store
    return ctx.get("assignments", lambda: store.load_assignments(ctx.engine))


def _assets_line(names, limit=3):
    return ", ".join(sorted(names)[:limit]) + (f" and {len(names) - limit} more" if len(names) > limit else "")


# ---------------------------------------------------------------- exposure
def _exposure(ctx):
    out = []
    inv = _inventory(ctx)
    t = "Internet-facing assets carry no Critical or known-exploited findings"
    uses = ("findings", "asset_ownership", "network_topology.yaml", "applications")
    exposed = set()
    if inv:
        from remediation.enrichment import network_reachability
        topo = _topology(ctx)
        exposed |= {a["name"] for a in inv if a.get("facing") == "external"}
        exposed |= {a["name"] for a in inv if network_reachability.trace_path(a["name"], topo)["verdict"] == "allowed"}
        from remediation.appsec import store as app_store
        apps = ctx.get("apps", lambda: app_store.list_applications(ctx.engine)) or []
        net = {app_store.norm(a["name"]) for a in apps if a.get("internet_facing")}
        exposed |= {a["name"] for a in inv if app_store.norm(a["name"]) in net}
    if not exposed:
        out.append(_unknown("exp-internet-critical", "exposure", t, "No asset is recorded as internet-facing (no facing flag, topology path or application marked internet-facing).",
                            uses, "Mark internet-facing assets on Asset Inventory and fill remediation/config/network_topology.yaml.", weight=5, n=len(inv or [])))
    else:
        bad = [f for f in _urgent(ctx) if _name(f) in exposed]
        hosts = {_name(f) for f in bad}
        ev = [f"{len(bad)} open Critical or known-exploited findings on {len(hosts)} of {len(exposed)} internet-facing assets."]
        if hosts:
            ev.append("Exposed: " + _assets_line(hosts))
        out.append(_chk("exp-internet-critical", "exposure", t, "pass" if not bad else "fail", weight=5, evidence=ev, data_used=uses,
                        detail="Internet-facing assets are attacked first, so a Critical or known-exploited flaw there is the shortest path in.",
                        recommendation="Fix or put a compensating control in front of these assets first." if bad else "Keep internet-facing assets on the fastest remediation lane.",
                        change=None if not bad else {"kind": "page", "where": "/queue", "key": "severity", "value": "Critical", "effect": "Lists the findings to fix first."}))

    fw = _firewall(ctx)
    t = "The firewall exposes no risky ports to the internet"
    if not fw or not fw["rules"]:
        out.append(_unknown("exp-ports", "exposure", t, "No firewall rules are recorded.", ("fw_rules",), "Import firewall rules on the Firewall page.", weight=5))
    else:
        e = fw["exposure"]
        risky = [p for p in e["ports"] if p["risky"]]
        wide = e["wide_open_rules"]
        ev = [f"{len(risky)} risky ports and {len(wide)} any-service rules are reachable from the internet through {len(fw['rules'])} recorded rules."]
        ev += [f"Port {p['port']} ({p['name']}) via {len(p['rules'])} rules" for p in risky[:3]]
        out.append(_chk("exp-ports", "exposure", t, "pass" if not risky and not wide else "fail", weight=5, evidence=ev, data_used=("fw_rules",),
                        detail="Management, remote-access and database ports on the internet are scanned continuously.",
                        recommendation="Remove the exposure, restrict the source or put the service behind a VPN." if risky or wide else "Keep reviewing rules after every change.",
                        change=None if not risky and not wide else {"kind": "page", "where": "/firewall", "key": "FW002", "value": "0 open", "effect": "Lists each exposed port with the rule that opens it."}))

    t = "Known-exploited findings are fixed within the allowed days"
    if not ctx.findings or not any(f.get("kev") is not None for f in ctx.findings):
        out.append(_unknown("exp-kev-age", "exposure", t, "No finding carries known-exploited (KEV) enrichment.", ("findings",), "Run the threat-intelligence enrichment so KEV status is recorded.", weight=4, n=len(ctx.findings)))
    else:
        limit = ctx.thr["kev_open_days"]
        kev = [f for f in _open(ctx) if _is_kev(f)]
        if not kev:
            out.append(_chk("exp-kev-age", "exposure", t, "pass", weight=4, evidence=[f"0 open known-exploited findings among {len(ctx.findings)} recorded."], data_used=("findings",),
                            detail="Known-exploited flaws are used in real attacks now.", recommendation="Keep KEV enrichment running."))
        else:
            old = [f for f in kev if (_date(f.get("first_seen")) and (ctx.now.date() - _date(f["first_seen"])).days > limit)]
            st, sc = _cov(ctx, len(kev) - len(old), len(kev))
            out.append(_chk("exp-kev-age", "exposure", t, st if old else "pass", score=sc, weight=4, data_used=("findings",),
                            evidence=[f"{len(old)} of {len(kev)} open known-exploited findings have been open longer than {limit} days."] + [f"{f.get('id')} on {_name(f)}" for f in old[:3]],
                            detail="The longer a known-exploited flaw stays open the more likely it is used.",
                            recommendation="Patch or mitigate the findings listed." if old else "Keep within the window.",
                            change=None if not old else {"kind": "yaml", "where": "remediation/config/posture_policy.yaml", "key": "kev_open_days", "value": 14, "effect": "Sets how long a known-exploited finding may stay open before it counts as a gap."}))
    return out


# ---------------------------------------------------------------- concentration
def _concentration(ctx):
    out = []
    t = "No vulnerable package is shared across most applications"
    from remediation.graphs import devsecops
    g = ctx.get("supply-chain", lambda: devsecops.build(engine=ctx.engine, findings=ctx.findings))
    if not g or g.get("note"):
        out.append(_unknown("con-package", "concentration", t, "No application with an SBOM is recorded.", ("applications", "app_sboms", "findings"),
                            "Register applications and upload an SBOM for each (Applications page, or POST /api/ingest/sbom from CI).", weight=4))
    else:
        apps = [n for n in g["nodes"] if n["kind"] == "application"]
        vuln = sorted((n for n in g["nodes"] if n["kind"] == "package" and n.get("sev")), key=lambda n: (-n["weight"], n["id"]))
        top = vuln[0] if vuln else None
        if not top or top["weight"] < 2:
            out.append(_chk("con-package", "concentration", t, "pass", weight=4, evidence=[f"{len(vuln)} vulnerable packages, none used by more than 1 of {len(apps)} applications."], data_used=("app_sboms", "findings"),
                            detail="One vulnerable package spread everywhere is one fix that matters everywhere.", recommendation="Keep SBOMs current."))
        else:
            share = top["weight"] / len(apps)
            st = "fail" if share >= ctx.thr["coverage_partial"] else "partial"
            out.append(_chk("con-package", "concentration", t, st, score=(1 - share) if st == "partial" else None, weight=4, data_used=("app_sboms", "findings"),
                            evidence=[f"{top['label']} is vulnerable and used by {top['weight']} of {len(apps)} applications ({round(100 * share)}%)."],
                            detail="A shared vulnerable dependency is a single point of failure for every application that uses it.",
                            recommendation="Upgrade it once, centrally, and pin the version in a shared dependency policy.",
                            change={"kind": "page", "where": "/dependencies", "key": top["label"], "value": "upgrade", "effect": "Shows every application that uses the package and the upgrade that closes the findings."}))
    urgent = _urgent(ctx)
    inv = _inventory(ctx)
    t = "Urgent findings are not concentrated in one team"
    if len(urgent) < MIN_URGENT or not inv:
        out.append(_unknown("con-team", "concentration", t, f"Only {len(urgent)} urgent findings are recorded, too few to judge concentration (needs {MIN_URGENT}).", ("findings", "asset_ownership", "finding_assignments"),
                            "Ingest scanner findings and record ownership.", weight=3, n=len(urgent)))
    else:
        team_of = {a["name"]: a.get("team") for a in inv}
        by_fid = {a["finding_id"]: a for a in _assignments(ctx) or []}
        counts = {}
        for f in urgent:
            team = (by_fid.get(f.get("id")) or {}).get("assigned_team") or team_of.get(_name(f))
            if team:
                counts[team] = counts.get(team, 0) + 1
        placed = sum(counts.values())
        if placed < MIN_URGENT:
            out.append(_unknown("con-team", "concentration", t, f"Only {placed} of {len(urgent)} urgent findings belong to a team.", ("findings", "asset_ownership", "finding_assignments"),
                                "Record asset owners and teams so concentration can be judged.", weight=3, n=placed))
        else:
            team, n = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
            share = n / placed
            st, sc = ("pass", None) if share <= 0.5 else ("partial", 0.5) if share <= 0.75 else ("fail", None)
            out.append(_chk("con-team", "concentration", t, st, score=sc, weight=3, data_used=("findings", "asset_ownership", "finding_assignments"),
                            evidence=[f"Team {team} holds {n} of {placed} urgent findings with a team ({round(100 * share)}%); {len(counts)} teams hold any."],
                            detail="When one team holds most of the urgent work it is a bottleneck and a single point of failure for remediation.",
                            recommendation="Rebalance, or add capacity to the team listed." if st != "pass" else "Keep watching the balance.",
                            change=None if st == "pass" else {"kind": "page", "where": "/assignments", "key": "team", "value": "rebalanced", "effect": "Reassigns urgent findings across teams."}))
    t = "Urgent findings are not concentrated on one asset"
    if len(urgent) < MIN_URGENT:
        out.append(_unknown("con-asset", "concentration", t, f"Only {len(urgent)} urgent findings are recorded, too few to judge concentration (needs {MIN_URGENT}).", ("findings",), "Ingest scanner findings.", weight=2, n=len(urgent)))
    else:
        counts = {}
        for f in urgent:
            counts[_name(f)] = counts.get(_name(f), 0) + 1
        asset, n = max(counts.items(), key=lambda kv: (kv[1], str(kv[0])))
        share = n / len(urgent)
        st, sc = ("pass", None) if share <= 0.5 else ("partial", 0.5) if share <= 0.75 else ("fail", None)
        out.append(_chk("con-asset", "concentration", t, st, score=sc, weight=2, data_used=("findings",),
                        evidence=[f"{asset} holds {n} of {len(urgent)} urgent findings ({round(100 * share)}%) across {len(counts)} assets."],
                        detail="One asset carrying most urgent risk is a single point of failure: if it falls, much of the risk is realised at once.",
                        recommendation="Treat the asset listed as a priority, or rebuild it." if st != "pass" else "Keep the risk spread understood."))
    return out


# ---------------------------------------------------------------- ownership
def _ownership(ctx):
    out = []
    inv = _inventory(ctx)
    t = "Every asset has an owner or team"
    if not inv:
        out.append(_unknown("own-assets", "ownership", t, "No assets are recorded (no findings carry an asset).", ("findings", "asset_ownership"), "Ingest scanner findings, then record owners on Asset Inventory.", weight=4))
    else:
        owned = [a for a in inv if a.get("owner") or a.get("team")]
        st, sc = _cov(ctx, len(owned), len(inv))
        out.append(_chk("own-assets", "ownership", t, st, score=sc, weight=4, data_used=("findings", "asset_ownership"),
                        evidence=[f"{len(owned)} of {len(inv)} assets have a recorded owner or team ({round(100 * len(owned) / len(inv))}%)."],
                        detail="Without an owner nobody is accountable for the asset's risk.",
                        recommendation="Record an owner and team for each asset." if st != "pass" else "Keep ownership current.",
                        change=None if st == "pass" else {"kind": "page", "where": "/ownership", "key": "owner", "value": "pat.owner@corp.test", "effect": "Records who is accountable for the asset."}))
    t = "Urgent findings have an assignee or team"
    urgent = _urgent(ctx)
    if not ctx.findings:
        out.append(_unknown("own-urgent", "ownership", t, "No findings are recorded.", ("findings", "finding_assignments"), "Ingest scanner findings.", weight=5))
    elif not urgent:
        out.append(_chk("own-urgent", "ownership", t, "na", weight=5, evidence=[f"0 open Critical or known-exploited findings among {len(ctx.findings)} recorded."], data_used=("findings",),
                        detail="Nothing urgent to assign.", recommendation="Keep assigning new urgent findings."))
    else:
        by_fid = {a["finding_id"]: a for a in _assignments(ctx) or []}
        have = [f for f in urgent if (by_fid.get(f.get("id")) or {}).get("assignee_email") or (by_fid.get(f.get("id")) or {}).get("assigned_team")]
        st, sc = _cov(ctx, len(have), len(urgent))
        out.append(_chk("own-urgent", "ownership", t, st, score=sc, weight=5, data_used=("findings", "finding_assignments"),
                        evidence=[f"{len(have)} of {len(urgent)} urgent findings are assigned to a person or team ({round(100 * len(have) / len(urgent))}%)."],
                        detail="An unassigned urgent finding is one nobody has been asked to fix.",
                        recommendation="Assign them, or auto-route from asset ownership." if st != "pass" else "Keep auto-routing on.",
                        change=None if st == "pass" else {"kind": "page", "where": "/assignments", "key": "auto-route", "value": "from asset ownership", "effect": "Assigns findings to the team that owns the asset."}))
    t = "Allow rules have a named owner"
    fw = _firewall(ctx)
    allow = [r for r in (fw or {}).get("rules", []) if r["enabled"] and r["action"] == "allow"]
    if not allow:
        out.append(_unknown("own-rules", "ownership", t, "No enabled allow rules are recorded.", ("fw_rules",), "Import firewall rules on the Firewall page.", weight=3))
    else:
        have = sum(1 for r in allow if r["owner"])
        st, sc = _cov(ctx, have, len(allow))
        out.append(_chk("own-rules", "ownership", t, st, score=sc, weight=3, data_used=("fw_rules",), evidence=[f"{have} of {len(allow)} enabled allow rules name an owner."],
                        detail="A rule with no owner cannot be recertified or removed safely.",
                        recommendation="Record an owner in each rule's tag or comment." if st != "pass" else "Keep recertifying.",
                        change=None if st == "pass" else {"kind": "page", "where": "/firewall", "key": "owner", "value": "pat.owner@corp.test", "effect": "Shows the rules with no owner (FW012)."}))
    return out


# ---------------------------------------------------------------- segmentation
def _segmentation(ctx):
    out = []
    assets = _assets(ctx)
    t = "The network path from the internet is recorded for assets"
    if not assets:
        out.append(_unknown("seg-topology", "segmentation", t, "No assets are recorded.", ("findings", "network_topology.yaml"), "Ingest scanner findings, then fill remediation/config/network_topology.yaml.", weight=3))
    else:
        from remediation.enrichment import network_reachability
        topo = _topology(ctx) or {"assets": []}
        have = sum(1 for n in assets if network_reachability.find_asset_path(n, topo) is not None)
        st, sc = _cov(ctx, have, len(assets))
        out.append(_chk("seg-topology", "segmentation", t, st, score=sc, weight=3, data_used=("findings", "network_topology.yaml"),
                        evidence=[f"{have} of {len(assets)} assets have a path in network_topology.yaml."],
                        detail="An asset with no recorded path has an unknown, not a safe, exposure.", recommendation="Add a path for each asset or group." if st != "pass" else "Keep the topology current.",
                        change=None if st == "pass" else {"kind": "yaml", "where": "remediation/config/network_topology.yaml", "key": "path_to_internet", "value": "the hops, outermost first", "effect": "Lets reachability be traced hop by hop."}))
    fw = _firewall(ctx)
    t = "Firewall rules divide the network into zones"
    if not fw or not fw["rules"]:
        out.append(_unknown("seg-zones", "segmentation", t, "No firewall rules are recorded.", ("fw_rules",), "Import firewall rules on the Firewall page.", weight=4))
    else:
        zones = {z for r in fw["rules"] for z in list(r["src_zones"]) + list(r["dst_zones"]) if z != "any"}
        st, sc = ("pass", None) if len(zones) >= 3 else ("partial", 0.5) if len(zones) == 2 else ("fail", None)
        out.append(_chk("seg-zones", "segmentation", t, st, score=sc, weight=4, data_used=("fw_rules",),
                        evidence=[f"{len(zones)} named zones appear in {len(fw['rules'])} recorded rules" + (f" ({', '.join(sorted(zones)[:5])})." if zones else ".")],
                        detail="A flat network lets an intruder reach everything from the first foothold.", recommendation="Define zones (for example internet, DMZ, application, data, management) and write rules between them." if st != "pass" else "Keep rules zone-specific.",
                        change=None if st == "pass" else {"kind": "page", "where": "/firewall", "key": "zones", "value": "named", "effect": "Shows which rules name no zone."}))
    t = "No rule allows any source to any destination on any service"
    if not fw or not fw["rules"]:
        out.append(_unknown("seg-any-any", "segmentation", t, "No firewall rules are recorded.", ("fw_rules",), "Import firewall rules on the Firewall page.", weight=4))
    else:
        bad = [f for f in fw["finds"] if f["id"] == "FW001"]
        out.append(_chk("seg-any-any", "segmentation", t, "pass" if not bad else "fail", weight=4, data_used=("fw_rules",),
                        evidence=[f"{len(bad)} any-any allow rules among {len(fw['rules'])} recorded."] + [f"{f['device']}/{f['rule']}" for f in bad[:3]],
                        detail="An any-any rule removes segmentation for the zones it names.", recommendation="Replace it with rules for the flows that are needed." if bad else "Keep new rules specific.",
                        change=None if not bad else {"kind": "page", "where": "/firewall", "key": "FW001", "value": "0 open", "effect": "Lists each any-any rule."}))
    return out


# ---------------------------------------------------------------- resilience
def _resilience(ctx):
    out = []
    url = (ctx.env.get("QUANTA_DATABASE_URL") or "").strip()
    scheme = url.split(":", 1)[0].lower() if url else "sqlite (default file)"
    postgres = scheme.startswith("postgres")
    out.append(_chk("res-database", "resilience", "The database is a shared server, not a single file", "pass" if postgres else "fail", weight=5, data_used=("environment",),
                    evidence=[f"Database scheme: {scheme}; 1 database instance is configured." + ("" if postgres else " A SQLite file allows one writer and no second replica.")],
                    detail="A single-file database cannot be shared by several replicas and is lost with its disk.",
                    recommendation="Use a managed PostgreSQL and put its URL in the vault." if not postgres else "Confirm the service has replication and backups.",
                    change=None if postgres else {"kind": "env", "where": "environment", "key": "QUANTA_DATABASE_URL", "value": "postgresql+psycopg2://quanta@db.corp.test/quanta", "effect": "Moves the shared state to PostgreSQL so replicas can share it."}))
    lock, files = (ctx.env.get("QUANTA_LOCK_BACKEND") or "file").strip().lower(), (ctx.env.get("QUANTA_FILES_BACKEND") or "file").strip().lower()
    t = "Replicas coordinate through the database"
    if not postgres:
        out.append(_chk("res-coordination", "resilience", t, "na", weight=3, data_used=("environment",), evidence=[f"Lock backend {lock}, files backend {files}; with a single SQLite file there is 1 instance to coordinate."],
                        detail="Coordination only matters with more than one replica.", recommendation="Move to PostgreSQL first."))
    else:
        n = (lock == "db") + (files == "db")
        st = "pass" if n == 2 else "partial" if n == 1 else "fail"
        out.append(_chk("res-coordination", "resilience", t, st, score=n / 2 if st == "partial" else None, weight=3, data_used=("environment",),
                        evidence=[f"{n} of 2 coordination settings use the database (lock backend: {lock}, files backend: {files})."],
                        detail="With file locks or local files, a second replica works on a different copy.",
                        recommendation="Set both backends to db (Helm: coordination.lockBackend and files.backend)." if st != "pass" else "Keep both on db.",
                        change=None if st == "pass" else {"kind": "env", "where": "environment", "key": "QUANTA_LOCK_BACKEND" if lock != "db" else "QUANTA_FILES_BACKEND", "value": "db", "effect": "Replicas share leases and working files through the database."}))
    has = bool((ctx.env.get("QUANTA_SESSION_SECRET") or "").strip() or (ctx.env.get("QUANTA_SESSION_SECRET_FILE") or "").strip())
    length = len((ctx.env.get("QUANTA_SESSION_SECRET") or "").strip())
    out.append(_chk("res-session-secret", "resilience", "Sessions survive a restart or a second replica", "pass" if has else "fail", weight=3, data_used=("environment",),
                    evidence=[f"A stable session secret is {'set' if has else 'not set'}" + (f" ({length} characters, value not shown)." if length else ".") + f" Settings checked: 2 (QUANTA_SESSION_SECRET, QUANTA_SESSION_SECRET_FILE)."],
                    detail="Without a stable secret every restart signs everyone out and replicas reject each other's sessions.",
                    recommendation="Set a stable random secret from your vault." if not has else "Rotate it on a schedule.",
                    change=None if has else {"kind": "env", "where": "environment", "key": "QUANTA_SESSION_SECRET", "value": "a long random value from your vault", "effect": "Sessions stay valid across restarts and replicas."}))
    out.append(_unknown("res-backups", "resilience", "The database and generated files are backed up and the restore is tested",
                        "Backups happen outside Quanta and cannot be observed from here.", ("environment",),
                        "Back up the database (point-in-time recovery for PostgreSQL), run `quanta-admin backup` for the file state, and test a restore at least yearly; record the test date.", weight=4,
                        change={"kind": "process", "where": "operations runbook", "key": "backup and restore test", "value": "yearly", "effect": "Proves the estate can be rebuilt from backups."}, n=0))
    return out


def run(ctx):
    out = []
    for fn in (_exposure, _concentration, _ownership, _segmentation, _resilience):
        out.extend(fn(ctx))
    return out
