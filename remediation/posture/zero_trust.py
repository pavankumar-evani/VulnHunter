"""CISA Zero Trust Maturity Model 2.0: the five pillars (identity, devices, networks, applications, data) and the three cross-cutting capabilities
(visibility and analytics, automation and orchestration, governance), answered from what Quanta already holds.

Every check reads recorded data only. Nothing recorded means `unknown` (not scored, never a pass); a setting that is simply not set is a fail with the
setting named. No check ever puts a secret in its evidence: environment settings are reported as present or absent.
"""
import datetime
import fnmatch

from remediation.posture import model

FRAMEWORK = {
    "id": "zero-trust",
    "title": "Zero trust (CISA Zero Trust Maturity Model 2.0)",
    "summary": "How far the estate recorded in Quanta has moved from perimeter trust to verifying every user, device, network path, application and piece of data, judged from recorded findings, controls, firewall rules, applications, connections and governance records.",
    "areas": [("identity", "Identity"), ("devices", "Devices"), ("networks", "Networks"), ("applications", "Applications and workloads"), ("data", "Data"),
              ("visibility", "Visibility and analytics"), ("automation", "Automation and orchestration"), ("governance", "Governance")],
    "refs": [{"label": "CISA Zero Trust Maturity Model", "url": "https://www.cisa.gov/zero-trust-maturity-model"},
             {"label": "NIST SP 800-207 Zero Trust Architecture", "url": "https://csrc.nist.gov/pubs/sp/800/207/final"}],
}
FW = FRAMEWORK["id"]
CLOSED = {"resolved", "closed", "fixed", "remediated"}
HOST_TYPES = {"windows-server", "windows-endpoint", "unix-server", "virtualization-host"}
OIDC_VARS = ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URI")


# ---------------------------------------------------------------- helpers
def _chk(cid, area, title, status, **kw):
    return model.check(f"zt-{cid}", FW, area, title, status, refs=FRAMEWORK["refs"], **kw)


def _date(value):
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def _age(ctx, value):
    d = _date(value)
    return (ctx.now.date() - d).days if d else None


def _cov(ctx, ok, total):
    """(status, score) for 'ok of total' against the shared coverage thresholds."""
    share = ok / total
    if share >= ctx.thr["coverage_good"]:
        return "pass", None
    if share >= ctx.thr["coverage_partial"]:
        return "partial", share
    return "fail", None


def _pct(ok, total):
    return f"{round(100 * ok / total)}%"


def _unknown(cid, area, title, why, data_used, recommendation, weight=3, change=None, n=0):
    return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"{why} Records that could answer this: {n}."], recommendation=recommendation, data_used=data_used, change=change,
                detail="Quanta cannot answer this from what is recorded, so it is left out of the score.")


def _open(ctx):
    return [f for f in ctx.findings if str(f.get("status") or "").lower() not in CLOSED]


def _asset_name(f):
    a = f.get("asset") or {}
    return a.get("name") or a.get("hostname")


def _assets(ctx):
    """{asset name: asset dict} from findings."""
    out = {}
    for f in ctx.findings:
        n = _asset_name(f)
        if n and n not in out:
            out[n] = f.get("asset") or {}
    return out


def _controls(ctx):
    from remediation.controls import store
    return ctx.get("controls", lambda: store.list_controls(engine=ctx.engine))


def _covered(rows, name, control_class, states=("verified",)):
    return any(r["control_class"] == control_class and r["state"] in states and fnmatch.fnmatchcase(name.lower(), r["asset_name"].lower()) for r in rows)


def _iam(ctx):
    def load():
        from remediation.iam import model as iam_model, store
        ents, roster = store.entitlements(ctx.engine), store.roster(ctx.engine)
        return {"ents": ents, "roster": roster, "finds": iam_model.analyse(ents, roster, today=ctx.now.date()) if ents else []}
    return ctx.get("iam", load)


def _firewall(ctx):
    def load():
        from remediation.firewall import analysis, store
        rules = store.rules(engine=ctx.engine)
        if not rules:
            return {"rules": [], "finds": [], "exposure": None}
        pol = analysis.policy()
        return {"rules": rules, "finds": analysis.analyse(rules, pol=pol, today=ctx.now.date()), "exposure": analysis.exposure(rules, pol=pol, today=ctx.now.date())}
    return ctx.get("firewall", load)


def _topology(ctx):
    from remediation.enrichment import network_reachability
    return ctx.get("topology", lambda: network_reachability.load_topology())


def _connections(ctx):
    from remediation.connections import store
    return ctx.get("connections", lambda: store.list_connections(ctx.engine))


# ---------------------------------------------------------------- identity
def _identity(ctx):
    out = []
    data = _iam(ctx)
    t = "People who have left have no access"
    uses = ("iam_entitlements", "iam_roster")
    rec = "Import the identity provider export and the HR roster on the Access Governance page so leavers with access can be found."
    if not data or not data["ents"]:
        out.append(_unknown("id-leavers", "identity", t, "No entitlements are recorded.", uses, rec, weight=5))
    elif not data["roster"]:
        out.append(_unknown("id-leavers", "identity", t, f"{len(data['ents'])} entitlements are recorded but no HR roster, so leavers cannot be identified.", uses, rec, weight=5, n=0))
    else:
        leavers = [f for f in data["finds"] if f["id"] == "IAM001"]
        ev = [f"{len(leavers)} of {len(data['ents'])} entitlements belong to people the roster marks as gone ({len(data['roster'])} people in the roster)."]
        ev += [f"{f['user']}: {f['entitlement']} on {f['system']}" for f in leavers[:3]]
        out.append(_chk("id-leavers", "identity", t, "pass" if not leavers else "fail", weight=5, evidence=ev, data_used=uses,
                        detail="A leaver who still has access is the clearest break of 'verify every access request'.",
                        recommendation="Disable the accounts listed and remove the entitlements; review their activity since the leaving date." if leavers else "Keep importing the roster so this stays current.",
                        change={"kind": "page", "where": "/access-governance", "key": "IAM001", "value": "0 open", "effect": "Shows each leaver who still holds access so it can be removed."} if leavers else None))

    t = "Dormant, shared and conflicting access is controlled"
    rec = "Import entitlements on the Access Governance page."
    if not data or not data["ents"]:
        out.append(_unknown("id-hygiene", "identity", t, "No entitlements are recorded.", uses, rec))
    else:
        people = {e["user"] for e in data["ents"]}
        bad = {f["user"] for f in data["finds"] if f["id"] in ("IAM002", "IAM005", "IAM006")}
        by = {r: sum(1 for f in data["finds"] if f["id"] == r) for r in ("IAM002", "IAM005", "IAM006")}
        st, sc = _cov(ctx, len(people) - len(bad), len(people))
        out.append(_chk("id-hygiene", "identity", t, st, score=sc, weight=4, data_used=uses,
                        evidence=[f"{len(bad)} of {len(people)} people have a dormant account ({by['IAM002']}), a separation-of-duties conflict ({by['IAM005']}) or an unowned shared account ({by['IAM006']})."],
                        detail="Dormant, shared and conflicting access is standing privilege that zero trust tries to remove.",
                        recommendation="Run an access review campaign and remove or justify each item." if bad else "Keep the periodic access review running.",
                        change={"kind": "page", "where": "/access-governance", "key": "campaign", "value": "quarterly", "effect": "Managers confirm or revoke each entitlement."} if bad else None))

    present = [v for v in OIDC_VARS if (ctx.env.get(v) or "").strip()]
    st = "pass" if len(present) == len(OIDC_VARS) else "partial" if present else "fail"
    out.append(_chk("id-sso", "identity", "Single sign-on is configured", st, score=len(present) / len(OIDC_VARS) if st == "partial" else None, weight=4, data_used=("environment",),
                    evidence=[f"{len(present)} of {len(OIDC_VARS)} OIDC settings are set ({', '.join(v for v in OIDC_VARS if v not in present) or 'none missing'})."],
                    detail="Local passwords are a weaker identity signal than a central identity provider with MFA and conditional access.",
                    recommendation="Set all four OIDC settings to enable single sign-on." if st != "pass" else "Keep local accounts to a break-glass minimum.",
                    change={"kind": "env", "where": "environment", "key": "OIDC_ISSUER", "value": "https://login.corp.test/", "effect": "Shows the Sign in with SSO button; set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI with it."} if st != "pass" else None))

    def load_users():
        from sqlalchemy import select
        from remediation.utils import db as db_module
        engine = ctx.engine or db_module.get_engine()
        db_module.ensure_schema(engine)
        with engine.connect() as conn:
            return [dict(r) for r in conn.execute(select(db_module.users.c.email, db_module.users.c.role)).mappings().all()]
    users = ctx.get("users", load_users)
    if not users:
        out.append(_unknown("id-admins", "identity", "Few accounts hold the administrator role", "No local accounts are recorded.", ("users",), "Create accounts, or use SSO.", weight=2))
    else:
        admins = [u for u in users if u["role"] == "admin"]
        ok = len(admins) <= max(2, round(0.2 * len(users)))
        out.append(_chk("id-admins", "identity", "Few accounts hold the administrator role", "pass" if ok else "fail", weight=2, data_used=("users",),
                        evidence=[f"{len(admins)} of {len(users)} local accounts are administrators."],
                        detail="Administrator is a standing high privilege; zero trust keeps it to the smallest group that can do the work.",
                        recommendation="Keep administrators to a few named people." if ok else "Demote accounts that do not need administrator rights.",
                        change=None if ok else {"kind": "page", "where": "/admin/people", "key": "role", "value": "user", "effect": "Removes administrator rights from the account."}))
    return out


# ---------------------------------------------------------------- devices
def _devices(ctx):
    out = []
    from remediation.inventory import asset_inventory
    assets = _assets(ctx)
    inv = ctx.get("inventory", lambda: asset_inventory.build_asset_inventory(ctx.findings, ownership=asset_inventory.load_ownership(ctx.engine))) if assets else None
    t = "Every device has an accountable owner"
    if not inv:
        out.append(_unknown("dev-owners", "devices", t, "No assets are recorded (no findings carry an asset).", ("findings", "asset_ownership"), "Ingest scanner findings, then record owners on Asset Inventory.", weight=4))
    else:
        owned = sum(1 for a in inv if a.get("owner") or a.get("team"))
        st, sc = _cov(ctx, owned, len(inv))
        out.append(_chk("dev-owners", "devices", t, st, score=sc, weight=4, data_used=("findings", "asset_ownership"),
                        evidence=[f"{owned} of {len(inv)} assets have a recorded owner or team ({_pct(owned, len(inv))})."],
                        detail="Without an owner nobody answers for the device's posture.",
                        recommendation="Record an owner and team for each asset." if st != "pass" else "Keep ownership current as assets change.",
                        change=None if st == "pass" else {"kind": "page", "where": "/ownership", "key": "owner", "value": "pat.owner@corp.test", "effect": "Records who is accountable for the asset."}))

    t = "Hosts have verified endpoint protection"
    rows = _controls(ctx)
    hosts = [n for n, a in assets.items() if a.get("type") in HOST_TYPES]
    if not rows or not hosts:
        out.append(_unknown("dev-edr", "devices", t, "No controls are recorded." if not rows else "No server or endpoint assets are recorded.", ("asset_controls", "findings"),
                            "Record endpoint protection per asset on the Controls page, or push it from your EDR with a controls:write key.", weight=5))
    else:
        verified = sum(1 for n in hosts if _covered(rows, n, "edr"))
        claimed = sum(1 for n in hosts if not _covered(rows, n, "edr") and _covered(rows, n, "edr", ("claimed",)))
        st, sc = _cov(ctx, verified, len(hosts))
        out.append(_chk("dev-edr", "devices", t, st, score=sc, weight=5, data_used=("asset_controls", "findings"),
                        evidence=[f"{verified} of {len(hosts)} hosts have a verified endpoint protection control; {claimed} more are only claimed."],
                        detail="Zero trust needs a device health signal that a person's claim does not replace.",
                        recommendation="Have the EDR push its state to Quanta so claimed controls become verified." if st != "pass" else "Keep the EDR feed running.",
                        change=None if st == "pass" else {"kind": "page", "where": "/controls", "key": "edr", "value": "verified", "effect": "Records the endpoint protection state per asset."}))

    t = "Devices run supported operating systems"
    from remediation.enrichment.eol_lookup import classify_eol
    known = [(n, classify_eol(a.get("os"), as_of=ctx.now.date())) for n, a in sorted(assets.items()) if a.get("os")]
    known = [(n, c) for n, c in known if c["status"] != "unknown"]
    if not known:
        out.append(_unknown("dev-eol", "devices", t, "No asset records an operating system that Quanta can date.", ("findings",), "Make sure scanner exports carry the operating system.", weight=3))
    else:
        eol = [n for n, c in known if c["status"] == "eol"]
        st, sc = _cov(ctx, len(known) - len(eol), len(known))
        out.append(_chk("dev-eol", "devices", t, st, score=sc, weight=3, data_used=("findings",),
                        evidence=[f"{len(eol)} of {len(known)} dated operating systems are past end of life."] + [f"End of life: {n}" for n in eol[:3]],
                        detail="An unsupported system receives no security fixes, so no device trust signal about it can be strong.",
                        recommendation="Upgrade or isolate the systems listed." if eol else "Keep checking support dates as new assets arrive."))
    return out


# ---------------------------------------------------------------- networks
def _networks(ctx):
    out = []
    fw = _firewall(ctx)
    uses = ("fw_rules",)
    t = "No rule exposes the internet to risky services"
    if not fw or not fw["rules"]:
        out.append(_unknown("net-firewall", "networks", t, "No firewall rules are recorded.", uses, "Import firewall rules on the Firewall page.", weight=5))
    else:
        bad = [f for f in fw["finds"] if f["id"] in ("FW001", "FW002", "FW003")]
        ev = [f"{len(bad)} rules allow any-any or expose risky services to the internet; {len(fw['rules'])} rules are recorded."]
        ev += [f"{f['device']}/{f['rule']}: {f['id']} {f['title']}" for f in bad[:3]]
        out.append(_chk("net-firewall", "networks", t, "pass" if not bad else "fail", weight=5, evidence=ev, data_used=uses,
                        detail="Allowing the internet to reach management or database ports, or any-any, is implicit trust in the network.",
                        recommendation="Remove the exposure or restrict the source to known addresses or a VPN." if bad else "Keep reviewing rules after every change.",
                        change=None if not bad else {"kind": "page", "where": "/firewall", "key": "FW002", "value": "0 open", "effect": "Lists each exposed rule with the fix."}))
    t = "Firewall rules are logged, owned, used and current"
    if not fw or not fw["rules"]:
        out.append(_unknown("net-hygiene", "networks", t, "No firewall rules are recorded.", uses, "Import firewall rules on the Firewall page.", weight=3))
    else:
        allow = [r for r in fw["rules"] if r["enabled"] and r["action"] == "allow"]
        dirty = {f["rule_key"] for f in fw["finds"] if f["id"] in ("FW007", "FW008", "FW012", "FW013")}
        if not allow:
            out.append(_unknown("net-hygiene", "networks", t, "No enabled allow rules are recorded.", uses, "Import firewall rules on the Firewall page.", weight=3))
        else:
            clean = sum(1 for r in allow if r["key"] not in dirty)
            st, sc = _cov(ctx, clean, len(allow))
            out.append(_chk("net-hygiene", "networks", t, st, score=sc, weight=3, evidence=[f"{clean} of {len(allow)} enabled allow rules are logged, owned, used and unexpired ({_pct(clean, len(allow))})."], data_used=uses,
                            detail="Rules nobody owns or that never log cannot be verified.",
                            recommendation="Recertify the rules with findings FW007, FW008, FW012 and FW013." if st != "pass" else "Keep the recertification cycle running.",
                            change=None if st == "pass" else {"kind": "page", "where": "/firewall", "key": "recertify", "value": "quarterly", "effect": "Owners confirm or remove each rule."}))
    t = "The network path from the internet is recorded for assets"
    assets = _assets(ctx)
    topo = _topology(ctx) if assets else None
    if not assets:
        out.append(_unknown("net-topology", "networks", t, "No assets are recorded.", ("findings", "network_topology.yaml"), "Ingest scanner findings, then fill remediation/config/network_topology.yaml.", weight=3))
    else:
        from remediation.enrichment import network_reachability
        have = sum(1 for n in assets if network_reachability.find_asset_path(n, topo or {"assets": []}) is not None)
        st, sc = _cov(ctx, have, len(assets))
        out.append(_chk("net-topology", "networks", t, st, score=sc, weight=3, evidence=[f"{have} of {len(assets)} assets have a path to the internet in network_topology.yaml."], data_used=("findings", "network_topology.yaml"),
                        detail="An asset with no recorded path has an unknown, not a safe, exposure.",
                        recommendation="Add a path for each asset or group of assets." if st != "pass" else "Keep the topology current.",
                        change=None if st == "pass" else {"kind": "yaml", "where": "remediation/config/network_topology.yaml", "key": "assets", "value": "a match and a path_to_internet", "effect": "Lets reachability be traced hop by hop."}))
    t = "Allow rules are limited to named zones"
    if not fw or not fw["rules"]:
        out.append(_unknown("net-segmentation", "networks", t, "No firewall rules are recorded.", uses, "Import firewall rules on the Firewall page.", weight=4))
    else:
        allow = [r for r in fw["rules"] if r["enabled"] and r["action"] == "allow"]
        if not allow:
            out.append(_unknown("net-segmentation", "networks", t, "No enabled allow rules are recorded.", uses, "Import firewall rules on the Firewall page.", weight=4))
        else:
            seg = sum(1 for r in allow if "any" not in r["src_zones"] and "any" not in r["dst_zones"])
            st, sc = _cov(ctx, seg, len(allow))
            out.append(_chk("net-segmentation", "networks", t, st, score=sc, weight=4, evidence=[f"{seg} of {len(allow)} enabled allow rules name both a source and a destination zone."], data_used=uses,
                            detail="Rules that span 'any' zone do not enforce micro-segmentation.",
                            recommendation="Name the zones on every allow rule." if st != "pass" else "Keep new rules zone-specific.",
                            change=None if st == "pass" else {"kind": "page", "where": "/firewall", "key": "zones", "value": "named", "effect": "Shows which rules cross any zone."}))
    return out


# ---------------------------------------------------------------- applications
def _applications(ctx):
    out = []
    from remediation.appsec import store
    apps = ctx.get("apps", lambda: store.list_applications(ctx.engine))
    sboms = ctx.get("sboms", lambda: store.sbom_summaries(ctx.engine)) if apps else {}
    t = "Applications have a current software bill of materials"
    if not apps:
        out.append(_unknown("app-sbom", "applications", t, "No applications are registered.", ("applications", "app_sboms"), "Register applications and upload an SBOM for each (Applications page, or POST /api/ingest/sbom from CI).", weight=4))
    else:
        limit = ctx.thr.get("min_sbom_age_days", 90)
        fresh = [a for a in apps if a["name"] in sboms and (_age(ctx, sboms[a["name"]]["uploaded_at"]) or 0) <= limit]
        net = [a for a in apps if a.get("internet_facing")]
        net_ok = sum(1 for a in net if a in fresh)
        st, sc = _cov(ctx, len(fresh), len(apps))
        out.append(_chk("app-sbom", "applications", t, st, score=sc, weight=4, data_used=("applications", "app_sboms"),
                        evidence=[f"{len(fresh)} of {len(apps)} applications have an SBOM under {limit} days old; {net_ok} of {len(net)} internet-facing ones do."],
                        detail="Without an inventory of components a vulnerable library cannot be traced to the workloads that run it.",
                        recommendation="Upload an SBOM for each application from CI." if st != "pass" else "Keep CI uploading an SBOM on each release.",
                        change=None if st == "pass" else {"kind": "page", "where": "/applications", "key": "sbom", "value": "uploaded", "effect": "Stores the component inventory for the application."}))
    t = "Internet-facing applications carry no open Critical findings"
    net = [a for a in apps or [] if a.get("internet_facing")]
    if not net or not ctx.findings:
        out.append(_unknown("app-critical", "applications", t, "No application is marked internet-facing." if not net else "No findings are recorded.", ("applications", "findings"),
                            "Mark internet-facing applications on the Applications page and ingest scanner findings.", weight=5))
    else:
        names = {store.norm(a["name"]): a["name"] for a in net}
        hits = [f for f in _open(ctx) if str(f.get("severity")) == "Critical" and store.norm(_asset_name(f)) in names]
        ev = [f"{len(hits)} open Critical findings on {len(net)} internet-facing applications."] + [f"{f.get('id')}: {f.get('title')}" for f in hits[:3]]
        out.append(_chk("app-critical", "applications", t, "pass" if not hits else "fail", weight=5, evidence=ev, data_used=("applications", "findings"),
                        detail="Internet-facing workloads are reached first, so a Critical flaw there is the most urgent.",
                        recommendation="Fix or mitigate the Critical findings on these applications first." if hits else "Keep these applications on the fastest remediation lane.",
                        change=None if not hits else {"kind": "page", "where": "/queue", "key": "severity", "value": "Critical", "effect": "Lists the findings to fix first."}))
    t = "API endpoints declare authentication"
    eps = ctx.get("endpoints", lambda: __import__("remediation.apisec.store", fromlist=["list_endpoints"]).list_endpoints(ctx.engine))
    spec = [e for e in eps or [] if e["in_spec"] and e.get("spec")]
    if not spec:
        out.append(_unknown("app-api-auth", "applications", t, "No API specification is recorded.", ("api_endpoints",), "Upload an OpenAPI specification on the API Security page.", weight=4))
    else:
        open_ = [e for e in spec if e["spec"].get("auth_state") == "none"]
        st, sc = _cov(ctx, len(spec) - len(open_), len(spec))
        out.append(_chk("app-api-auth", "applications", t, st, score=sc, weight=4, data_used=("api_endpoints",),
                        evidence=[f"{len(open_)} of {len(spec)} specified endpoints are declared open with no authentication."] + [f"{e['method']} {e['template']}" for e in open_[:3]],
                        detail="Some endpoints (health checks) are public on purpose; each one should be a decision, not a default.",
                        recommendation="Require authentication, or record why the endpoint is public." if open_ else "Keep specifications current.",
                        change=None if not open_ else {"kind": "page", "where": "/api-security", "key": "auth", "value": "required", "effect": "Shows each open endpoint with its OWASP API risk."}))
    return out


# ---------------------------------------------------------------- data
def _data(ctx):
    out = []
    from remediation.apisec import classify, store
    classes = ctx.get("api_classes", lambda: store.list_classes(ctx.engine))
    t = "A data classification is recorded"
    if not classes:
        out.append(_unknown("data-classes", "data", t, "No data classification is imported.", ("api_data_classes",), "Import your classification on the API Security page so detected data can be mapped to it.", weight=3))
    else:
        out.append(_chk("data-classes", "data", t, "pass", weight=3, evidence=[f"{len(classes)} data classes are imported."], data_used=("api_data_classes",),
                        detail="Zero trust protects data by what it is, so the classes must exist before they can drive policy.", recommendation="Review the classes yearly."))
    t = "Sensitive data seen in APIs is mapped to a class"
    eps = ctx.get("endpoints", lambda: store.list_endpoints(ctx.engine))
    seen = {}
    for e in eps or []:
        for det, n in ((e.get("obs") or {}).get("detected") or {}).items():
            seen[det] = seen.get(det, 0) + n
    if not seen:
        out.append(_unknown("data-unclassified", "data", t, "No sensitive data has been observed in API traffic.", ("api_endpoints",), "Import gateway or access logs on the API Security page.", weight=4))
    else:
        mapped = [d for d in seen if classes and classify.class_of(d, [], classes)]
        st, sc = _cov(ctx, len(mapped), len(seen))
        out.append(_chk("data-unclassified", "data", t, st, score=sc, weight=4, data_used=("api_endpoints", "api_data_classes"),
                        evidence=[f"{len(mapped)} of {len(seen)} kinds of sensitive data seen in traffic map to one of {len(classes or [])} classes."],
                        detail="Unmapped data is unclassified, never assumed safe.",
                        recommendation="Map each detected kind to a class." if st != "pass" else "Keep the mapping current.",
                        change=None if st == "pass" else {"kind": "page", "where": "/api-security", "key": "classification", "value": "mapped", "effect": "Maps detected data to your classes."}))
    t = "Assets that hold findings have verified encryption"
    rows = _controls(ctx)
    assets = list(_assets(ctx))
    if not rows or not assets:
        out.append(_unknown("data-encryption", "data", t, "No controls are recorded." if not rows else "No assets are recorded.", ("asset_controls", "findings"), "Record encryption controls on the Controls page.", weight=3))
    else:
        ok = sum(1 for n in assets if _covered(rows, n, "encryption"))
        st, sc = _cov(ctx, ok, len(assets))
        out.append(_chk("data-encryption", "data", t, st, score=sc, weight=3, data_used=("asset_controls", "findings"),
                        evidence=[f"{ok} of {len(assets)} assets have a verified encryption control."], detail="Encryption at rest and in transit limits what a compromised network position can read.",
                        recommendation="Record verified encryption per asset." if st != "pass" else "Keep the controls feed current.",
                        change=None if st == "pass" else {"kind": "page", "where": "/controls", "key": "encryption", "value": "verified", "effect": "Records encryption state per asset."}))
    return out


# ---------------------------------------------------------------- visibility
def _visibility(ctx):
    out = []
    conns = _connections(ctx)
    t = "Scanner and SIEM connections are working"
    from remediation.connections import registry
    mine = [c for c in conns or [] if c["enabled"] and ((registry.SPECS.get(c["type"]) or {}).get("pull") or (registry.SPECS.get(c["type"]) or {}).get("category") == "SIEM / logging")]
    if not mine:
        out.append(_unknown("vis-connections", "visibility", t, "No enabled scanner or SIEM connection is recorded.", ("connections",), "Add a scanner on the Connections page.", weight=4))
    else:
        limit = ctx.thr["stale_days"]
        ok = [c for c in mine if c.get("last_status") == "ok" and (_age(ctx, c.get("last_run_at")) is not None and _age(ctx, c["last_run_at"]) <= limit)]
        st, sc = _cov(ctx, len(ok), len(mine))
        out.append(_chk("vis-connections", "visibility", t, st, score=sc, weight=4, data_used=("connections",),
                        evidence=[f"{len(ok)} of {len(mine)} enabled connections succeeded within {limit} days."] + [f"Not healthy: {c['name']} ({c.get('last_status') or 'never run'})" for c in mine if c not in ok][:3],
                        detail="A connection that stopped reporting is a blind spot.", recommendation="Fix or re-run the failing connections." if st != "pass" else "Keep monitoring sync status."))
    t = "Security alerts are arriving"
    alerts = ctx.get("alerts", lambda: __import__("remediation.hunting.store", fromlist=["list_alerts"]).list_alerts(ctx.engine))
    if not alerts:
        out.append(_unknown("vis-alerts", "visibility", t, "No alert has ever been received.", ("soc_alerts",), "Point your SIEM or EDR at POST /api/ingest/alerts.", weight=4))
    else:
        newest = min(_age(ctx, a["received_at"]) for a in alerts if _age(ctx, a["received_at"]) is not None)
        ok = newest <= ctx.thr["stale_days"]
        out.append(_chk("vis-alerts", "visibility", t, "pass" if ok else "fail", weight=4, data_used=("soc_alerts",),
                        evidence=[f"{len(alerts)} alerts recorded; the newest arrived {newest} days ago (limit {ctx.thr['stale_days']})."],
                        detail="Analytics need a steady feed.", recommendation="Check the alert feed." if not ok else "Keep the feed monitored."))
    t = "Findings are fresh"
    seen = [f for f in ctx.findings if _date(f.get("last_seen"))]
    if not seen:
        out.append(_unknown("vis-freshness", "visibility", t, "No finding carries a last-seen date.", ("findings",), "Ingest scanner results regularly.", weight=3))
    else:
        limit = ctx.thr["stale_days"]
        ok = sum(1 for f in seen if _age(ctx, f["last_seen"]) <= limit)
        st, sc = _cov(ctx, ok, len(seen))
        out.append(_chk("vis-freshness", "visibility", t, st, score=sc, weight=3, data_used=("findings",),
                        evidence=[f"{ok} of {len(seen)} findings were seen by a scan within {limit} days."], detail="Stale findings mean the estate is not being observed.",
                        recommendation="Schedule scanner syncs." if st != "pass" else "Keep scans scheduled.",
                        change=None if st == "pass" else {"kind": "page", "where": "/connections", "key": "schedule_minutes", "value": "1440", "effect": "Runs the scanner sync daily."}))
    return out


# ---------------------------------------------------------------- automation
def _automation(ctx):
    out = []
    conns = _connections(ctx)
    from remediation.connections import registry
    pulls = [c for c in conns or [] if c["enabled"] and (registry.SPECS.get(c["type"]) or {}).get("pull")]
    t = "Scanner syncs run on a schedule"
    if not pulls:
        out.append(_unknown("auto-sync", "automation", t, "No enabled pull connection is recorded.", ("connections",), "Add a scanner on the Connections page.", weight=3))
    else:
        sched = [c for c in pulls if (c.get("schedule_minutes") or 0) > 0]
        st, sc = _cov(ctx, len(sched), len(pulls))
        out.append(_chk("auto-sync", "automation", t, st, score=sc, weight=3, data_used=("connections",),
                        evidence=[f"{len(sched)} of {len(pulls)} enabled pull connections have a schedule."], detail="Manual syncs lapse; zero trust needs continuous signals.",
                        recommendation="Set a schedule on each connection." if st != "pass" else "Keep schedules in place.",
                        change=None if st == "pass" else {"kind": "page", "where": "/connections", "key": "schedule_minutes", "value": "1440", "effect": "Runs the sync daily."}))
    t = "Response playbooks exist and gate destructive steps"
    pbs = ctx.get("playbooks", lambda: __import__("remediation.soar.playbooks", fromlist=["list_all"]).list_all(ctx.engine))
    if not pbs:
        out.append(_unknown("auto-playbooks", "automation", t, "No response playbook is recorded.", ("soar_playbooks",), "Create a playbook on the SOAR page.", weight=3))
    else:
        on = [p for p in pbs if p["enabled"]]
        gated = sum(1 for p in on if any(s.get("type") == "request-approval" for s in p["steps"]))
        out.append(_chk("auto-playbooks", "automation", t, "pass" if on else "fail", weight=3, data_used=("soar_playbooks",),
                        evidence=[f"{len(on)} of {len(pbs)} playbooks are enabled; {gated} include an approval step."], detail="Playbooks that change the environment need an approval step by design.",
                        recommendation="Enable at least one playbook." if not on else "Review playbooks yearly."))
    return out


# ---------------------------------------------------------------- governance
def _governance(ctx):
    out = []
    t = "Risk exceptions have not run past expiry"
    from remediation.exceptions import store as ex
    items = ctx.get("exceptions", lambda: ex.list_exceptions_with_status(ctx.engine, as_of=ctx.now.date()))
    if not items:
        out.append(_unknown("gov-exceptions", "governance", t, "No exception is recorded.", ("exceptions",), "Record accepted risks as exceptions with an expiry.", weight=3))
    else:
        live = [e for e in items if e["computed_status"] != "revoked"]
        expired = [e for e in live if e["computed_status"] == "expired"]
        if not live:
            out.append(_unknown("gov-exceptions", "governance", t, "Every recorded exception was revoked.", ("exceptions",), "Record accepted risks as exceptions with an expiry.", weight=3))
        else:
            st, sc = _cov(ctx, len(live) - len(expired), len(live))
            out.append(_chk("gov-exceptions", "governance", t, st, score=sc, weight=3, data_used=("exceptions",),
                            evidence=[f"{len(expired)} of {len(live)} exceptions are past their expiry date and not revoked or renewed."], detail="An expired waiver is an unreviewed risk acceptance.",
                            recommendation="Renew or revoke the expired exceptions." if expired else "Keep reviewing exceptions before they expire.",
                            change=None if not expired else {"kind": "page", "where": "/exceptions", "key": "status", "value": "revoked", "effect": "Revokes the exception so the finding is back in the queue."}))
    t = "Active policies are reviewed on time"
    pols = ctx.get("policies", lambda: __import__("remediation.grc.policies", fromlist=["list_policies"]).list_policies(ctx.engine))
    act = [p for p in pols or [] if p["status"] == "active"]
    if not act:
        out.append(_unknown("gov-policies", "governance", t, "No active policy is recorded.", ("grc_policies",), "Record policies on the GRC page.", weight=3))
    else:
        late = [p for p in act if p["review_date"] and p["review_date"] < ctx.now.date().isoformat()]
        undated = [p for p in act if not p["review_date"]]
        ok = len(act) - len(late) - len(undated)
        st, sc = _cov(ctx, ok, len(act))
        out.append(_chk("gov-policies", "governance", t, st, score=sc, weight=3, data_used=("grc_policies",),
                        evidence=[f"{ok} of {len(act)} active policies are within their review date; {len(late)} are overdue and {len(undated)} have no review date."], detail="A policy nobody reviews drifts from practice.",
                        recommendation="Set and meet a review date on each policy." if st != "pass" else "Keep reviewing on schedule.",
                        change=None if st == "pass" else {"kind": "page", "where": "/grc", "key": "review_date", "value": "2027-01-31", "effect": "Sets when the policy is next reviewed."}))
    t = "The risk register is reviewed"
    risks = ctx.get("risks", lambda: __import__("remediation.grc.risks", fromlist=["list_risks"]).list_risks(ctx.engine, include_closed=False))
    if not risks:
        out.append(_unknown("gov-risks", "governance", t, "No risk is recorded.", ("grc_risks",), "Add risks on the GRC page.", weight=3))
    else:
        today = ctx.now.date().isoformat()
        late = [r for r in risks if r["review_date"] and r["review_date"] < today]
        undated = [r for r in risks if not r["review_date"]]
        ok = len(risks) - len(late) - len(undated)
        st, sc = _cov(ctx, ok, len(risks))
        out.append(_chk("gov-risks", "governance", t, st, score=sc, weight=3, data_used=("grc_risks",),
                        evidence=[f"{ok} of {len(risks)} open risks are within their review date; {len(late)} overdue, {len(undated)} undated."], detail="A register not reviewed stops reflecting the estate.",
                        recommendation="Give every risk a review date and meet it." if st != "pass" else "Keep the review cadence.",
                        change=None if st == "pass" else {"kind": "page", "where": "/grc", "key": "review_date", "value": "2027-01-31", "effect": "Schedules the risk review."}))
    return out


def run(ctx):
    out = []
    for fn in (_identity, _devices, _networks, _applications, _data, _visibility, _automation, _governance):
        out.extend(fn(ctx))
    return out
