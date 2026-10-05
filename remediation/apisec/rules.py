"""
OWASP API Security Top 10 (2023) rules, applied to the inventory, the traffic aggregates, your data-classification framework and the protection policies.

Deterministic and explicit: each rule names the observation it needs and the threshold (remediation/config/api_security.yaml). A finding carries an EVIDENCE CHAIN, the
ordered observations that led to it with where each came from (specification, traffic, classification, policy), and, where a request can confirm it, a REPRODUCIBLE
REQUEST as a cURL command built from placeholders ($TOKEN, $OTHER_OBJECT_ID) so a developer can confirm a true or false positive against a system they are
authorised to test. A rule that lacks the data it needs raises nothing: a gap is listed instead, never a pass and never a guess.

Honest limits: these are INDICATORS from records. "Possible object enumeration" is a caller walking many object ids; it does not prove authorization is missing. The rules do
not send any request themselves. Built against the OWASP API Security Top 10 2023 text; not run against a live traffic source.
"""
import datetime
import re
from urllib.parse import urlsplit

from remediation.apisec import classify, config, paths, policies

OWASP = {
    "API1:2023": "Broken Object Level Authorization", "API2:2023": "Broken Authentication", "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption", "API5:2023": "Broken Function Level Authorization", "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery", "API8:2023": "Security Misconfiguration", "API9:2023": "Improper Inventory Management", "API10:2023": "Unsafe Consumption of APIs",
}
CWE = {"API1:2023": ["CWE-639"], "API2:2023": ["CWE-287"], "API3:2023": ["CWE-213", "CWE-915"], "API4:2023": ["CWE-770"], "API5:2023": ["CWE-285"], "API6:2023": ["CWE-799"],
       "API7:2023": ["CWE-918"], "API8:2023": ["CWE-16"], "API9:2023": ["CWE-1059"], "API10:2023": ["CWE-20"]}
LEVELS = ["Low", "Medium", "High", "Critical"]
SEV_WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
FIX = {
    "API1:2023": "Check, on the server and for every request, that the caller is allowed to access the specific object id in the request (not only that they are logged in). Use unguessable ids as defence in depth, not as the control.",
    "API2:2023": "Require authentication on every non-public endpoint with a standard mechanism; validate token signature, algorithm, expiry, issuer and audience on the server; never accept unsigned tokens; keep credentials out of URLs.",
    "API3:2023": "Return only the properties the caller needs by using an explicit response model, and bind only an allow-list of properties from the request so a caller cannot set role, price or ownership fields.",
    "API4:2023": "Apply rate limits and quotas per caller and per endpoint, cap page sizes and response size, and put a limit in front of expensive operations.",
    "API5:2023": "Deny by default: check the caller's role or scope for every function, especially administrative paths and state-changing methods, and do not expose administrative endpoints on the public interface.",
    "API6:2023": "Identify the business flows that can be abused by automation (sign-up, login, checkout, reset, redeem) and add per-caller limits, bot or device checks and anomaly alerts to those flows.",
    "API7:2023": "Do not fetch URLs supplied by callers; if unavoidable, allow-list destinations, block internal and metadata address ranges, disable redirects, and return no raw response.",
    "API8:2023": "Serve APIs only over TLS, remove credentials from URLs, restrict cross-origin access, and keep error responses free of internal detail.",
    "API9:2023": "Keep one authoritative inventory: document every endpoint, name an owner, retire deprecated and superseded versions, and review shadow endpoints found in traffic.",
    "API10:2023": "Treat data from third-party APIs as untrusted: validate it, enforce TLS and timeouts, limit what is forwarded, and review what sensitive data is sent out.",
}


def sev(base, plus=0):
    return LEVELS[max(0, min(3, LEVELS.index(base) + plus))]


def _today(today):
    return today or datetime.date.today()


# ---------------------------------------------------------------- the view of one endpoint
def _re_any(patterns, text):
    return next((p for p in patterns if re.search(p, text, re.I)), None)


def view(ep, classes, has_spec, cfg, policy_list=(), today=None):
    """Everything the rules need to know about one endpoint, derived, with the reason for each derived value."""
    today = _today(today)
    obs, spec = ep["obs"], ep.get("spec") or {}
    pat = cfg["patterns"]
    v = {"id": ep["id"], "service": ep["service"], "method": ep["method"], "template": ep["template"], "path_key": ep["path_key"], "owner": ep["owner"], "status": ep["status"],
         "in_spec": ep["in_spec"], "observed": ep["observed"], "calls": ep["calls_total"], "first_seen": ep["first_seen"], "last_seen": ep["last_seen"], "notes": ep["notes"]}
    v["state"] = "documented" if ep["in_spec"] and ep["observed"] else "spec-only" if ep["in_spec"] else ("shadow" if has_spec else "undocumented")
    # exposure
    if ep["exposure_override"]:
        v["exposure"], v["exposure_basis"] = ep["exposure_override"], "set by a person"
    elif obs["external_calls"]:
        v["exposure"], v["exposure_basis"] = "external", f"{obs['external_calls']:,} call(s) from public addresses"
    elif spec.get("exposure_hint") in ("external", "internal", "partner"):
        v["exposure"], v["exposure_basis"] = spec["exposure_hint"], "the specification says so (x-exposure)"
    elif obs["internal_calls"]:
        v["exposure"], v["exposure_basis"] = "internal", f"only private addresses seen ({obs['internal_calls']:,} calls)"
    else:
        v["exposure"], v["exposure_basis"] = "unknown", "no client addresses in the data"
    # authentication
    mech = sorted(k for k in obs["auth_counts"] if k != "none")
    none_n = obs["auth_counts"].get("none", 0)
    v["auth_mechanisms"] = mech or (spec.get("auth") or [])
    if obs["unauth_success"]:
        v["auth_state"] = "open-observed"
    elif spec.get("auth_state") == "none" and not mech:
        v["auth_state"] = "open-declared"
    elif mech or spec.get("auth_state") == "declared":
        v["auth_state"] = "authenticated"
    else:
        v["auth_state"] = "unknown"
    v["unauth_calls"] = obs["unauth_success"]
    v["auth_none_calls"] = none_n
    v["public_path"] = bool(_re_any(pat["public_paths"], ep["template"]))
    # data, under YOUR framework
    names = sorted(set(obs["response_fields"]) | set(spec.get("response_fields") or []))
    v["data"] = classify.assess_data(obs["detected"], names, classes)
    smax = cfg["severity"]["sensitive_priority_max"]
    v["sensitive"] = v["data"]["top_priority"] is not None and v["data"]["top_priority"] <= smax
    # inventory
    last = datetime.date.fromisoformat(ep["last_seen"]) if ep["last_seen"] else None
    v["days_since_seen"] = (today - last).days if last else None
    v["deprecated"] = bool(spec.get("deprecated"))
    v["has_object_id"] = paths.has_object_id(ep["path_key"], (spec.get("params") or {}).get("query", []) + obs["query_params"])
    v["covered_by"] = {k: policies.has_active(policy_list, k, ep["service"], ep["method"], ep["path_key"]) for k in policies.KINDS}
    v["blocked_by"] = {k: policies.has_active(policy_list, k, ep["service"], ep["method"], ep["path_key"], block_only=True) for k in policies.KINDS}
    return v


# ---------------------------------------------------------------- reproducible request
_SAFE_SEG = re.compile(r"^[A-Za-z0-9._~%:@+,=-]+$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


def _base_url(service, specs):
    for s in specs:
        if s["service"] == service:
            for u in (s.get("meta") or {}).get("servers") or []:
                if u.startswith("https://") and "{" not in u:
                    sp = urlsplit(u)
                    return f"{sp.scheme}://{sp.netloc}", None
    return (f"https://{service}", None) if _SAFE_HOST.match(service) and "." in service else ("https://${API_HOST}", "Set API_HOST to the host that serves this service.")


def curl(v, specs, token=True, placeholder="OBJECT_ID", extra_headers=(), query=(), data=None, note=None):
    """A cURL command with placeholders only, or None when the path holds characters that are not safe to place in a command."""
    base, hint = _base_url(v["service"], specs)
    out, n = [], 0
    for seg in paths.normalise_path(v["template"]).split("/")[1:]:
        if seg in ("{}", "{id}") or (seg.startswith("{") and seg.endswith("}")):
            nm = re.sub(r"[^A-Za-z0-9]", "", seg) or "ID"
            out.append("${" + (placeholder if n == 0 else (nm.upper() if nm.upper() != "ID" else f"ID{n + 1}")) + "}")
            n += 1
        elif _SAFE_SEG.match(seg):
            out.append(seg)
        elif seg == "":
            continue
        else:
            return None
    url = base + "/" + "/".join(out)
    q = [f"{k}=VALUE" for k in query if _SAFE_NAME.match(k)]
    if q:
        url += "?" + "&".join(q)
    parts = ["curl -sS -i", f"-X {v['method']}"]
    if token:
        parts.append('-H "Authorization: Bearer ${TOKEN}"')
    for h in extra_headers:
        parts.append(f'-H "{h}"')
    if data:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{data}'")
    parts.append(f'"{url}"')
    return {"command": " ".join(parts), "placeholders": sorted(set(re.findall(r"\$\{([A-Z0-9_]+)\}", " ".join(parts)))), "note": " ".join(x for x in (hint, note) if x) or None}


def _req(v, specs, expect, **kw):
    c = curl(v, specs, **kw)
    if not c:
        return {"testable": False, "command": None, "expect": expect, "note": "The path contains characters that are not safe to put in a command, so no request is generated."}
    return {"testable": True, "command": c["command"], "placeholders": c["placeholders"], "expect": expect,
            "note": "Run only against a system you are authorised to test, preferably non-production. " + (c["note"] or "")}


# ---------------------------------------------------------------- findings
def _f(rule, severity, title, v, why, evidence, request=None, key_extra=""):
    return {"rule": rule, "owasp": OWASP[rule], "severity": severity, "title": title, "endpoint_id": v["id"], "service": v["service"], "method": v["method"], "path": v["template"],
            "why": why, "evidence": evidence, "request": request, "fix": FIX[rule], "key": f"{rule}:{v['service']}:{v['method']}:{v['path_key']}:{key_extra}"}


def _step(step, source, detail):
    return {"step": step, "source": source, "detail": detail}


def _data_evidence(v):
    d = v["data"]
    steps = []
    if d["classes"]:
        steps.append(_step("Sensitive data", "classification", "Under your framework this endpoint returns: " + ", ".join(f"{c['name']} (priority {c['priority']})" for c in d["classes"])))
    if d["unclassified"]:
        steps.append(_step("Unclassified data", "classification", "Seen but not mapped to any of your classes: " + ", ".join(d["unclassified"])))
    return steps


def _exposure_step(v):
    return _step("Exposure", "traffic", f"{v['exposure']} ({v['exposure_basis']})")


def evaluate(v, ep, specs, cfg, actors=(), policy_list=(), today=None):
    """Findings for one endpoint view. `actors` are that endpoint's caller rows."""
    th, pat = cfg["thresholds"], cfg["patterns"]
    obs, spec = ep["obs"], ep.get("spec") or {}
    out = []
    plus_ext = 1 if v["exposure"] == "external" else 0
    plus_sens = 1 if v["sensitive"] else 0
    changing = v["method"] in pat["state_changing_methods"]
    data_ev = _data_evidence(v)

    # API9: inventory
    if v["state"] == "shadow" and v["status"] != "accepted-risk":
        ev = [_step("Observed", "traffic", f"{v['calls']:,} call(s) between {v['first_seen']} and {v['last_seen']}."),
              _step("Not documented", "specification", f"No uploaded specification for service '{v['service']}' describes {v['method']} {v['template']}."), _exposure_step(v)] + data_ev
        bump = 1 if (plus_ext or plus_sens or v["auth_state"] == "open-observed") else 0
        out.append(_f("API9:2023", sev("Medium", bump),
                      f"Shadow endpoint {v['method']} {v['template']}", v, "An endpoint is serving traffic that no specification documents, so nobody is reviewing, testing or owning it.", ev,
                      _req(v, specs, "A response (not 404) confirms the endpoint exists. Compare it with the specification.", token=v["auth_state"] != "open-observed")))
    zombie_why = None
    if v["in_spec"] and v["deprecated"] and v["observed"] and v["days_since_seen"] is not None and v["days_since_seen"] <= 30:
        zombie_why = f"The specification marks it deprecated, and it was called as recently as {v['last_seen']} ({v['calls']:,} call(s) in total)."
    if zombie_why and v["status"] != "decommissioning":
        out.append(_f("API9:2023", sev("Medium", plus_ext), f"Deprecated endpoint still in use: {v['method']} {v['template']}", v, "A deprecated endpoint that still answers is an old attack surface nobody maintains.",
                      [_step("Deprecated", "specification", "Marked deprecated in the specification."), _step("Still live", "traffic", zombie_why), _exposure_step(v)] + data_ev,
                      _req(v, specs, "A 2xx response means it is still live; it should return 404 or 410 once retired."), key_extra="zombie"))

    # API2: authentication
    if v["auth_state"] == "open-observed" and not v["public_path"] and v["status"] != "accepted-risk":
        ev = [_step("Unauthenticated success", "traffic", f"{v['unauth_calls']:,} request(s) with no credentials received a success response (of {v['calls']:,} total)."),
              _step("Not a public path", "pattern", "The path is not one of the public patterns (health, status, docs)."), _exposure_step(v)] + data_ev
        if changing:
            ev.append(_step("State-changing method", "traffic", f"{v['method']} changes data."))
        out.append(_f("API2:2023", sev("Medium", plus_ext + plus_sens + (1 if changing else 0)), f"Unauthenticated access to {v['method']} {v['template']}", v,
                      "Callers with no credentials receive successful responses from an endpoint that is not meant to be public.", ev,
                      _req(v, specs, "Without credentials the server should answer 401 or 403. A 2xx confirms the finding.", token=False)))
    elif v["auth_state"] == "open-declared" and not v["public_path"] and (changing or v["sensitive"]):
        out.append(_f("API2:2023", sev("Medium", plus_ext + plus_sens), f"Specification declares no authentication for {v['method']} {v['template']}", v,
                      "The specification explicitly removes security from an operation that changes data or returns sensitive data.",
                      [_step("Declared open", "specification", "security: [] on this operation."), _exposure_step(v)] + data_ev,
                      _req(v, specs, "Without credentials the server should answer 401 or 403.", token=False), key_extra="declared"))
    j = obs["jwt"]
    if j["seen"]:
        base_ev = [_step("Tokens observed", "traffic", f"{j['seen']:,} request(s) carried a decodable token; header and claims were read without verification and discarded.")]
        if j["none_accepted"]:
            out.append(_f("API2:2023", "Critical", f"Unsigned tokens accepted on {v['method']} {v['template']}", v, "A token whose algorithm is 'none' has no signature, and requests carrying one succeeded.",
                          base_ev + [_step("alg none", "traffic", f"{j['none_accepted']:,} request(s) with alg=none returned a success response.")],
                          _req(v, specs, "A request with an unsigned token (alg none) must be rejected with 401.", note="Craft the unsigned token with your own test identity."), key_extra="jwt-none"))
        elif j["algs"].get("none"):
            out.append(_f("API2:2023", "High", f"Unsigned tokens presented to {v['method']} {v['template']}", v, "Tokens with algorithm 'none' were sent. Check the server rejects them.",
                          base_ev + [_step("alg none", "traffic", f"{j['algs']['none']:,} request(s) carried alg=none; their outcome is not linked to a response in the data.")], key_extra="jwt-none-presented"))
        if j["no_exp"]:
            out.append(_f("API2:2023", sev("Medium", plus_ext), f"Tokens without an expiry used on {v['method']} {v['template']}", v, "A token with no expiry is valid forever if it leaks.",
                          base_ev + [_step("No exp claim", "traffic", f"{j['no_exp']:,} of {j['seen']:,} token(s) had no expiry.")], key_extra="jwt-noexp"))
        if j["max_lifetime_hours"] and j["max_lifetime_hours"] > th["jwt_max_lifetime_hours"]:
            out.append(_f("API2:2023", "Medium", f"Long-lived tokens on {v['method']} {v['template']}", v, "A long lifetime widens the window in which a stolen token works.",
                          base_ev + [_step("Lifetime", "traffic", f"Longest token lifetime {j['max_lifetime_hours']:g} h; the limit is {th['jwt_max_lifetime_hours']} h.")], key_extra="jwt-life"))
        if j["key_url_header"]:
            out.append(_f("API2:2023", "High", f"Tokens naming their own key location on {v['method']} {v['template']}", v, "A jku, x5u or jwk header lets the sender point the verifier at a key they control, unless the server ignores it.",
                          base_ev + [_step("Key header", "traffic", f"{j['key_url_header']:,} token(s) carried a jku, x5u or jwk header.")], key_extra="jwt-keyurl"))
        weak = [a for a in j["algs"] if a in th["jwt_weak_algorithms"] and a != "none"]
        if weak:
            out.append(_f("API2:2023", "Low", f"Shared-secret token signatures on {v['method']} {v['template']}", v, "A symmetric signature means every service that can verify a token can also mint one.",
                          base_ev + [_step("Algorithm", "traffic", "Algorithms seen: " + ", ".join(f"{a} x{n}" for a, n in sorted(j['algs'].items())))], key_extra="jwt-weak"))
    cred = [q for q in obs["query_params"] if q.lower() in pat["credential_params"]]
    if cred:
        out.append(_f("API2:2023", "High", f"Credential in the URL of {v['method']} {v['template']}", v,
                      "Secrets in a query string end up in access logs, proxies, browser history and Referer headers.",
                      [_step("Query parameters", "traffic", "Parameter name(s): " + ", ".join(cred)), _exposure_step(v)], key_extra="cred-url"))

    # API8: transport
    if obs["plain_http"]:
        out.append(_f("API8:2023", sev("Medium", plus_sens + (1 if (obs["auth_counts"].get("bearer") or obs["auth_counts"].get("basic")) else 0)), f"Plain HTTP used for {v['method']} {v['template']}", v,
                      "Traffic over HTTP can be read and changed in transit, including credentials.", [_step("Plain HTTP", "traffic", f"{obs['plain_http']:,} request(s) arrived over HTTP rather than HTTPS."), _exposure_step(v)] + data_ev,
                      _req(v, specs, "An HTTP (not HTTPS) request should be refused or redirected before any data is returned.", token=False, note="Use http:// in place of https:// in the URL."), key_extra="http"))

    # API1: object enumeration
    if v["has_object_id"]:
        worst = max(actors, key=lambda a: a["distinct_objects"], default=None)
        if worst and worst["distinct_objects"] >= th["bola_distinct_objects_per_actor_day"]:
            err = f"{worst['errors'] / worst['calls']:.0%}" if worst["calls"] else "0%"
            out.append(_f("API1:2023", sev("High", (1 if v["sensitive"] and v["exposure"] == "external" else 0)), f"Possible object enumeration on {v['method']} {v['template']}", v,
                          "One caller touched many different object ids on an endpoint addressed by id. That is how object-level authorization gaps are found and abused. It is an indicator, not proof.",
                          [_step("Object-addressed endpoint", "traffic", "The path takes an object id."),
                           _step("Many objects, one caller", "traffic", f"Caller {worst['actor']} used {worst['distinct_objects']:,} distinct ids on {worst['day']} (limit {th['bola_distinct_objects_per_actor_day']}); {worst['calls']:,} call(s), {err} errors."),
                           _exposure_step(v)] + data_ev,
                          _req(v, specs, "Using a low-privilege token, request an object that belongs to a different user. Anything other than 403 or 404 confirms the finding.",
                              placeholder="OTHER_USERS_OBJECT_ID"), key_extra="enum"))

    # API3: undeclared properties and mass assignment
    if v["in_spec"] and spec.get("response_fields") is not None and v["observed"]:
        undeclared = sorted(set(obs["response_fields"]) - set(spec.get("response_fields") or []))
        flagged = classify.detect_fields(undeclared)
        if undeclared and flagged:
            cred_hit = "credential" in flagged
            out.append(_f("API3:2023", sev("High" if cred_hit else "Medium", plus_sens), f"Undocumented sensitive properties returned by {v['method']} {v['template']}", v,
                          "The response carries properties the specification does not declare, and their names indicate personal, financial or secret data.",
                          [_step("Observed fields", "traffic", "Undeclared in the specification: " + ", ".join(undeclared[:12])),
                           _step("Looks sensitive", "classification", "By name: " + ", ".join(f"{d} ({', '.join(ns[:3])})" for d, ns in sorted(flagged.items())))] + data_ev,
                          _req(v, specs, "Compare the response body with the specification; the listed properties should not be present unless the caller needs them."), key_extra="excess"))
    if changing:
        risky = sorted(f for f in obs["request_fields"] if f.lower() in pat["mass_assignment_fields"] and f not in (spec.get("request_fields") or []))
        if risky:
            out.append(_f("API3:2023", sev("Medium", plus_ext), f"Possible mass assignment on {v['method']} {v['template']}", v,
                          "Callers send privileged-looking properties that the specification does not declare. If the server binds them, a caller could set their own role or price.",
                          [_step("Request fields", "traffic", "Seen in requests, not in the specification: " + ", ".join(risky)), _exposure_step(v)],
                          _req(v, specs, "Send the request with an extra property such as role set to admin using a normal user's token. The server should ignore or reject it.",
                              data='{"role":"admin"}'), key_extra="mass"))

    # API4: consumption
    top = max(actors, key=lambda a: a["calls"], default=None)
    total = sum(a["calls"] for a in actors)
    if v["calls"] >= th["min_calls_for_rate_checks"] and not v["covered_by"]["rate-limit"] and v["exposure"] in ("external", "partner", "unknown"):
        if top and total and top["calls"] / total >= th["dominant_actor_share"] and len(actors) > 1:
            out.append(_f("API4:2023", sev("Medium", plus_sens), f"One caller dominates {v['method']} {v['template']} with no rate limit", v,
                          "A single caller accounts for most of the traffic and nothing limits how much one caller can take.",
                          [_step("Dominant caller", "traffic", f"{top['actor']} made {top['calls']:,} of {total:,} recorded calls ({top['calls'] / total:.0%}); threshold {th['dominant_actor_share']:.0%}."),
                           _step("No rate limit", "policy", "No enabled rate-limit policy covers this endpoint."), _exposure_step(v)],
                          _req(v, specs, "Send a burst of requests (for example 200 in a few seconds) from one test identity. If none is slowed or refused there is no effective limit.",
                              note="Do this only in non-production."), key_extra="dominant"))
        if obs["max_response_bytes"] >= th["large_response_bytes"] and not any(q.lower() in pat["pagination_params"] for q in obs["query_params"] + (spec.get("params") or {}).get("query", [])):
            out.append(_f("API4:2023", "Medium", f"Large responses without pagination on {v['method']} {v['template']}", v, "An unbounded response lets one request consume a lot of memory, bandwidth and database time.",
                          [_step("Largest response", "traffic", f"{obs['max_response_bytes']:,} bytes in one response (limit {th['large_response_bytes']:,})."), _step("No paging parameter", "traffic", "None of: " + ", ".join(pat["pagination_params"][:6]) + ", ... was seen or declared."),
                           _step("No rate limit", "policy", "No enabled rate-limit policy covers it.")], key_extra="large"))

    # API5: function level
    adm = _re_any(pat["admin_paths"], v["template"])
    if adm and v["exposure"] in ("external", "partner") and v["status"] != "accepted-risk":
        out.append(_f("API5:2023", sev("High", (1 if changing else 0) + (1 if v["auth_state"] == "open-observed" else 0)), f"Administrative-looking endpoint reachable externally: {v['method']} {v['template']}", v,
                      "A path that looks administrative is being called from public addresses. Function-level checks must stop ordinary users reaching it.",
                      [_step("Administrative path", "pattern", f"The path matches '{adm}'."), _exposure_step(v), _step("Authentication", "traffic", v["auth_state"] + (f" ({', '.join(v['auth_mechanisms'])})" if v["auth_mechanisms"] else ""))],
                      _req(v, specs, "With an ordinary user's token the server should answer 403. Anything else confirms the finding.", note="Use a token from a user without administrative rights."), key_extra="admin"))

    # API6: business flows
    flow = _re_any(pat["sensitive_flows"], v["template"])
    if flow and v["method"] != "GET":
        if top and top["calls"] >= th["scraping_calls_per_actor_day"] and not v["covered_by"]["rate-limit"]:
            out.append(_f("API6:2023", sev("Medium", plus_sens + plus_ext), f"Automated use of a sensitive flow: {v['method']} {v['template']}", v,
                          "A business flow that attackers automate (sign-up, login, checkout, reset) is being called at high volume by one caller with no rate limit.",
                          [_step("Sensitive flow", "pattern", f"The path matches '{flow}'."), _step("Volume", "traffic", f"{top['actor']} made {top['calls']:,} calls on {top['day']} (limit {th['scraping_calls_per_actor_day']:,})."),
                           _step("No rate limit", "policy", "No enabled rate-limit policy covers this endpoint."), _exposure_step(v)], key_extra="flow"))

    # API7: server-side request forgery
    urlp = sorted({q for q in obs["query_params"] + (spec.get("params") or {}).get("query", []) + obs["request_fields"] + (spec.get("request_fields") or []) if q.lower() in pat["url_params"]})
    if urlp:
        out.append(_f("API7:2023", sev("Medium", 1 if (v["exposure"] == "external" and v["auth_state"] == "open-observed") else 0), f"Caller-supplied URL parameter on {v['method']} {v['template']}", v,
                      "The endpoint accepts a URL or host from the caller. If the server fetches it, an attacker can make the server reach internal systems.",
                      [_step("URL-like parameter", "traffic" if set(urlp) & set(obs["query_params"] + obs["request_fields"]) else "specification", "Name(s): " + ", ".join(urlp)), _exposure_step(v)],
                      _req(v, specs, "Send a URL that points at a host you control (for example a request-catcher) and a loopback address. If the server contacts either, or returns its content, the finding is confirmed.",
                          query=urlp[:1], note="Replace VALUE with the test URL."), key_extra="ssrf"))
    return out


def evaluate_dependencies(deps, views_by_service):
    out = []
    for d in deps:
        if (d.get("dest_exposure") or "") in ("third-party", "external-vendor", "third_party") and any(w["sensitive"] for w in views_by_service.get(d["source_service"], [])):
            ev = [_step("Outbound dependency", "traffic", f"{d['source_service']} called {d['dest_service']} {d['calls']:,} time(s), last on {d['last_seen']}."),
                  _step("Third party", "traffic", "The destination is marked third-party in the records."),
                  _step("Sensitive data in the caller", "classification", f"{d['source_service']} serves endpoints that return data in your sensitive classes.")]
            out.append({"rule": "API10:2023", "owasp": OWASP["API10:2023"], "severity": "Low", "title": f"Review third-party API consumption: {d['source_service']} to {d['dest_service']}", "endpoint_id": None,
                        "service": d["source_service"], "method": "", "path": d["dest_service"], "why": "Data from third-party APIs should be validated, and what is sent to them reviewed, when the calling service handles sensitive data.",
                        "evidence": ev, "request": None, "fix": FIX["API10:2023"], "key": f"API10:2023:{d['source_service']}:{d['dest_service']}"})
    return out


def run(endpoints, specs, classes, actor_rows, deps, policy_list, today=None, cfg=None):
    """-> (views, findings, gaps). The whole assessment from already-loaded data."""
    cfg = cfg or config.load()
    today = _today(today)
    spec_services = {s["service"] for s in specs}
    by_ep = {}
    for a in actor_rows:
        by_ep.setdefault(a["endpoint_id"], []).append(a)
    views, findings = [], []
    for ep in endpoints:
        v = view(ep, classes, ep["service"] in spec_services, cfg, policy_list, today)
        v["findings"] = 0
        views.append(v)
        fs = evaluate(v, ep, specs, cfg, by_ep.get(ep["id"], []), policy_list, today)
        v["findings"] = len(fs)
        findings += fs
    by_service = {}
    for v in views:
        by_service.setdefault(v["service"], []).append(v)
    findings += evaluate_dependencies(deps, by_service)
    findings.sort(key=lambda f: (-SEV_WEIGHT[f["severity"]], f["service"], f["rule"], f["path"]))
    # gaps: things the data could not decide, listed so nothing is silently treated as fine
    gaps = []
    for svc in sorted({v["service"] for v in views if v["observed"]} - spec_services):
        gaps.append({"kind": "no-specification", "subject": svc, "detail": f"Traffic was seen for '{svc}' but no specification was uploaded, so nothing can be called shadow. Upload its OpenAPI file or generate one from the inventory."})
    unclassified = {}
    for v in views:
        for d in v["data"]["unclassified"]:
            unclassified.setdefault(d, 0)
            unclassified[d] += 1
    for d, n in sorted(unclassified.items()):
        gaps.append({"kind": "unclassified-data", "subject": d, "detail": f"'{d}' was observed on {n} endpoint(s) and is not mapped to any of your data classes, so its sensitivity is unknown."})
    ext_no_owner = [v for v in views if v["exposure"] == "external" and not v["owner"]]
    if ext_no_owner:
        gaps.append({"kind": "no-owner", "subject": f"{len(ext_no_owner)} external endpoint(s)", "detail": "External endpoints with no named owner cannot be routed to anyone."})
    stale = cfg["thresholds"]["stale_days"]
    observed_services = {v["service"] for v in views if v["observed"]}
    for v in views:
        if v["state"] == "spec-only" and v["service"] in observed_services and not v["deprecated"]:
            gaps.append({"kind": "documented-never-seen", "subject": f"{v['method']} {v['template']}", "detail": f"Documented for '{v['service']}' but never observed in the traffic imported so far."})
        elif v["state"] == "documented" and v["days_since_seen"] is not None and v["days_since_seen"] > stale:
            gaps.append({"kind": "stale", "subject": f"{v['method']} {v['template']}", "detail": f"Documented, but not seen for {v['days_since_seen']} days (limit {stale}). Documentation drift or an unused endpoint."})
    return views, findings, gaps[:300]


def to_queue_items(findings, specs):
    """The findings in the shape the ingest API takes (scan type dast, asset type application)."""
    items = []
    spec_by = {s["service"]: s for s in specs}
    for f in findings:
        lines = [f"{f['rule']} {f['owasp']}. {f['why']}", "", "Evidence chain:"] + [f"  {i}. {e['step']} ({e['source']}): {e['detail']}" for i, e in enumerate(f["evidence"], 1)]
        if f["request"]:
            lines += ["", "Request to confirm (true or false positive):" if f["request"].get("testable") else "Request:", "  " + (f["request"].get("command") or f["request"].get("note", "")),
                      "  Expect: " + f["request"]["expect"]]
        base = ((spec_by.get(f["service"]) or {}).get("meta") or {}).get("servers") or []
        items.append({"title": f"[{f['rule']}] {f['title']}", "severity": f["severity"], "asset": {"name": f["service"], "type": "application"}, "source_ref": f["key"][:200],
                      "description": "\n".join(lines)[:6000], "recommended_fix": f["fix"], "scan_type": "dast", "cwe": CWE[f["rule"]], "rule_id": f["rule"], "tool": "quanta-api-security",
                      "location": {"url": (f"{f['method']} {f['path']}").strip() + (f"  [{base[0]}]" if base else "")}})
    return items
