"""
Review artifacts: a policy rendered as a rule in the format of a common edge service, for a person to read, test and apply through their own change process.

Two targets: `aws-waf` (a rule for a web ACL, plus any IP-set resources it refers to) and `cloud-armor` (security policy rules). Monitor mode becomes the service's
own non-enforcing mode (a Count action; Cloud Armor preview). Nothing here calls any service. Built from the formats' public documentation and never validated
against a live account: review each artifact in a test web ACL or policy first. Where a policy cannot be expressed at an edge request filter it says so plainly
instead of emitting something that looks like protection but is not (a data-loss limit counts what leaves, which a request filter cannot see; Cloud Armor custom
rules cannot read a request body).
"""
import re

from remediation.apisec import paths

TARGETS = {"aws-waf": "AWS WAF (WAFv2 rule)", "cloud-armor": "Google Cloud Armor (security policy rules)"}
_TT = [{"Priority": 0, "Type": "NONE"}]


def _rule_name(p):
    return re.sub(r"[^A-Za-z0-9_-]", "-", f"quanta-{p['name']}")[:100].strip("-") or f"quanta-policy-{p['id']}"


def _regex_of(path_pattern):
    """A regular expression for an endpoint path pattern ({} or {name} segments match one segment; a trailing * matches the rest)."""
    prefix = path_pattern.endswith("*")
    body = path_pattern[:-1] if prefix else path_pattern
    segs = [s for s in paths.normalise_path(body or "/").split("/")[1:]] if body.strip("/") else []
    rx = "".join("/[^/]+" if (s.startswith("{") and s.endswith("}")) or s.startswith(":") else "/" + re.escape(s) for s in segs)
    if prefix:
        return "^" + rx + "(/.*)?$"
    return "^" + (rx or "/") + "$"


def _endpoint_list(p):
    out = []
    for e in p["scope"].get("endpoints") or []:
        m, _, pth = e.partition(" ")
        out.append((m, pth))
    return out


def _cel_quote(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


# ---------------------------------------------------------------- AWS WAF
def _aws_scope(p):
    eps = _endpoint_list(p)
    if not eps:
        return None
    stmts = []
    for m, pth in eps:
        parts = [{"RegexMatchStatement": {"RegexString": _regex_of(pth), "FieldToMatch": {"UriPath": {}}, "TextTransformations": _TT}}]
        if m != "*":
            parts.insert(0, {"ByteMatchStatement": {"SearchString": m, "FieldToMatch": {"Method": {}}, "PositionalConstraint": "EXACTLY", "TextTransformations": _TT}})
        stmts.append(parts[0] if len(parts) == 1 else {"AndStatement": {"Statements": parts}})
    return stmts[0] if len(stmts) == 1 else {"OrStatement": {"Statements": stmts}}


def _aws_and(*stmts):
    s = [x for x in stmts if x]
    return s[0] if len(s) == 1 else {"AndStatement": {"Statements": s}}


def _aws(p):
    name, notes, resources = _rule_name(p), [], []
    k, par = p["kind"], p["params"]
    scope = _aws_scope(p)
    if p["scope"].get("services"):
        notes.append("Service-level scope is not translated into the rule: attach it to the web ACL that fronts: " + ", ".join(p["scope"]["services"]) + ".")
    if k == "rate-limit":
        rb = {"Limit": par["limit"], "EvaluationWindowSec": par["window_seconds"], "AggregateKeyType": "IP"}
        if par["by"] == "actor":
            rb["AggregateKeyType"] = "CUSTOM_KEYS"
            rb["CustomKeys"] = [{"Header": {"Name": par["actor_header"].lower(), "TextTransformations": _TT}}]
            notes.append("Counting by a header uses rate-based custom keys; confirm your web ACL's rule-group capacity and the header is always present.")
        if scope:
            rb["ScopeDownStatement"] = scope
        stmt = {"RateBasedStatement": rb}
    elif k == "malicious-source":
        v4 = [c for c in par["cidrs"] if ":" not in c]
        v6 = [c for c in par["cidrs"] if ":" in c]
        refs = []
        for ver, addrs in (("IPV4", v4), ("IPV6", v6)):
            if addrs:
                nm = f"{name}-{ver.lower()}"
                resources.append({"type": "AWS::WAFv2::IPSet", "Name": nm, "Scope": "REGIONAL or CLOUDFRONT (choose to match your web ACL)", "IPAddressVersion": ver, "Addresses": addrs})
                refs.append({"IPSetReferenceStatement": {"ARN": f"<ARN of IP set {nm} once created>"}})
        stmt = _aws_and(refs[0] if len(refs) == 1 else {"OrStatement": {"Statements": refs}}, scope)
        notes.append("Create the IP set resource(s) first and put their ARNs in the rule.")
    elif k == "geo-restriction":
        geo = {"GeoMatchStatement": {"CountryCodes": par["countries"]}}
        stmt = _aws_and({"NotStatement": {"Statement": geo}} if par["type"] == "allow-only" else geo, scope)
    elif k == "custom-signature":
        fm = {"header": {"SingleHeader": {"Name": par.get("header_name", "").lower()}}, "query": {"QueryString": {}}, "uri_path": {"UriPath": {}}, "body": {"Body": {"OversizeHandling": "CONTINUE"}}}[par["target"]]
        if par["match"] == "regex":
            sig = {"RegexMatchStatement": {"RegexString": par["pattern"], "FieldToMatch": fm, "TextTransformations": _TT}}
        else:
            sig = {"ByteMatchStatement": {"SearchString": par["pattern"], "FieldToMatch": fm, "TextTransformations": _TT,
                                          "PositionalConstraint": {"contains": "CONTAINS", "exact": "EXACTLY", "starts_with": "STARTS_WITH"}[par["match"]]}}
            notes.append("SearchString is shown as text, as the console's JSON editor takes it; encode it as base64 for the CLI or an SDK.")
        if par["target"] == "body":
            notes.append("A web ACL inspects only the first part of a request body (a size limit set by the service); larger bodies follow the OversizeHandling setting.")
        stmt = _aws_and(sig, scope)
    else:
        return None
    rule = {"Name": name, "Priority": 1000 + p["id"], "Statement": stmt, "Action": {"Block": {}} if p["mode"] == "block" else {"Count": {}},
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": name}}
    if p["mode"] == "monitor":
        notes.append("Monitor mode is a Count action: matching requests are counted and sampled, not blocked.")
    return {"rules": [rule], "resources": resources}, notes


# ---------------------------------------------------------------- Cloud Armor
def _cel_scope(p):
    eps = _endpoint_list(p)
    if not eps:
        return None
    parts = []
    for m, pth in eps:
        cond = f"request.path.matches({_cel_quote(_regex_of(pth))})"
        parts.append(f"(request.method == {_cel_quote(m)} && {cond})" if m != "*" else f"({cond})")
    return " || ".join(parts)


def _cel_and(*exprs):
    e = [f"({x})" for x in exprs if x]
    return " && ".join(e)


def _armor(p):
    name, notes = _rule_name(p), []
    k, par = p["kind"], p["params"]
    scope = _cel_scope(p)
    base = 1000 + p["id"] * 10
    if p["scope"].get("services"):
        notes.append("Service-level scope is not translated into the rule: attach it to the security policy of the backend service for: " + ", ".join(p["scope"]["services"]) + ".")
    preview = p["mode"] == "monitor"
    if preview:
        notes.append("Monitor mode sets preview: the rule is evaluated and logged but not enforced.")
    rules = []
    if k == "rate-limit":
        rl = {"rateLimitThreshold": {"count": par["limit"], "intervalSec": par["window_seconds"]}, "conformAction": "allow", "exceedAction": "deny(429)",
              "enforceOnKey": "IP" if par["by"] == "ip" else "HTTP_HEADER"}
        if par["by"] == "actor":
            rl["enforceOnKeyName"] = par["actor_header"]
        rules.append({"priority": base, "description": f"Quanta policy {p['name']} v{p['version']}", "match": {"expr": {"expression": scope or "true"}}, "action": "throttle", "rateLimitOptions": rl,
                      "preview": preview})
    elif k == "malicious-source":
        cidrs = par["cidrs"]
        for i in range(0, len(cidrs), 10):
            chunk = cidrs[i:i + 10]
            r = {"priority": base + i // 10, "description": f"Quanta policy {p['name']} v{p['version']} (part {i // 10 + 1})", "action": "deny(403)", "preview": preview}
            if scope:
                ranges = " || ".join(f"inIpRange(origin.ip, {_cel_quote(c)})" for c in chunk)
                r["match"] = {"expr": {"expression": _cel_and(ranges, scope)}}
            else:
                r["match"] = {"versionedExpr": "SRC_IPS_V1", "config": {"srcIpRanges": chunk}}
            rules.append(r)
        if len(cidrs) > 10:
            notes.append("Cloud Armor accepts a limited number of ranges per rule, so the list is split across several rules with consecutive priorities.")
    elif k == "geo-restriction":
        any_c = " || ".join(f"origin.region_code == {_cel_quote(c)}" for c in par["countries"])
        geo = f"!({any_c})" if par["type"] == "allow-only" else any_c
        rules.append({"priority": base, "description": f"Quanta policy {p['name']} v{p['version']}", "match": {"expr": {"expression": _cel_and(geo, scope)}}, "action": "deny(403)", "preview": preview})
    elif k == "custom-signature":
        t = par["target"]
        if t == "body":
            return None, ["Cloud Armor custom rules cannot match on a request body. Use a preconfigured WAF rule, or send this policy to an inline gateway that can read bodies."]
        subject = {"header": f"request.headers[{_cel_quote(par.get('header_name', '').lower())}]", "query": "request.query", "uri_path": "request.path"}[t]
        pat = _cel_quote(par["pattern"])
        expr = {"contains": f"{subject}.contains({pat})", "exact": f"{subject} == {pat}", "starts_with": f"{subject}.startsWith({pat})", "regex": f"{subject}.matches({pat})"}[par["match"]]
        rules.append({"priority": base, "description": f"Quanta policy {p['name']} v{p['version']}", "match": {"expr": {"expression": _cel_and(expr, scope)}}, "action": "deny(403)", "preview": preview})
    else:
        return None
    return {"rules": rules, "resources": []}, notes


def generate(p, target):
    """{target, label, supported, artifact, notes} for a policy (as returned by policies.get) and a target in TARGETS."""
    if target not in TARGETS:
        raise ValueError(f"target must be one of {', '.join(TARGETS)}")
    common = ["Generated from the service's public rule format and not validated against a live account. Review it in a test web ACL or policy first. Quanta has not applied it."]
    if p["kind"] == "data-loss":
        return {"target": target, "label": TARGETS[target], "supported": False, "artifact": None,
                "notes": ["A data-loss limit counts what leaves in responses. An edge request filter cannot see responses, so no rule is generated for it.",
                          "Send this policy to an endpoint you own that sits where responses are visible (an API gateway, sidecar or the application tier)."] + common}
    built = (_aws if target == "aws-waf" else _armor)(p)
    if built is None or built[0] is None:
        return {"target": target, "label": TARGETS[target], "supported": False, "artifact": None, "notes": (built[1] if built else []) + common}
    artifact, notes = built
    if not p["enabled"]:
        notes = notes + ["The policy is disabled in Quanta: do not add this rule, or remove it if it is already present."]
    return {"target": target, "label": TARGETS[target], "supported": True, "artifact": artifact, "notes": notes + common}
