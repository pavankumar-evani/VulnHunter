"""
Renders a Sigma-style selection as a search in the language of a SIEM: Splunk SPL, Microsoft Sentinel KQL, Elastic EQL and ES|QL, Google SecOps
UDM search, or a CrowdStrike Falcon FQL host lookup, scoped to the hosts a hunt is about.

This is a small, honest translator, not pySigma: it handles the modifiers the hunt library uses (contains, startswith, endswith, exact match,
lists as OR, several fields as AND) and nothing else. Anything a language cannot express (another modifier, a field with no equivalent in that
language's schema, a selection a host-lookup API cannot take) raises NotExpressible, which the caller records as "not expressible"; part of a
selection is never silently dropped. Field names are Sigma's except for UDM, which needs a mapping to UDM paths (UDM_FIELDS), so the analyst maps
the others to their own data model. The rendered text is sent only by a confirmed, read-only search connection (remediation/hunting/search_base.py),
or run by the analyst by hand.
"""
import re

_MODS = ("contains", "startswith", "endswith")
LANGUAGES = ("splunk-spl", "kql", "eql", "esql", "udm", "fql")
_FIELD = re.compile(r"[A-Za-z0-9_.\-]+")


class NotExpressible(ValueError):
    """The selection cannot be written faithfully in this language. A ValueError so callers that already catch ValueError keep working."""


def _q(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _clause(key, value):
    field, _, mod = key.partition("|")
    if not _FIELD.fullmatch(field):
        raise ValueError(f"Unsupported field name: {field}")
    if mod and mod not in _MODS:
        raise ValueError(f"Unsupported modifier: {mod}")
    values = value if isinstance(value, list) else [value]
    parts = []
    for v in values:
        if isinstance(v, (int, float)) and not mod:
            parts.append(f"{field}={v}")
        elif mod == "contains":
            parts.append(f'{field}="*{_wild(v)}*"')
        elif mod == "startswith":
            parts.append(f'{field}="{_wild(v)}*"')
        elif mod == "endswith":
            parts.append(f'{field}="*{_wild(v)}"')
        else:
            parts.append(f"{field}={_q(v)}")
    return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"


def _wild(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def to_spl(selection, hosts=None, index=None):
    """One SPL search for a selection; `hosts` narrows it to the affected assets."""
    if not selection:
        raise ValueError("A detection needs at least one field")
    body = " ".join(_clause(k, v) for k, v in selection.items())
    head = f"index={index} " if index else ""
    scope = ""
    if hosts:
        scope = "(" + " OR ".join(f"host={_q(h)}" for h in sorted(hosts)[:50]) + ") "
    return f"search {head}{scope}{body}".strip()


# ---------------------------------------------------------------- the other languages
def _conds(selection):
    """-> [(field, mod, [values])], validated once for every language."""
    if not selection:
        raise ValueError("A detection needs at least one field")
    out = []
    for key, value in selection.items():
        field, _, mod = key.partition("|")
        if not _FIELD.fullmatch(field):
            raise NotExpressible(f"Unsupported field name: {field}")
        if mod and mod not in _MODS:
            raise NotExpressible(f"Unsupported modifier: {mod}")
        out.append((field, mod, value if isinstance(value, list) else [value]))
    return out


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _kf(field):
    """A KQL column name; a name with a hyphen needs the bracket form."""
    return field if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field) else "['" + field + "']"


def _bt(field):
    """An EQL / ES|QL field name; a hyphen needs backticks (a dotted path is fine as it is)."""
    return field if re.fullmatch(r"[A-Za-z_@][A-Za-z0-9_.@]*", field) else "`" + field + "`"


def _join(ors, op):
    return ors[0] if len(ors) == 1 else "(" + f" {op} ".join(ors) + ")"


def to_kql(selection, hosts=None, index=None):  # noqa: ARG001 - every renderer takes the same three arguments
    """KQL for Microsoft Sentinel (Log Analytics): a search over all tables (`union *`), lists as OR, fields as AND, hosts as DeviceName or Computer."""
    parts = []
    for field, mod, values in _conds(selection):
        field = _kf(field)
        ors = []
        for v in values:
            if _num(v) and not mod:
                ors.append(f"{field} == {v}")
            else:
                ors.append(f"{field} {mod or '=~'} {_q(v)}")
        parts.append(_join(ors, "or"))
    scope = ""
    if hosts:
        names = ", ".join(_q(h) for h in sorted(hosts)[:50])
        scope = f"| where DeviceName in~ ({names}) or Computer in~ ({names}) "
    return f"union * {scope}| where " + " and ".join(parts)


def to_eql(selection, hosts=None, index=None):  # noqa: ARG001
    """Elastic EQL: `any where ...` with the case-insensitive functions stringContains~, startsWith~, endsWith~ and `:` for case-insensitive equality."""
    parts = []
    for field, mod, values in _conds(selection):
        field = _bt(field)
        ors = []
        for v in values:
            if _num(v) and not mod:
                ors.append(f"{field} == {v}")
            elif mod == "contains":
                ors.append(f"stringContains~({field}, {_q(v)})")
            elif mod == "startswith":
                ors.append(f"startsWith~({field}, {_q(v)})")
            elif mod == "endswith":
                ors.append(f"endsWith~({field}, {_q(v)})")
            else:
                if re.search(r"[*?]", str(v)):
                    raise NotExpressible(f"{field}: a value with * or ? is a wildcard in EQL's ':' operator and cannot be matched literally")
                ors.append(f"{field} : {_q(v)}")
        parts.append(_join(ors, "or"))
    scope = f" host.name in~ ({', '.join(_q(h) for h in sorted(hosts)[:50])}) and" if hosts else ""
    return "any where" + scope + " " + " and ".join(parts)


def _like_body(v):
    """The inside of an ES|QL LIKE pattern for a literal value: * and ? are wildcards there, so they are escaped; lower-cased because the field is."""
    return str(v).lower().replace("\\", "\\\\").replace('"', '\\"').replace("*", "\\\\*").replace("?", "\\\\?")


def to_esql(selection, hosts=None, index=None):
    """Elastic ES|QL: FROM <index> | WHERE ... (case-insensitive through TO_LOWER). `index` defaults to the logs-* data streams."""
    parts = []
    for field, mod, values in _conds(selection):
        field = _bt(field)
        ors = []
        for v in values:
            if _num(v) and not mod:
                ors.append(f"{field} == {v}")
            elif mod:
                b = _like_body(v)
                pat = {"contains": f'"*{b}*"', "startswith": f'"{b}*"', "endswith": f'"*{b}"'}[mod]
                ors.append(f"TO_LOWER({field}) LIKE {pat}")
            else:
                ors.append(f"TO_LOWER({field}) == {_q(str(v).lower())}")
        parts.append(_join(ors, "OR"))
    scope = f"TO_LOWER(host.name) IN ({', '.join(_q(h.lower()) for h in sorted(hosts)[:50])}) AND " if hosts else ""
    return f"FROM {index or 'logs-*'} | WHERE {scope}" + " AND ".join(parts)


# Sigma field -> UDM path. A field not listed has no agreed UDM equivalent here and the selection is reported as not expressible.
UDM_FIELDS = {
    "Image": "target.process.file.full_path", "ParentImage": "principal.process.file.full_path", "CommandLine": "target.process.command_line",
    "User": "principal.user.userid", "TargetUserName": "target.user.userid", "DestinationIp": "target.ip", "DestinationPort": "target.port",
    "SourceIp": "principal.ip", "QueryName": "network.dns.questions.name", "cs-uri-query": "target.url", "sc-status": "network.http.response_code",
    "EventID": "metadata.product_event_type",
}


def _udm_rx(v, mod):
    esc = re.escape(str(v)).replace("/", "\\/")
    pre, post = ("", ".*") if mod == "startswith" else (".*", "") if mod == "endswith" else (".*", ".*")
    return f"/^{pre}{esc}{post}$/ nocase"


def to_udm(selection, hosts=None, index=None):  # noqa: ARG001
    """Google SecOps (Chronicle) UDM search: `udm.path = "x" nocase` or a regex with nocase, lists as OR, fields as AND, hosts as principal or target hostname."""
    parts = []
    for field, mod, values in _conds(selection):
        path = UDM_FIELDS.get(field)
        if not path:
            raise NotExpressible(f"{field} has no UDM field mapping in Quanta (UDM_FIELDS); map it, or write the search in the UDM search box")
        ors = []
        for v in values:
            if _num(v) and not mod:
                ors.append(f"{path} = {v}")
            elif mod:
                ors.append(f"{path} = {_udm_rx(v, mod)}")
            else:
                ors.append(f"{path} = {_q(v)} nocase")
        parts.append(_join(ors, "OR"))
    scope = ""
    if hosts:
        scope = "(" + " OR ".join(f"principal.hostname = {_q(h)} nocase OR target.hostname = {_q(h)} nocase" for h in sorted(hosts)[:50]) + ") AND "
    return scope + " AND ".join(parts)


FQL_FIELDS = {"ComputerName": "hostname", "Hostname": "hostname", "host": "hostname", "LocalIP": "local_ip", "ExternalIP": "external_ip"}


def to_fql(selection, hosts=None, index=None):  # noqa: ARG001
    """CrowdStrike Falcon: a read-only HOST lookup in FQL, written `hosts <FQL>`. The Hosts and Alerts APIs are not an event store, so process,
    command-line and network selections are not expressible; only a selection made of host name or address fields is."""
    parts = []
    for field, mod, values in _conds(selection):
        name = FQL_FIELDS.get(field)
        if not name or mod:
            raise NotExpressible(f"{field}{('|' + mod) if mod else ''} is event data; the Falcon Hosts and Alerts APIs only answer host-attribute lookups")
        clean = [str(v).replace("'", "") for v in values]
        parts.append(f"{name}:['" + "','".join(clean) + "']" if len(clean) > 1 else f"{name}:'{clean[0]}'")
    return "hosts " + "+".join(parts)


RENDERERS = {"splunk-spl": to_spl, "kql": to_kql, "eql": to_eql, "esql": to_esql, "udm": to_udm, "fql": to_fql}


def render(language, selection, hosts=None, index=None):
    """The selection in `language`. Raises NotExpressible (a ValueError) when it cannot be written faithfully."""
    fn = RENDERERS.get(language)
    if not fn:
        raise NotExpressible(f"No renderer for the language {language!r}")
    return fn(selection, hosts, index)
