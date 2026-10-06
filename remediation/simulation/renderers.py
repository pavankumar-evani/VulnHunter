"""
Renderers: turn the one fictional estate (estate.py) into each vendor's own response format.

    RENDERERS = {connection_type: render(estate, values) -> transport}
    session_for(connection_type, values=None, estate=None) -> transport

The transport is whatever the connector accepts through its injection seam: a ReplaySession (a
`requests.Session` stand-in, replay.py) for HTTP connectors, or a fake GMP client for OpenVAS (a
stateful protocol, not HTTP). The connector's own code then runs for real: it builds the requests, pages
through the answers and parses the vendor format. Only the network is replaced.

How to add a connector (the contract):
  1. Read the connector in remediation/connectors/ and its tests/test_*_connector.py: the hand-rolled
     fake there shows the exact vendor response shapes it parses.
  2. Write `render_<name>(estate, values=None)`: build routes (method, url_regex, handler) and return
     ReplaySession(routes). Take every record from `estate` (so hosts correlate across sources); use
     estate.detections_for(<source>) / estate.hosts_for(<source>) and add a coverage key in estate.py
     if the source sees a different set of hosts. Honour the connector's paging parameters, with small
     pages so multi-page code runs. Never read the clock or the network.
  3. Register it in RENDERERS under the registry type id (remediation/connections/registry.py SPECS key),
     and add the label in LABELS so the demonstration loader names the connection.
  4. In registry.py make that type's `pull`/`test` accept `session=None` and pass it to the connector
     (see _tenable / _qualys). Nothing else changes.
"""
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import Element, SubElement
from xml.sax.saxutils import escape

from remediation.simulation import estate as estate_mod
from remediation.simulation.replay import ReplaySession

SIM_BASE_URL = "https://simulation.invalid"


def _json(payload, status=200):
    return status, None, payload


# --------------------------------------------------------------------------- Tenable.io
def render_tenable(estate, values=None):
    detections = estate.detections_for("tenable")
    exports = {}

    def record(d):
        h, v = d["host"], d["vuln"]
        return {"plugin": {"id": v["plugin_id"], "name": v["title"], "synopsis": v["synopsis"], "solution": v["solution"], "risk_factor": v["severity"],
                           "cvss3_base_score": v["cvss"], "cve": [v["cve"]]},
                "asset": {"hostname": h["fqdn"], "fqdn": h["fqdn"], "ipv4": h["ip"], "operating_system": [h["os"]]},
                "port": {"port": d["port"], "protocol": d["protocol"].upper()},
                "first_found": estate_mod.timestamp(d["first_seen"]), "last_found": estate_mod.timestamp(d["last_seen"], 4)}

    def start(req):
        body = req.json or {}
        per = max(1, min(int(body.get("num_assets", 50)), 5))  # small chunks so the multi-chunk path always runs
        since = (body.get("filters") or {}).get("since")
        rows = [d for d in detections if since is None or _epoch(d["last_seen"]) >= int(since)]
        by_host = {}
        for d in rows:
            by_host.setdefault(d["host_id"], []).append(record(d))
        groups = list(by_host.values())
        chunks = [[r for g in groups[i:i + per] for r in g] for i in range(0, len(groups), per)]
        uuid = f"sim-export-{estate.seed}-{len(exports) + 1:04d}"
        exports[uuid] = chunks
        return _json({"export_uuid": uuid})

    def status(req):
        chunks = exports.get(req.match.group("uuid"))
        if chunks is None:
            return _json({"error": "export not found"}, 404)
        return _json({"status": "FINISHED", "chunks_available": list(range(1, len(chunks) + 1))})

    def chunk(req):
        chunks = exports.get(req.match.group("uuid"))
        n = int(req.match.group("chunk"))
        if chunks is None or not 1 <= n <= len(chunks):
            return _json({"error": "chunk not found"}, 404)
        return _json(chunks[n - 1])

    return ReplaySession([
        ("GET", r"/session$", lambda req: _json({"username": "simulation", "email": "simulation@corp.test"})),
        ("POST", r"/vulns/export$", start),
        ("GET", r"/vulns/export/(?P<uuid>[^/]+)/status$", status),
        ("GET", r"/vulns/export/(?P<uuid>[^/]+)/chunks/(?P<chunk>\d+)$", chunk),
    ])


def _epoch(date_text):
    import calendar
    import datetime
    return calendar.timegm(datetime.date.fromisoformat(date_text).timetuple())


# --------------------------------------------------------------------------- Qualys VMDR
_QUALYS_PAGE = 4


def _qualys_host_id(host):
    return 100000 + int(host["id"][1:])


def render_qualys(estate, values=None):
    hosts = estate.hosts_for("qualys")
    by_host = {}
    for d in estate.detections_for("qualys"):
        by_host.setdefault(d["host_id"], []).append(d)
    xml_head = '<?xml version="1.0" encoding="UTF-8" ?>\n'

    def need_header(req):
        if not any(k.lower() == "x-requested-with" for k in req.headers):
            return 400, None, xml_head + "<SIMPLE_RETURN><RESPONSE><TEXT>Bad Request: X-Requested-With header required</TEXT></RESPONSE></SIMPLE_RETURN>"
        return None

    def detection(req):
        bad = need_header(req)
        if bad:
            return bad
        limit = max(1, min(int(req.params.get("truncation_limit", 1000)), _QUALYS_PAGE))
        id_min = int(req.params.get("id_min", 0))
        pending = [h for h in hosts if _qualys_host_id(h) >= id_min]
        page, rest = pending[:limit], pending[limit:]
        out = [xml_head, "<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>"]
        for h in page:
            out.append(f"<HOST><ID>{_qualys_host_id(h)}</ID><IP>{escape(h['ip'])}</IP><DNS>{escape(h['fqdn'])}</DNS><OS>{escape(h['os'])}</OS><DETECTION_LIST>")
            for d in by_host.get(h["id"], []):
                v = d["vuln"]
                out.append(f"<DETECTION><QID>{v['qid']}</QID><TYPE>Confirmed</TYPE><SEVERITY>{estate_mod.qualys_level(v['cvss'])}</SEVERITY>"
                           f"<PORT>{d['port']}</PORT><PROTOCOL>{d['protocol'].upper()}</PROTOCOL>"
                           f"<FIRST_FOUND_DATETIME>{estate_mod.timestamp(d['first_seen'])}</FIRST_FOUND_DATETIME>"
                           f"<LAST_FOUND_DATETIME>{estate_mod.timestamp(d['last_seen'], 4)}</LAST_FOUND_DATETIME></DETECTION>")
            out.append("</DETECTION_LIST></HOST>")
        out.append("</HOST_LIST>")
        if rest:
            nxt = f"{req.path_url}?action=list&id_min={_qualys_host_id(rest[0])}"
            out.append(f"<WARNING><CODE>1980</CODE><TEXT>{limit} record limit exceeded. Use URL to get next batch of results.</TEXT><URL>{escape(nxt)}</URL></WARNING>")
        out.append("</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>")
        return 200, {"Content-Type": "text/xml"}, "".join(out)

    def knowledge_base(req):
        bad = need_header(req)
        if bad:
            return bad
        wanted = {q for q in req.params.get("ids", "").split(",") if q}
        out = [xml_head, "<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><VULN_LIST>"]
        for v in estate.vulnerabilities:
            if v["qid"] in wanted:
                out.append(f"<VULN><QID>{v['qid']}</QID><VULN_TYPE>Vulnerability</VULN_TYPE><SEVERITY_LEVEL>{estate_mod.qualys_level(v['cvss'])}</SEVERITY_LEVEL>"
                           f"<TITLE>{escape(v['title'])}</TITLE><SOLUTION>{escape(v['solution'])}</SOLUTION>"
                           f"<CVE_LIST><CVE><ID>{v['cve']}</ID><URL>https://nvd.nist.gov/vuln/detail/{v['cve']}</URL></CVE></CVE_LIST></VULN>")
        out.append("</VULN_LIST></RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>")
        return 200, {"Content-Type": "text/xml"}, "".join(out)

    return ReplaySession([
        ("GET", r"/api/2\.0/fo/asset/host/vm/detection/$", detection),
        ("GET", r"/api/2\.0/fo/knowledge_base/vuln/$", knowledge_base),
    ])


# --------------------------------------------------------------------------- OpenVAS / GVM (GMP, not HTTP)
class SimulatedGmp:
    """A GMP client double that answers with GMP-shaped XML elements, the same surface python-gvm's authenticated Gmp client offers
    to remediation/connectors/openvas_connector.py. The task it reports is always finished."""

    def __init__(self, estate):
        self.estate = estate
        self.created_targets, self.created_tasks, self.started_tasks = [], [], []
        self.served = []

    def connect(self):
        return None

    def disconnect(self):
        return None

    def authenticate(self, username, password):  # the simulation never inspects credentials
        return None

    def get_version(self):
        self.served.append(("get_version",))
        return ET.fromstring("<get_version_response status='200'><version>22.4</version></get_version_response>")

    def create_target(self, name, hosts):
        self.served.append(("create_target", name))
        self.created_targets.append({"name": name, "hosts": hosts})
        return ET.fromstring("<create_target_response id='sim-target-1' status='201'/>")

    def create_task(self, name, config_id, target_id, scanner_id):
        self.served.append(("create_task", name))
        self.created_tasks.append({"name": name, "target_id": target_id})
        return ET.fromstring("<create_task_response id='sim-task-1' status='201'/>")

    def start_task(self, task_id):
        self.served.append(("start_task", task_id))
        self.started_tasks.append(task_id)
        return ET.fromstring("<start_task_response status='202'/>")

    def get_task(self, task_id):
        self.served.append(("get_task", task_id))
        root = Element("get_tasks_response")
        task = SubElement(root, "task", {"id": str(task_id)})
        SubElement(task, "status").text = "Done"
        SubElement(task, "progress").text = "100"
        return root

    def get_results(self, task_id=None, details=True):
        self.served.append(("get_results", task_id))
        root = Element("get_results_response")
        for n, d in enumerate(self.estate.detections_for("openvas"), 1):
            h, v = d["host"], d["vuln"]
            res = SubElement(root, "result", {"id": f"sim-result-{n:05d}", "creation_time": estate_mod.timestamp(d["first_seen"]),
                                              "modification_time": estate_mod.timestamp(d["last_seen"], 4)})
            SubElement(res, "name").text = v["title"]
            host = SubElement(res, "host")
            host.text = h["ip"]
            SubElement(host, "hostname").text = h["fqdn"]
            SubElement(res, "port").text = f"{d['port'] or 'general'}/{d['protocol']}"
            SubElement(res, "severity").text = str(v["cvss"])
            SubElement(res, "threat").text = v["severity"]
            SubElement(res, "description").text = v["synopsis"]
            nvt = SubElement(res, "nvt", {"oid": v["oid"]})
            SubElement(nvt, "cve").text = v["cve"]
            SubElement(nvt, "cvss_base").text = str(v["cvss"])
            SubElement(nvt, "tags").text = f"summary={v['synopsis'].replace('|', ' ')}|solution={v['solution'].replace('|', ' ')}|solution_type=VendorFix"
        return root


def render_openvas(estate, values=None):
    return SimulatedGmp(estate)


def sim_now():
    """The simulated 'current time' handed to connectors that take a `now` (the AI usage ones): fixed, never the clock."""
    return estate_mod.build().now()


def _header(req, name):
    low = name.lower()
    return next((v for k, v in req.headers.items() if k.lower() == low), None)


def _unauthorized(req, *names):
    if any(not _header(req, n) for n in names):
        return 401, None, {"error": "unauthorized"}
    return None


# --------------------------------------------------------------------------- Prisma Cloud (CSPM)
def render_prismacloud(estate, values=None):
    policies = {p["key"]: p for p in estate_mod.POSTURE_POLICIES}

    def login(req):
        if not (req.json or {}).get("username"):
            return 401, None, {"message": "invalid_credentials"}
        return _json({"token": f"simulated-prisma-token-{estate.seed}", "message": "login_successful", "customerNames": [{"customerName": "Simulation", "prismaId": "0000000000"}]})

    def alert(a):
        p = policies[a["policy"]]
        return {"id": a["id"], "status": a["status"], "reason": "RESOURCE_UPDATED", "firstSeen": estate_mod.epoch_ms(a["first_seen"]),
                "lastSeen": estate_mod.epoch_ms(a["last_seen"], 4), "alertTime": estate_mod.epoch_ms(a["last_seen"], 4),
                "policy": {"policyId": f"sim-{p['key']}", "name": p["name"], "policyType": "config", "severity": p["severity"], "description": p["description"],
                           "recommendation": "Follow the cloud provider's guidance for this setting, then re-scan."},
                "resource": a["resource"]}

    def search(req):
        bad = _unauthorized(req, "x-redlock-auth")
        if bad:
            return bad
        status = next((f.get("value") for f in (req.json or {}).get("filters", []) if f.get("name") == "alert.status"), None)
        items = [alert(a) for a in estate.cloud_alerts if status in (None, a["status"])]
        return _json({"items": items, "totalRows": len(items)})

    return ReplaySession([("POST", r"/login$", login), ("POST", r"/v2/alert$", search)])


# --------------------------------------------------------------------------- Cortex XSIAM (incidents)
def render_cortex_xsiam(estate, values=None):
    def incident(i):
        return {"incident_id": i["incident_id"], "incident_name": i["incident_name"], "description": i["description"], "status": i["status"],
                "severity": i["severity"], "creation_time": estate_mod.epoch_ms(i["creation_time"], 8), "modification_time": estate_mod.epoch_ms(i["modification_time"], 14),
                "detection_time": None, "hosts": list(i["hosts"]), "host_count": len(i["hosts"]), "alert_count": i["alert_count"],
                "mitre_technique_id_and_name": list(i["mitre"]), "assigned_user_mail": None, "starred": False}

    def get_incidents(req):
        bad = _unauthorized(req, "x-xdr-auth-id", "Authorization")
        if bad:
            return bad
        rd = (req.json or {}).get("request_data") or {}
        start, stop = max(0, int(rd.get("search_from", 0))), max(0, int(rd.get("search_to", 100)))
        wanted = next((f.get("value") for f in rd.get("filters", []) if f.get("field") == "status"), None)
        rows = [i for i in estate.incidents if not wanted or i["status"] in wanted]
        page = [incident(i) for i in rows[start:stop]]
        return _json({"reply": {"total_count": len(rows), "result_count": len(page), "incidents": page}})

    return ReplaySession([("POST", r"/public_api/v1/incidents/get_incidents$", get_incidents)])


# --------------------------------------------------------------------------- Infoblox NIOS (WAPI)
def _b64(text):
    import base64
    return base64.b64encode(text.encode()).decode().rstrip("=")


def render_infoblox(estate, values=None):
    records = [(h["fqdn"], h["ip"], {"Owner Team": {"value": h["owner_team"]}, "Environment": {"value": h["environment"]}}) for h in estate.hosts]
    records += [(u["fqdn"], u["ip"], {"Owner Team": {"value": u["owner_team"]}}) for u in estate.unmanaged]

    def host_records(req):
        limit = int(req.params.get("_max_results", 1000))
        out = []
        for name, ip, ext in records[:max(1, limit)]:
            ref = f"record:host/{_b64('dns.host$._default.test.corp.' + name)}:{name}/default"
            out.append({"_ref": ref, "name": name, "view": "default", "extattrs": ext,
                        "ipv4addrs": [{"_ref": f"record:host_ipv4addr/{_b64('dns.host_ipv4addr$.' + ip)}:{ip}/{name}/default", "configure_for_dhcp": False,
                                       "host": name, "ipv4addr": ip}]})
        return 200, None, out

    return ReplaySession([("GET", r"/wapi/v[\d.]+/record:host$", host_records)])


# --------------------------------------------------------------------------- Axonius (devices)
_AXONIUS_OS = {"windows": "Windows", "linux": "Linux", "network": "Cisco IOS", "firewall": "PAN-OS", "workstation": "Windows", "iot": "Linux"}
_AXONIUS_ADAPTERS = {"tenable": "tenable_io_adapter", "qualys": "qualys_adapter", "openvas": "openvas_adapter", "prismacloud": "aws_adapter",
                     "infoblox": "infoblox_adapter", "active-directory": "active_directory_adapter", "cortex-xsiam": "cortex_xdr_adapter"}


def render_axonius(estate, values=None):
    import hashlib
    devices = []
    for h in estate.hosts:
        adapters = [a for src, a in _AXONIUS_ADAPTERS.items() if h["id"] in set(estate.coverage.get(src, []))]
        devices.append((h["fqdn"], h["ip"], h["mac"], _AXONIUS_OS[h["family"]], adapters))
    for u in estate.unmanaged:  # only the directory and DNS know these; no scanner does
        devices.append((u["fqdn"], u["ip"], u["mac"], _AXONIUS_OS[u["family"]], ["infoblox_adapter"] + (["active_directory_adapter"] if u["family"] == "workstation" else [])))

    def search(req):
        bad = _unauthorized(req, "api-key", "api-secret")
        if bad:
            return bad
        page = (req.json or {}).get("page") or {}
        offset, limit = max(0, int(page.get("offset", 0))), max(1, int(page.get("limit", 50)))
        rows = [{"internal_axon_id": hashlib.sha256(f"quanta-sim:{name}".encode()).hexdigest()[:32], "hostname": name, "ips": [ip], "macs": [mac], "os_type": os_type,
                 "adapters": adapters, "adapter_count": len(adapters)} for name, ip, mac, os_type, adapters in devices[offset:offset + limit]]
        return _json({"assets": rows, "page": {"totalResources": len(devices), "pageSize": limit, "pageNumber": offset // limit}})

    return ReplaySession([("POST", r"/api/devices$", search)])


# --------------------------------------------------------------------------- Active Directory (LDAP, not HTTP)
class _Attr:
    def __init__(self, value):
        self.value = value


class _Entry:
    """Stands in for an ldap3 Entry: only populated attributes exist, each with a `.value`."""

    def __init__(self, **attrs):
        for k, v in attrs.items():
            if v is not None:
                setattr(self, k, _Attr(v))


class SimulatedLdap:
    """A connection double with the surface remediation/connectors/active_directory_connector.py uses: `search(base, filter, attributes=, search_scope=)`,
    `.entries`, `unbind()`. It answers a computer search with the directory's computer objects and a base-scope probe with the root object."""

    def __init__(self, estate, base_dn="DC=corp,DC=test"):
        self.estate = estate
        self.base_dn = base_dn
        self.entries = []
        self.searches = []
        self.unbound = False

    def _computers(self):
        e = self.estate
        for h in e.hosts_for("active-directory"):
            ou = "Domain Controllers" if h["role"] == "dc" else "Servers"
            ver = {"2016": "10.0 (14393)", "2019": "10.0 (17763)", "2022": "10.0 (20348)"}[h["os"].split("Server ")[1][:4]]
            yield _Entry(cn=h["name"].upper(), dNSHostName=h["fqdn"], operatingSystem=h["os"].replace("Microsoft ", ""), operatingSystemVersion=ver,
                         distinguishedName=f"CN={h['name'].upper()},OU={ou},{self.base_dn}",
                         managedBy=f"CN={h['owner_team']},OU=Groups,{self.base_dn}", userAccountControl=532480 if h["role"] == "dc" else 4096)
        for u in e.unmanaged:
            if u["family"] == "workstation":
                yield _Entry(cn=u["name"].upper(), dNSHostName=u["fqdn"], operatingSystem=u["os"],
                             operatingSystemVersion="10.0 (22631)" if "11" in u["os"] else "10.0 (19045)",
                             distinguishedName=f"CN={u['name'].upper()},OU=Workstations,{self.base_dn}",
                             managedBy=f"CN={u['owner_team']},OU=Groups,{self.base_dn}", userAccountControl=4096 if u["enabled"] else 4098)

    def search(self, search_base, search_filter, attributes=None, search_scope=None):
        self.searches.append((search_base, search_filter, tuple(attributes or ()), search_scope))
        if "objectclass=computer" in search_filter.replace(" ", "").lower():
            self.entries = list(self._computers())
        else:  # a base-scope probe (the connection test): the root object itself
            self.entries = [_Entry(distinguishedName=self.base_dn)]
        return True

    def unbind(self):
        self.unbound = True


def render_active_directory(estate, values=None):
    return SimulatedLdap(estate)


# --------------------------------------------------------------------------- AI usage (Anthropic Usage & Cost, OpenAI organization usage)
_USAGE_PAGE = 3  # buckets per page, small so the connector's paging loop always runs


def _day_start(date):
    import datetime
    return datetime.datetime.combine(date, datetime.time(0, 0), tzinfo=datetime.timezone.utc)


def _days_in_window(start, end):
    """The UTC days whose bucket overlaps [start, end)."""
    import datetime
    d = start.date()
    out = []
    while _day_start(d) < end:
        if _day_start(d) + datetime.timedelta(days=1) > start:
            out.append(d)
        d += datetime.timedelta(days=1)
    return out


def _page_of(days, req):
    """Opaque page tokens: the index of the first bucket of the page."""
    limit = max(1, min(int(req.params.get("limit", _USAGE_PAGE)), _USAGE_PAGE))
    token = req.params.get("page")
    first = int(token.split("_", 1)[1]) if token and token.startswith("pg_") else 0
    chunk = days[first:first + limit]
    more = first + limit < len(days)
    return chunk, more, (f"pg_{first + limit}" if more else None)


def render_anthropic_usage(estate, values=None):
    import datetime

    def parse(text):
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))

    def iso(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def report(req):
        if not _header(req, "x-api-key") or not _header(req, "anthropic-version"):
            return 401, None, {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}
        start = parse(req.params["starting_at"])
        end = parse(req.params["ending_at"]) if req.params.get("ending_at") else estate.now()
        chunk, more, nxt = _page_of(_days_in_window(start, end), req)
        data = []
        for d in chunk:
            results = []
            for app, ws, key, models in estate.usage_workspaces("anthropic"):
                for model in models:
                    u = estate.usage_for("anthropic", d, app, ws, model)
                    results.append({"uncached_input_tokens": u["uncached_input"], "cache_creation": {"ephemeral_1h_input_tokens": u["cache_1h"], "ephemeral_5m_input_tokens": u["cache_5m"]},
                                    "cache_read_input_tokens": u["cache_read"], "output_tokens": u["output"], "server_tool_use": {"web_search_requests": 0},
                                    "api_key_id": key, "workspace_id": ws, "model": model, "service_tier": "standard", "context_window": "0-200k"})
            data.append({"starting_at": iso(_day_start(d)), "ending_at": iso(_day_start(d + datetime.timedelta(days=1))), "results": results})
        return _json({"data": data, "has_more": more, "next_page": nxt})

    return ReplaySession([("GET", r"/v1/organizations/usage_report/messages$", report)])


def render_openai_usage(estate, values=None):
    import datetime

    def report(req):
        auth = _header(req, "Authorization") or ""
        if not auth.startswith("Bearer ") or len(auth) <= 7:
            return 401, None, {"error": {"message": "Incorrect API key provided", "type": "invalid_request_error"}}
        start = datetime.datetime.fromtimestamp(int(req.params["start_time"]), datetime.timezone.utc)
        chunk, more, nxt = _page_of(_days_in_window(start, estate.now()), req)
        data = []
        for d in chunk:
            results = []
            for app, proj, key, models in estate.usage_workspaces("openai"):
                for model in models:
                    u = estate.usage_for("openai", d, app, proj, model)
                    results.append({"object": "organization.usage.completions.result", "input_tokens": u["uncached_input"] + u["cache_read"], "input_cached_tokens": u["cache_read"],
                                    "output_tokens": u["output"], "num_model_requests": u["requests"], "project_id": proj, "user_id": None, "api_key_id": None,
                                    "model": model, "batch": False})
            data.append({"object": "bucket", "start_time": int(_day_start(d).timestamp()), "end_time": int(_day_start(d + datetime.timedelta(days=1)).timestamp()), "results": results})
        return _json({"object": "page", "data": data, "has_more": more, "next_page": nxt})

    return ReplaySession([("GET", r"/v1/organization/usage/completions$", report)])


RENDERERS = {"tenable": render_tenable, "qualys": render_qualys, "openvas": render_openvas, "prismacloud": render_prismacloud, "cortex-xsiam": render_cortex_xsiam,
             "infoblox": render_infoblox, "axonius": render_axonius, "active-directory": render_active_directory,
             "anthropic-usage": render_anthropic_usage, "openai-usage": render_openai_usage}
LABELS = {"tenable": "Tenable.io", "qualys": "Qualys VMDR", "openvas": "OpenVAS / Greenbone (GVM)", "prismacloud": "Prisma Cloud", "cortex-xsiam": "Cortex XSIAM",
          "infoblox": "Infoblox", "axonius": "Axonius", "active-directory": "Active Directory", "anthropic-usage": "Anthropic usage (AI spend)",
          "openai-usage": "OpenAI usage (AI spend)"}


def implemented():
    """The connection types that have a renderer, in a stable order."""
    return sorted(RENDERERS)


def session_for(conn_type, values=None, estate=None):
    """The transport to hand a connector's `session=` (or `gmp_client=`) for a simulation connection."""
    if conn_type not in RENDERERS:
        raise KeyError(f"No simulation is available for connector type {conn_type!r}")
    return RENDERERS[conn_type](estate or estate_mod.build(), values or {})
