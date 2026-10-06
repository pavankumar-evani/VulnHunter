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


RENDERERS = {"tenable": render_tenable, "qualys": render_qualys, "openvas": render_openvas}
LABELS = {"tenable": "Tenable.io", "qualys": "Qualys VMDR", "openvas": "OpenVAS / Greenbone (GVM)"}


def implemented():
    """The connection types that have a renderer, in a stable order."""
    return sorted(RENDERERS)


def session_for(conn_type, values=None, estate=None):
    """The transport to hand a connector's `session=` (or `gmp_client=`) for a simulation connection."""
    if conn_type not in RENDERERS:
        raise KeyError(f"No simulation is available for connector type {conn_type!r}")
    return RENDERERS[conn_type](estate or estate_mod.build(), values or {})
