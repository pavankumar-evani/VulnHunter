"""
A small, clearly labelled demo for the application-security pages, so a fresh install has something to click through.

`seed()` registers one application from the sample CycloneDX SBOM (remediation/sample-data/sbom.json), and merges a handful of dependency and code findings under
the source name `appsec-demo` so `remove()` can take exactly those back out. It never touches findings from any other source. It prints (does not write) the
network-topology entry that would make the graph's exposure lane show a path, because that file is hand-maintained configuration.

Run it with `python cli/quanta_admin.py seed-appsec-demo` (and `--remove` to undo). The findings are invented for the demo; the CVE ids are real, public ones.
"""
import datetime
import json
from pathlib import Path

from remediation.appsec import store
from remediation.ingest import merge

SOURCE = "appsec-demo"
SAMPLE_SBOM = Path(__file__).resolve().parent.parent / "sample-data" / "sbom.json"

TOPOLOGY_SNIPPET = """assets:
  - match:
      name: "{name}"
    path_to_internet:
      - {{hop_type: "waf", name: "Edge-WAF", default_action: "allow"}}
      - {{hop_type: "load_balancer", name: "App-LB", default_action: "allow"}}
      - {{hop_type: "dmz", name: "DMZ-A", default_action: "allow"}}
      - {{hop_type: "firewall", name: "Core-FW", default_action: "allow"}}
"""


def _dep(ref, name, pkg, version, fixed, cve, severity, cvss, kev, epss, today):
    return {"source_ref": ref, "title": f"{cve} in {pkg}", "severity": severity, "cvss": cvss, "cve": cve, "cwe": [], "rule_id": cve, "tool": "demo", "scan_type": "sca",
            "asset": {"name": name, "ip": None, "type": "application", "os": None}, "description": f"Demo finding for {pkg} {version}.", "recommended_fix": f"Upgrade {pkg} to {fixed}.",
            "location": {"file": None, "line": None, "url": None, "snippet": None}, "remediation_domain": "application", "first_seen": today, "last_seen": today,
            "kev": {"listed": True, "date_added": "2021-12-10", "vulnerability_name": cve} if kev else None, "epss": {"score": epss, "percentile": None} if epss is not None else None,
            "dependency": {"package": pkg, "ecosystem": "maven", "version": version, "fixed_version": fixed, "direct": None}}


def findings(name, today):
    return [
        _dep("demo-1", name, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", "Critical", 10.0, True, 0.97, today),
        _dep("demo-2", name, "log4j-core", "2.14.1", "2.15.0", "CVE-2021-45046", "Critical", 9.0, False, 0.6, today),
        _dep("demo-3", name, "jackson-databind", "2.12.4", "2.12.7.1", "CVE-2022-42003", "High", 7.5, False, 0.05, today),
        _dep("demo-4", name, "spring-boot-starter-web", "2.5.4", "2.7.18", "CVE-2022-22965", "Critical", 9.8, True, 0.9, today),
        {"source_ref": "demo-5", "title": "SQL injection in the user lookup", "severity": "High", "cvss": None, "cve": None, "cwe": ["CWE-89"], "rule_id": "demo.sqli", "tool": "demo", "scan_type": "sast",
         "asset": {"name": name, "ip": None, "type": "application", "os": None}, "description": "String concatenation builds a SQL query from request input.",
         "recommended_fix": "Use a parameterised query.", "location": {"file": "app/db.py", "line": 3, "url": None, "snippet": None}, "remediation_domain": None,
         "first_seen": today, "last_seen": today, "kev": None, "epss": None},
    ]


def seed(name="orders-service", actor="seed", engine=None, findings_path=None):
    doc = json.loads(SAMPLE_SBOM.read_text(encoding="utf-8"))
    store.upsert_application(name, {"environment": "production", "platform": "demo", "owner": "demo.owner", "team": "Demo team", "business_criticality": "high", "internet_facing": True,
                                    "repo_provider": "github", "repo": "example/orders-service", "default_branch": "main", "manifest_paths": ["pom.xml"]}, actor, engine)
    sb = store.set_sbom(name, doc, "demo", actor, engine)
    today = datetime.date.today().isoformat()
    res = merge.merge(findings(name, today), SOURCE, path=findings_path, reconcile=True)
    return {"application": name, "components": sb["components"], "findings": res, "topology_snippet": TOPOLOGY_SNIPPET.format(name=name)}


def remove(name="orders-service", engine=None, findings_path=None):
    res = merge.merge([], SOURCE, path=findings_path, reconcile=True)
    return {"application_removed": store.delete_application(name, engine), "findings": res}
