"""A small, hand-built estate shared by the ontology tests: module graphs in each module's own vocabulary, findings and a controls inventory.

Facts built in (the expectations in the tests rest on these):
  * infra: internet -reaches-> fw-edge -routes_to-> web-01, and web-01 -pivot-> db-01      (so both assets are internet-facing; db-01 only by pivot)
  * remediation: team platform owns web-01; db-01 is in the graph with no owner
  * devsecops: orders uses log4j-core
  * ai: bot (system) can_call shell (tool) and reads web (data source)
  * findings: F1 on web-01 (CVE-A, KEV listed, dependency log4j-core), F2 on db-01 (CVE-B, not KEV), F3 on web-01 with no CVE
  * controls: one verified EDR control on db-*
"""
from remediation.graphs.schema import GraphBuilder, prov


def infra():
    g = GraphBuilder("infra", "Exposure and movement", "d")
    g.node("internet", "Internet", "internet")
    g.node("hop:fw-edge", "fw-edge", "hop", meta={"hop_type": "firewall"})
    g.node("asset:web-01", "web-01", "asset", weight=2, sev="critical", meta={"open_findings": 2, "type": "unix-server"})
    g.node("asset:db-01", "db-01", "asset", weight=1, sev="high", meta={"open_findings": 1, "type": "unix-server"})
    topo = prov(source="network_topology.yaml", source_kind="user", confidence="declared")
    g.edge("internet", "hop:fw-edge", "reaches", prov=topo)
    g.edge("hop:fw-edge", "asset:web-01", "routes_to", prov=topo)
    g.edge("asset:web-01", "asset:db-01", "pivot", label="lateral-movement", prov=prov(source="attack_chains", source_kind="derived", confidence="heuristic"))
    return g.build()


def remediation():
    g = GraphBuilder("remediation", "Ownership", "d")
    g.node("team:platform", "platform", "team")
    g.node("asset:web-01", "web-01", "asset", weight=2)
    g.node("asset:db-01", "db-01", "asset", weight=1, meta={"unowned": True})
    g.edge("team:platform", "asset:web-01", "owns", prov=prov(source="asset ownership record", confidence="declared"))
    return g.build()


def devsecops():
    g = GraphBuilder("devsecops", "Supply chain", "d")
    g.node("app:orders", "orders", "application", meta={"environment": "production"})
    g.node("pkg:maven:org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-core", "package", meta={"ecosystem": "maven", "vulnerable": True})
    g.edge("app:orders", "pkg:maven:org.apache.logging.log4j:log4j-core", "uses", label="2.14.1",
           prov=prov(source="SBOM (ci)", observed_at="2026-10-01T10:00:00Z", confidence="declared"))
    return g.build()


def ai():
    g = GraphBuilder("ai", "AI dependencies", "d")
    g.node("system:bot", "bot", "system", meta={"kind": "agent"})
    g.node("tool:shell", "shell", "tool")
    g.node("data-source:web", "web", "data-source")
    g.edge("system:bot", "tool:shell", "can_call")
    g.edge("system:bot", "data-source:web", "reads")
    return g.build()


def graphs():
    return {"infra": infra(), "remediation": remediation(), "devsecops": devsecops(), "ai": ai()}


def findings():
    def f(i, name, cve, kev, sev="critical", pkg=None):
        d = {"id": f"F{i}", "title": f"Finding {i}", "severity": sev, "asset": {"hostname": name, "type": "unix-server"}, "source": "tenable",
             "first_seen": "2026-09-01", "last_seen": "2026-10-02", "scan_type": "vuln"}
        if cve:
            d.update(cve=cve, kev={"listed": kev}, epss={"score": 0.5})
        if pkg:
            d["dependency"] = {"package": pkg}
        return d
    return [f(1, "web-01", "CVE-A", True, pkg="log4j-core"), f(2, "db-01", "CVE-B", False, sev="high"), f(3, "web-01", None, None, sev="low")]


def controls():
    return [{"id": 1, "asset_name": "db-*", "control_class": "edr", "name": "EDR on databases", "state": "verified", "source": "crowdstrike", "last_seen": "2026-10-01T00:00:00Z"}]


def estate_graph(**kw):
    from remediation.ontology import estate
    kw.setdefault("controls", controls())
    return estate.build(findings=findings(), graphs=graphs(), modules=("infra", "remediation", "devsecops", "ai"), **kw)
