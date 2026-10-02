"""
Draft a threat model from what Quanta already knows, so a model starts from the real estate instead of a blank page.

Takes the assets that appear in the findings (optionally only those matching name patterns), makes one component per asset, and uses the
hand-maintained network topology (network_topology.yaml) to mark which are reachable from the internet. Every component it creates is marked
`inferred`: it is a starting point for a person to correct, not a statement of fact. Security properties (authentication, encryption,
logging, input validation) are deliberately left unset, which makes the rules raise them as "unconfirmed" questions rather than assuming either way.
"""
import fnmatch
import re

TYPE_MAP = {
    "windows-server": "service", "unix-server": "service", "windows-endpoint": "process", "unix-endpoint": "process",
    "network-routing-switching": "service", "network-security-device": "service", "iot-ot-device": "service", "virtualization-host": "service",
    "cloud-infrastructure": "service", "application": "process", "client-application": "process", "container-runtime": "process",
    "code-repository": "process", "iac-resource": "service", "ai-ml-system": "ai-model",
}
SKIP = {"certificate", "mobile-device", "printer"}
MAX_ASSETS = 60


def _slug(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-")[:60] or "asset"


def from_findings(findings, patterns=None, topology=None):
    counts, types = {}, {}
    for f in findings:
        a = f.get("asset") or {}
        name, typ = a.get("name"), a.get("type")
        if not name or typ in SKIP:
            continue
        if patterns and not any(fnmatch.fnmatchcase(name.lower(), p.lower()) for p in patterns):
            continue
        counts[name] = counts.get(name, 0) + 1
        types[name] = typ
    chosen = sorted(counts, key=lambda n: (-counts[n], n))[:MAX_ASSETS]
    from remediation.enrichment import network_reachability
    topo = topology
    comps, flows, used = [], [], set()
    for name in chosen:
        try:
            exposed = network_reachability.trace_path(name, topo)["verdict"] == "allowed"
        except Exception:  # noqa: BLE001 - an unreadable topology file must not block drafting
            exposed = False
        cid = _slug(name)
        while cid in used:
            cid += "-x"
        used.add(cid)
        comps.append({"id": cid, "name": name, "type": TYPE_MAP.get(types[name], "service"), "assets": [name], "internet_facing": exposed,
                      "trust_zone": "exposed" if exposed else "internal", "inferred": True, "technology": types[name]})
    exposed_components = [c for c in comps if c["internet_facing"]]
    if exposed_components:
        comps.insert(0, {"id": "users", "name": "Users and the internet", "type": "external", "trust_zone": "internet", "inferred": True})
        for c in exposed_components:
            flows.append({"id": f"users->{c['id']}", "from": "users", "to": c["id"], "protocol": "unknown", "inferred": True})
    return {"components": comps, "data_flows": flows,
            "trust_zones": [{"id": "internet", "name": "Internet", "trust": 0}, {"id": "exposed", "name": "Internet-facing", "trust": 1}, {"id": "internal", "name": "Internal", "trust": 2}],
            "data_classes": []}
