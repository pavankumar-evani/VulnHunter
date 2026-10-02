"""
Proposes hunts from the vulnerabilities actually in the estate. A CVE that is on CISA's KEV list (or has a high EPSS score) and is open on at least one
asset becomes one hypothesis: "someone may already have exploited CVE-X on these assets", with the ATT&CK techniques Quanta tags for those findings,
the affected hosts, and a query per detection from the hunt library. Techniques with no library entry still produce a hunt, with no queries and a
note saying so.

Nothing here is a detection claim. A proposed hunt means the exposure makes it worth looking, not that anything happened.
"""
from pathlib import Path

import yaml

from remediation.hunting import translate

LIBRARY_PATH = Path(__file__).with_name("library.yaml")
DEFAULT_EPSS = 0.5


def library():
    with open(LIBRARY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def build_queries(technique_ids, hosts, lib=None, index=None):
    lib = lib if lib is not None else library()
    out = []
    for tid in technique_ids:
        entry = lib.get(tid)
        if not entry:
            continue
        for d in entry.get("detections", []):
            out.append({"technique": tid, "name": d["name"], "domain": entry.get("domain", "endpoint"), "source": "SIEM", "language": "splunk-spl",
                        "query": translate.to_spl(d["selection"], hosts, index), "result": None, "notes": ""})
    return out


def data_sources(technique_ids, lib=None):
    lib = lib if lib is not None else library()
    seen = []
    for tid in technique_ids:
        for ds in (lib.get(tid) or {}).get("data_sources", []):
            if ds not in seen:
                seen.append(ds)
    return seen


def _short(text, n=90):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "..."


def _is_open(f):
    return not (f.get("status") in ("resolved", "closed") or (f.get("exception") or {}).get("active"))


def candidates(findings, epss_min=DEFAULT_EPSS):
    """{cve: {...}} for each CVE that is KEV-listed or has EPSS >= epss_min on at least one open finding."""
    groups = {}
    for f in findings:
        cve = f.get("cve")
        if not cve or not _is_open(f):
            continue
        kev = bool((f.get("kev") or {}).get("listed"))
        epss = (f.get("epss") or {}).get("score") or 0
        if not kev and epss < epss_min:
            continue
        g = groups.setdefault(cve, {"cve": cve, "title": _short((f.get("kev") or {}).get("vulnerability_name") or f.get("title") or cve), "kev": False, "epss": 0, "ransomware": False, "hosts": set(),
                                    "findings": [], "techniques": {}})
        g["kev"] = g["kev"] or kev
        g["epss"] = max(g["epss"], epss)
        g["ransomware"] = g["ransomware"] or (f.get("kev") or {}).get("known_ransomware_campaign_use") == "Known"
        name = (f.get("asset") or {}).get("name")
        if name:
            g["hosts"].add(name)
        g["findings"].append(f.get("id"))
        for t in f.get("attack_techniques") or []:
            g["techniques"][t["technique_id"]] = t["technique_name"]
    return groups


def propose(findings, existing_refs=(), epss_min=DEFAULT_EPSS, index=None):
    """Hunt proposals, most urgent first, skipping CVEs that already have a hunt."""
    lib, out = library(), []
    for cve, g in candidates(findings, epss_min).items():
        if cve in set(existing_refs):
            continue
        tids = sorted(g["techniques"])
        hosts = sorted(g["hosts"])
        why = ("on CISA's Known Exploited Vulnerabilities list" if g["kev"] else f"with a {round(g['epss'] * 100)}% exploitation probability (EPSS)")
        hypothesis = (f"{cve} ({g['title']}) is {why} and is open on {len(hosts)} asset{'s' if len(hosts) != 1 else ''}. "
                      "An adversary may already have exploited it. Look for exploitation attempts and for activity after a successful one.")
        missing = [t for t in tids if t not in lib]
        queries = build_queries(tids, hosts, lib, index)
        out.append({"title": f"Exploitation of {cve}", "hypothesis": hypothesis, "source": "generated", "source_ref": cve,
                    "techniques": [{"technique_id": t, "technique_name": g["techniques"][t]} for t in tids], "assets": hosts,
                    "data_sources": data_sources(tids, lib), "queries": queries, "finding_ids": g["findings"][:50],
                    "priority": (2 if g["kev"] else 0) + (1 if g["ransomware"] else 0) + g["epss"],
                    "notes": ("No library queries exist for " + ", ".join(missing) + "; write them for your data model.") if missing
                    else "No ATT&CK technique is tagged for these findings, so no queries were generated; write them for your data model." if not tids else ""})
    return sorted(out, key=lambda h: -h["priority"])
