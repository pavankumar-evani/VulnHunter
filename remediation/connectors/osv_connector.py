"""
OSV.dev connector: asks the public Open Source Vulnerabilities database which known advisories affect the packages in an application's SBOM.

Implements the documented OSV API (https://google.github.io/osv.dev/api/):
  - POST /v1/querybatch   ({"queries": [{"package": {"purl": ...}}, ...]}) -> {"results": [{"vulns": [{"id": ...}]}, ...]}
  - GET  /v1/vulns/{id}   -> the advisory: summary, aliases (CVE ids), severity, affected ranges with `fixed` events

Only package URLs and versions are sent, never the application name, repository or any finding. Quanta ships no vulnerability database of its own, so
this is how an SBOM alone (without an SCA scanner) becomes a vulnerable-component view. It is an outbound call to a third party, so the route that uses
it is admin-gated, shows what would be sent first, and runs only after confirmation.

Honest limits: built against OSV's public documentation and unit-tested against a hand-rolled fake session; it has not been run against the live
service from this repository. OSV returns a CVSS vector rather than a number, and Quanta does not compute scores from vectors, so a finding created
from OSV carries the advisory's severity label and the ranking marks the CVSS score as assumed. OSV has no exploit-prediction or known-exploited data:
Quanta's own CVE enrichment adds those when the finding has a CVE alias.
"""
import re

import requests

from remediation.appsec import versions
from remediation.utils.retry import retry_with_backoff

BASE_URL = "https://api.osv.dev"
BATCH = 500
MAX_COMPONENTS = 2000
MAX_ADVISORIES = 600
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}
_RETRY = (requests.exceptions.ConnectionError, requests.exceptions.Timeout)


class OsvError(RuntimeError):
    pass


class OsvConnector:
    def __init__(self, base_url=BASE_URL, session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()

    def _post(self, path, body):
        def call():
            r = self.session.post(self.base_url + path, json=body, timeout=30)
            if r.status_code >= 400:
                raise OsvError(f"OSV answered {r.status_code} for {path}")
            return r.json()
        return retry_with_backoff(call, retryable_exceptions=_RETRY)

    def _get(self, path):
        def call():
            r = self.session.get(self.base_url + path, timeout=30)
            if r.status_code >= 400:
                raise OsvError(f"OSV answered {r.status_code} for {path}")
            return r.json()
        return retry_with_backoff(call, retryable_exceptions=_RETRY)

    def test_connection(self):
        """The cheapest real call: an empty batch query."""
        self._post("/v1/querybatch", {"queries": []})
        return True

    def query(self, components):
        """components: [{"purl" | ("ecosystem", "name"), "version"}] -> [[advisory id, ...], ...] in the same order."""
        if len(components) > MAX_COMPONENTS:
            raise OsvError(f"Too many components for one check ({len(components)}; the limit is {MAX_COMPONENTS})")
        out = []
        for i in range(0, len(components), BATCH):
            queries = []
            for c in components[i:i + BATCH]:
                q = {"package": {"purl": c["purl"]}} if c.get("purl") and "@" in c["purl"] else {"package": {"name": c["name"], "ecosystem": c["ecosystem"]}, "version": c["version"]}
                queries.append(q)
            res = self._post("/v1/querybatch", {"queries": queries}).get("results") or []
            res += [{}] * (len(queries) - len(res))
            out += [[v["id"] for v in (r.get("vulns") or []) if v.get("id")] for r in res]
        return out

    def advisory(self, advisory_id):
        if not re.match(r"^[A-Za-z0-9_.:-]{3,80}$", advisory_id):
            raise OsvError("Unexpected advisory id")
        return self._get("/v1/vulns/" + advisory_id)


def fixed_version(advisory, ecosystem, name, current):
    """The lowest fixed version above `current` among the advisory's affected ranges for this package, or None."""
    best = None
    for aff in advisory.get("affected") or []:
        pkg = aff.get("package") or {}
        have, want = (pkg.get("name") or "").lower(), (name or "").lower()
        if have != want and not have.endswith(":" + want.rsplit(":", 1)[-1]) and not (pkg.get("purl") or "").lower().startswith(f"pkg:{(ecosystem or '').lower()}/"):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                fx = ev.get("fixed")
                if fx and versions.compare(fx, current) == 1 and (best is None or versions.compare(fx, best) == -1):
                    best = fx
    return best


def severity_of(advisory):
    label = ((advisory.get("database_specific") or {}).get("severity") or "").upper()
    return _SEV.get(label)


def to_findings(application, components, advisories_by_component, today):
    """Findings in Quanta's schema: one per (component, advisory). `advisories_by_component` is [(component, advisory dict), ...]."""
    out = []
    for comp, adv in advisories_by_component:
        cves = [a for a in (adv.get("aliases") or []) + [adv.get("id", "")] if _CVE.match(a)]
        sev = severity_of(adv) or "Medium"
        fixed = fixed_version(adv, comp.get("ecosystem"), comp.get("name"), comp.get("version"))
        pkg = f"{comp['group']}:{comp['name']}" if comp.get("group") and comp.get("ecosystem") == "maven" else comp["name"]
        out.append({"source_ref": f"{adv['id']}:{comp.get('purl') or pkg + '@' + str(comp.get('version'))}", "title": (adv.get("summary") or adv["id"])[:300], "severity": sev,
                    "cvss": None, "cve": cves[0].upper() if cves else None, "cwe": (adv.get("database_specific") or {}).get("cwe_ids") or [], "rule_id": adv["id"], "tool": "OSV.dev",
                    "scan_type": "sca", "asset": {"name": application, "ip": None, "type": "application", "os": None},
                    "description": (adv.get("details") or adv.get("summary") or "")[:2000],
                    "recommended_fix": (f"Upgrade {pkg} to {fixed} or later." if fixed else "No fixed version is listed in the advisory; check the package's releases."),
                    "location": {"file": None, "line": None, "url": f"https://osv.dev/vulnerability/{adv['id']}", "snippet": None},
                    "remediation_domain": "application" if cves else None, "first_seen": today, "last_seen": today, "kev": None, "epss": None,
                    "dependency": {"package": pkg, "ecosystem": comp.get("ecosystem"), "version": comp.get("version"), "fixed_version": fixed, "direct": comp.get("direct")}})
    return out
