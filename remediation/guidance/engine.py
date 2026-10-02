"""
Remediation guidance: turns a finding into a plain, ordered "how to fix this" for the analyst or developer.

Two parts, kept deliberately separate:

* a curated knowledge base (knowledge.yaml): the approach, the checks and the references for each class
  of problem, written and reviewed by people, identical on every run, and editable by your own team;
* tailoring from what Quanta actually knows about THIS finding: the vulnerable package and the fixed
  version, the operating system, whether the CVE is on the CISA KEV list, the SLA, what the scanner
  itself recommended, and, when the client has recorded them, the firewall and EDR controls already
  protecting the asset.

Matching is explicit and explainable (`matched_by` says why an entry was chosen): CWE first, then scan
type, asset type and keywords. When nothing matches, a generic approach is returned and labelled as such,
rather than a confident-sounding guess. This is guidance, not an automated change; `automation` says plainly
what Quanta can and cannot do for the finding.
"""
import re
from pathlib import Path

import yaml

KB_PATH = Path(__file__).resolve().parent / "knowledge.yaml"
_CACHE = {"mtime": None, "kb": None}
_CWE_RE = re.compile(r"CWE-(\d+)", re.I)
_KB_NUM = re.compile(r"\bKB\d{6,8}\b", re.I)
_GENERIC_FIX = re.compile(r"^\s*(see|refer to)\b.*\b(advisory|vendor)\b", re.I)

ECOSYSTEM_COMMANDS = {
    "npm": "npm install {package}@{fixed}  (then commit package.json and the lockfile)",
    "pypi": "pip install '{package}>={fixed}'  (then update requirements and the lockfile)",
    "maven": "set the version of {package} to {fixed} in pom.xml, then run mvn -U dependency:tree to confirm",
    "gradle": "set {package} to {fixed} in the build file, then run gradle dependencies to confirm",
    "nuget": "dotnet add package {package} --version {fixed}",
    "go": "go get {package}@v{fixed} && go mod tidy",
    "gem": "bundle update {package}  (and raise the constraint in the Gemfile to >= {fixed})",
    "cargo": "cargo update -p {package} --precise {fixed}",
    "composer": "composer require {package}:^{fixed}",
}


def load_kb(path=None):
    path = Path(path or KB_PATH)
    mtime = path.stat().st_mtime
    if _CACHE["kb"] is None or _CACHE["mtime"] != (str(path), mtime):
        _CACHE["kb"] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        _CACHE["mtime"] = (str(path), mtime)
    return _CACHE["kb"]


def finding_cwes(finding):
    """CWE ids on a finding, from an explicit field or mentioned in its text, as 'CWE-89' strings."""
    found = []
    explicit = finding.get("cwe")
    for raw in (explicit if isinstance(explicit, (list, tuple)) else [explicit]):
        for m in _CWE_RE.finditer(str(raw or "")):
            found.append(f"CWE-{m.group(1)}")
        if raw and str(raw).strip().isdigit():
            found.append(f"CWE-{str(raw).strip()}")
    text = f"{finding.get('title', '')} {finding.get('description', '')}"
    found += [f"CWE-{m.group(1)}" for m in _CWE_RE.finditer(text)]
    return list(dict.fromkeys(found))


def _scan_type(finding):
    if finding.get("scan_type"):
        return finding["scan_type"]
    from remediation.enrichment.scan_type_mapping import classify_finding
    return classify_finding(finding)


def _score(entry, finding, cwes, scan_type, asset_type, text):
    m = entry.get("match") or {}
    score, why = 0, []
    hit = [c for c in cwes if c in (m.get("cwe") or [])]
    if hit:
        score += 100
        why.append(f"CWE {', '.join(hit)}")
    # a scan type alone is not evidence when the entry is also tied to specific asset types (every unclassified
    # asset defaults to the infrastructure scan type), so there it only counts together with the asset type
    needs_asset = bool(m.get("asset_types"))
    asset_hit = asset_type in (m.get("asset_types") or [])
    if scan_type in (m.get("scan_types") or []) and (asset_hit or not needs_asset):
        score += 30
        why.append(f"scan type {scan_type}")
    if asset_hit:
        score += 25
        why.append(f"asset type {asset_type}")
    kw = [k for k in (m.get("keywords") or []) if k.lower() in text]
    if kw:
        score += min(20 * len(kw), 40)
        why.append("keyword " + ", ".join(f"'{k}'" for k in kw[:3]))
    return score, why


def match(finding, kb=None):
    """(entry, matched_by) for the best curated entry, or (fallback, None) when nothing fits well."""
    kb = kb or load_kb()
    cwes = finding_cwes(finding)
    scan_type = _scan_type(finding)
    asset_type = (finding.get("asset") or {}).get("type", "")
    text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('file', '')}".lower()
    best, best_score, best_why = None, 0, []
    for entry in kb.get("entries", []):
        s, why = _score(entry, finding, cwes, scan_type, asset_type, text)
        if s > best_score:
            best, best_score, best_why = entry, s, why
    if best is None or best_score < 30:
        return kb["fallback"], None
    return best, "; ".join(best_why)


def _tailor(finding):
    notes = []
    dep = finding.get("dependency") or {}
    if dep.get("package"):
        fixed = dep.get("fixed_version")
        line = f"Package {dep['package']}"
        if dep.get("ecosystem"):
            line += f" ({dep['ecosystem']})"
        line += f" is at {dep.get('version') or 'an unknown version'}"
        line += f"; the fixed version is {fixed}." if fixed else "; the advisory does not give a fixed version in the data Quanta has, so confirm it from the advisory before upgrading."
        line += " It is a direct dependency." if dep.get("direct") is True else (" It is a transitive dependency: upgrade the parent or override this version." if dep.get("direct") is False else "")
        notes.append(line)
        cmd = ECOSYSTEM_COMMANDS.get(str(dep.get("ecosystem") or "").lower())
        if cmd and fixed:
            notes.append("Typical command: " + cmd.format(package=dep["package"], fixed=fixed))
    asset = finding.get("asset") or {}
    os_name = str(asset.get("os") or "").lower()
    text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('recommended_fix', '')}"
    kb_ids = _KB_NUM.findall(text)
    if "windows" in os_name or asset.get("type") in ("windows-server", "windows-endpoint"):
        if kb_ids:
            notes.append(f"To confirm the patch on the host: Get-HotFix -Id {kb_ids[0].upper()}  (PowerShell).")
        else:
            notes.append("To list installed updates on the host: Get-HotFix  (PowerShell), and compare with the advisory.")
    elif any(w in os_name for w in ("linux", "ubuntu", "debian", "red hat", "rhel", "centos", "suse", "amazon")) or asset.get("type") in ("unix-server", "unix-endpoint"):
        notes.append("To confirm the package version on the host: dpkg -l <package> (Debian/Ubuntu) or rpm -q <package> (Red Hat family); then restart the affected service.")
    kev = finding.get("kev") or {}
    if kev.get("listed"):
        due = kev.get("due_date") or kev.get("dueDate")
        notes.append("This CVE is on the CISA Known Exploited Vulnerabilities list: attackers are using it now. Treat it as urgent" + (f"; CISA's due date for federal agencies was {due}." if due else "."))
    epss = (finding.get("epss") or {}).get("score") if isinstance(finding.get("epss"), dict) else None
    if isinstance(epss, (int, float)) and epss >= 0.5:
        notes.append(f"Its exploit probability (EPSS) is {epss:.0%}, which is high.")
    sla = finding.get("sla") or {}
    if sla.get("breached"):
        notes.append("Its SLA deadline has already passed; if it cannot be fixed now, record an exception with an expiry and apply the compensating controls.")
    return notes


def _automation(finding, scan_type):
    domain = finding.get("remediation_domain")
    if domain in ("windows-server", "unix-server"):
        return {"available": True, "kind": "playbook",
                "note": "Quanta can generate a reviewable Ansible playbook for this (run /remediate --generate, or Trigger Remediation once approved). It never runs it; your change process does."}
    if domain == "iot-ot-device":
        return {"available": True, "kind": "isolation-plan",
                "note": "Quanta generates an isolation plan and a vendor checklist for this device, never a patch."}
    if domain == "application" and finding.get("cve"):
        return {"available": True, "kind": "dependency-upgrade",
                "note": "Quanta generates a dependency upgrade plan; the version change, tests and pull request are done in your normal developer workflow."}
    if str(finding.get("auto_fixable", finding.get("Auto-fixable?", ""))).strip().lower() in ("true", "yes"):
        return {"available": True, "kind": "code-fix",
                "note": "Quanta can apply this fix mechanically on a new branch (run /quanta-scan --fix); you review and merge the pull request."}
    return {"available": False, "kind": None,
            "note": "Quanta has no automated fix for this type of finding yet, so follow the steps above. It will still track the owner, the deadline and the rescan."}


def build(finding, kb=None, client_controls=True):
    """The guidance for one finding. Always returns a usable structure."""
    kb = kb or load_kb()
    entry, matched_by = match(finding, kb)
    scan_type = _scan_type(finding)
    vendor = (finding.get("recommended_fix") or finding.get("fix_hint") or "").strip()
    weak = (not vendor) or bool(_GENERIC_FIX.match(vendor))
    refs = list(entry.get("references") or [])
    for cwe in finding_cwes(finding)[:2]:
        refs.append({"title": f"{cwe} (MITRE)", "url": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"})
    if finding.get("cve"):
        refs.append({"title": f"{finding['cve']} (NVD)", "url": f"https://nvd.nist.gov/vuln/detail/{finding['cve']}"})
    out = {
        "id": entry["id"], "title": entry["title"], "matched_by": matched_by, "curated": entry["id"] != "generic",
        "summary": entry.get("summary"), "why_it_matters": entry.get("why"),
        "tailored": _tailor(finding),
        "steps": list(entry.get("steps") or []), "verify": list(entry.get("verify") or []),
        "compensating_controls": list(entry.get("compensating") or []),
        "effort": entry.get("effort"), "references": refs,
        "vendor_solution": {"text": vendor, "informative": not weak} if vendor else None,
        "automation": _automation(finding, scan_type), "scan_type": scan_type,
        "client_controls": None,
    }
    try:
        from remediation.enrichment import client_controls as _cc
        out["client_assessment"] = _cc.assess(finding) if finding.get("asset") else _cc.assess(finding, inventory=[])
    except Exception:  # noqa: BLE001 - guidance must never fail because the optional controls data is unreadable
        out["client_assessment"] = None
    if client_controls and finding.get("asset"):
        try:
            from remediation.enrichment import control_coverage
            cov = control_coverage.assess_coverage(finding)
        except Exception:  # noqa: BLE001 - guidance must never fail because an optional dataset is unreadable
            cov = None
        if cov and cov.get("has_data"):
            out["client_controls"] = {
                "existing_coverage_pct": cov["existing_coverage_pct"], "residual_risk_pct": cov["residual_risk_pct"],
                "recommended_controls": cov["recommended_controls"],
                "note": "From the firewall and EDR data recorded for this asset in your security controls file.",
            }
        else:
            out["client_controls_note"] = ("No firewall or EDR data is recorded for this asset, so the compensating controls above are general. "
                                           "Add the asset to remediation/config/security_controls.yaml to get ones that account for what is already protecting it.")
    return out
