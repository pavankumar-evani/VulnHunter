"""
SARIF 2.1.0 adapter: one reader for most security scanners.

SARIF (OASIS Static Analysis Results Interchange Format) is what Semgrep, CodeQL, SonarQube (export), OWASP
ZAP, Trivy, Grype, Checkov, tfsec, KICS, gitleaks, Hadolint, actionlint and many more can emit. Reading it
once gives Quanta SAST, DAST, SCA, IaC, secrets, container-image and pipeline findings without a connector
per tool. Each result becomes a Finding with the fields the rest of Quanta already understands, plus a few
that make it useful to a developer: the scan type, the location (file and line, or URL), the rule id, the
CWE ids and the tool's own fix suggestion.

Decisions, stated so they can be challenged:

* Identity: a result keeps the same finding across re-uploads through `source_ref`, built from the tool's own
  fingerprint when it supplies one, otherwise a hash of rule + file + the code snippet (or message). The line
  number is deliberately not part of the hash, so adding a line above a finding does not create a duplicate.
* Severity: a numeric `security-severity` (CodeQL, Semgrep and others, 0 to 10) wins; otherwise the SARIF level
  (error = High, warning = Medium, note = Low). Quanta does not escalate a result to Critical on level alone.
* Scan type: given by the caller, otherwise inferred from the tool name (below), otherwise `sast`.
* Asset: SARIF describes code and URLs, not hosts. The caller names the asset (a repository or application);
  for web scans the host in the URL is used when none is given.
* A result with a CVE rule id from a code or dependency tool (Grype, OSV, Dependabot) becomes an SCA finding on an
  `application` asset, so the existing dependency-upgrade path applies; the package comes from the result
  properties when present. A container-image scanner (Trivy) keeps its CVEs as container-image findings.
* Suppressed results (`suppressions`) and `kind` other than `fail` are skipped.
"""
from remediation.utils.digest import dedup_sha1
import json
import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
CWE_RE = re.compile(r"(?:CWE[-_ :/]*|cwe-)(\d+)", re.I)

# lower-case substring of the tool name -> scan type
TOOL_SCAN_TYPES = (
    (("zap", "burp", "nuclei", "arachni", "wapiti", "nikto", "acunetix", "netsparker", "invicti"), "dast"),
    (("gitleaks", "trufflehog", "detect-secrets", "secretlint", "git-secrets", "ggshield"), "secrets"),
    (("checkov", "tfsec", "kics", "terrascan", "cfn-lint", "cfn_nag", "kube-linter", "kubesec", "snyk iac", "trivy-config"), "iac"),
    (("hadolint", "dockle", "docker-bench", "anchore", "clair"), "container"),
    (("actionlint", "zizmor", "poutine", "scorecard", "gha-", "pipeline"), "cicd"),
    (("grype", "osv-scanner", "dependency-check", "dependabot", "snyk open", "npm audit", "pip-audit", "safety", "retire.js"), "sca"),
    (("trivy",), "container"),
    (("semgrep", "codeql", "sonar", "bandit", "eslint", "spotbugs", "findsecbugs", "gosec", "brakeman", "flawfinder",
      "cppcheck", "psalm", "phpstan", "checkmarx", "fortify", "veracode", "coverity", "snyk code", "devskim", "pmd"), "sast"),
)
VALID_SCAN_TYPES = ("sast", "dast", "sca", "secrets", "iac", "container", "cicd", "coverage")

LEVEL_SEVERITY = {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}
MAX_RESULTS = 20000


class SarifError(ValueError):
    pass


def summarize(data, scan_type=None):
    """The runs in a SARIF file as [{tool, scan_type, results}], including a run with no results (a clean scan). Raises SarifError for a non-SARIF file."""
    doc = data
    if isinstance(doc, (str, bytes)):
        try:
            doc = json.loads(doc)
        except ValueError as exc:
            raise SarifError(f"Not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise SarifError("This is not a SARIF file: it has no 'runs' list.")
    out = []
    for run in doc["runs"]:
        tool = (((run.get("tool") or {}).get("driver")) or {}).get("name")
        if tool:
            out.append({"tool": tool, "scan_type": scan_type or infer_scan_type(tool), "results": len(run.get("results") or [])})
    return out


def infer_scan_type(tool_name):
    name = (tool_name or "").lower()
    for needles, scan_type in TOOL_SCAN_TYPES:
        if any(n in name for n in needles):
            return scan_type
    return "sast"


def _severity(score, level):
    try:
        s = float(score)
    except (TypeError, ValueError):
        s = None
    if s is not None:
        return ("Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"), s
    return LEVEL_SEVERITY.get((level or "warning").lower(), "Medium"), None


def _cwes(*sources):
    found = []
    for src in sources:
        for text in (src if isinstance(src, (list, tuple)) else [src]):
            for m in CWE_RE.finditer(str(text or "")):
                c = f"CWE-{m.group(1)}"
                if c not in found:
                    found.append(c)
    return found


def _text(node):
    if isinstance(node, dict):
        return (node.get("markdown") or node.get("text") or "").strip()
    return str(node or "").strip()


def _uri(loc):
    art = ((loc or {}).get("physicalLocation") or {}).get("artifactLocation") or {}
    uri = art.get("uri") or ""
    return uri[7:] if uri.startswith("file://") else uri


def _fingerprint(result, rule_id, uri, snippet):
    fps = result.get("partialFingerprints") or result.get("fingerprints") or {}
    if fps:
        return f"{rule_id}:{sorted(fps.items())[0][1]}"
    basis = "|".join([rule_id or "", uri or "", re.sub(r"\s+", " ", snippet or _text(result.get("message")))[:300]])
    return f"{rule_id}:{dedup_sha1(basis.encode('utf-8', 'replace')).hexdigest()[:16]}"


def _host(uri):
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", uri or "", re.I)
    return m.group(1) if m else None


def parse(doc, source, scan_type=None, asset=None, today=None):
    """Findings (without ids) from a parsed SARIF document. Returns (findings, skipped)."""
    import datetime
    if isinstance(doc, (str, bytes)):
        try:
            doc = json.loads(doc)
        except ValueError as exc:
            raise SarifError(f"Not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise SarifError("This is not a SARIF file: it has no 'runs' list.")
    if scan_type and scan_type not in VALID_SCAN_TYPES:
        raise SarifError(f"scan_type must be one of {', '.join(VALID_SCAN_TYPES)}")
    today = today or datetime.date.today().isoformat()
    findings, skipped, seen = [], {"suppressed": 0, "not_a_failure": 0, "duplicate": 0}, set()
    for run in doc["runs"]:
        driver = ((run.get("tool") or {}).get("driver")) or {}
        tool = driver.get("name") or "unknown tool"
        run_type = scan_type or infer_scan_type(tool)
        rules = {r.get("id"): r for r in (driver.get("rules") or []) if isinstance(r, dict)}
        for result in run.get("results") or []:
            if len(findings) >= MAX_RESULTS:
                raise SarifError(f"More than {MAX_RESULTS} results in one file; split it.")
            if result.get("suppressions"):
                skipped["suppressed"] += 1
                continue
            if (result.get("kind") or "fail") != "fail":
                skipped["not_a_failure"] += 1
                continue
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or ""
            rule = rules.get(rule_id) or {}
            rprops = rule.get("properties") or {}
            props = result.get("properties") or {}
            loc = (result.get("locations") or [{}])[0]
            phys = (loc or {}).get("physicalLocation") or {}
            region = phys.get("region") or {}
            uri = _uri(loc)
            snippet = _text(region.get("snippet"))
            message = _text(result.get("message"))
            level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
            severity, score = _severity(props.get("security-severity") or rprops.get("security-severity"), level)
            title = (_text(rule.get("shortDescription")) or _text(rule.get("name")) or message.split("\n")[0] or rule_id or "Finding")[:300]
            cves = CVE_RE.findall(f"{rule_id} {title} {message}")
            cwes = _cwes(rprops.get("tags"), rprops.get("cwe"), props.get("cwe"), [t.get("id") for t in result.get("taxa") or []],
                         rule.get("relationships"), rule_id if "cwe" in rule_id.lower() else "")
            fix = ""
            for fx in result.get("fixes") or []:
                fix = _text(fx.get("description"))
                if fix:
                    break
            fix = fix or _text(rule.get("help")) or props.get("fix") or ""
            this_type = "sca" if (cves and run_type in ("sast", "sca")) else run_type
            url = uri if re.match(r"^https?://", uri or "", re.I) else None
            name = asset or (_host(uri) if run_type == "dast" else None) or source
            a_type = {"sca": "application", "dast": "application", "container": "container-runtime", "iac": "iac-resource"}.get(this_type, "code-repository")
            ref = _fingerprint(result, rule_id, uri, snippet)
            key = (ref, name, cves[0] if cves else "")
            if key in seen:
                skipped["duplicate"] += 1
                continue
            seen.add(key)
            description = message if message and message != title else _text(rule.get("fullDescription")) or message
            f = {
                "source_ref": ref, "title": title, "severity": severity, "cvss": score,
                "cve": cves[0].upper() if cves else None, "cwe": cwes, "rule_id": rule_id or None, "tool": tool,
                "scan_type": this_type,
                "asset": {"name": name, "ip": None, "type": a_type, "os": None},
                "description": (description or "")[:2000], "recommended_fix": fix[:2000],
                "location": {"file": None if url else (uri or None), "line": region.get("startLine"), "end_line": region.get("endLine"),
                             "url": url, "snippet": snippet[:500] or None},
                "remediation_domain": "application" if (this_type == "sca" and cves) else None,
                "first_seen": today, "last_seen": today, "kev": None, "epss": None,
            }
            pkg = props.get("package") or props.get("packageName") or props.get("pkgName")
            if this_type == "sca" and pkg:
                f["dependency"] = {"package": pkg, "ecosystem": (props.get("ecosystem") or props.get("pkgType") or None),
                                   "version": props.get("installedVersion") or props.get("version"),
                                   "fixed_version": props.get("fixedVersion") or props.get("fixed_version"), "direct": None}
            if props.get("patch"):
                f["suggested_patch"] = str(props["patch"])[:6000]
            findings.append(f)
    return findings, skipped
