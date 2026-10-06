"""
Test-coverage ingest: turns a coverage report into findings only where it matters for security.

Coverage is not a vulnerability, and a repository-wide percentage says little. What is worth a finding is
security-relevant code (authentication, authorization, sessions, cryptography, input validation, payments,
uploads, parsers) that is barely tested, because that is where a regression slips in unnoticed. So this reads a
Cobertura XML, JaCoCo XML or lcov report, finds the files whose path suggests security-relevant code, and raises
a finding for each one below a threshold. Everything else is reported only as the overall summary.

The path match is a heuristic (it looks at file and folder names), stated as such in each finding; a team can
tune the patterns and threshold. A file with no executable lines is ignored.
"""
import re

from remediation.utils import safe_xml

SECURITY_PATH = re.compile(
    r"(auth|login|logout|session|token|jwt|oauth|saml|sso|password|passwd|credential|crypt|cipher|hash|sign(?:ing|ature)?|verify|"
    r"permission|authoriz|rbac|acl|admin|payment|billing|checkout|sanitiz|validat|escape|upload|deserial|parser|secret|csrf|firewall)", re.I)
STRONG = re.compile(r"(auth|login|password|crypt|cipher|payment|billing|permission|authoriz|rbac|token|jwt|secret)", re.I)
MAX_FILES = 50000


class CoverageError(ValueError):
    pass


def _safe_xml(text):
    # Real JaCoCo reports carry a DOCTYPE that only names a DTD, which ElementTree never fetches, so that is allowed.
    # Entity declarations and an internal subset are refused by the shared safe parser.
    try:
        return safe_xml.fromstring(text)
    except safe_xml.UnsafeXml as exc:
        raise CoverageError("Entity declarations and internal DTD subsets are not accepted in a coverage report.") from exc
    except safe_xml.ParseError as exc:
        raise CoverageError(f"Not valid XML: {exc}") from exc


def detect(text):
    head = text.lstrip()[:3000]
    if head.startswith("<"):
        m = re.search(r"<(?!\?|!)([A-Za-z][\w:-]*)", head)
        tag = (m.group(1) if m else "").lower()
        if tag == "report":
            return "jacoco"
        if tag == "coverage":
            return "cobertura"
        raise CoverageError("Unrecognised XML coverage report; supported: Cobertura (<coverage>) and JaCoCo (<report>).")
    if "SF:" in text and ("DA:" in text or "end_of_record" in text):
        return "lcov"
    raise CoverageError("Could not recognise the format. Supported: Cobertura XML, JaCoCo XML, lcov.")


def parse_cobertura(text):
    root = _safe_xml(text)
    files = {}
    for cls in root.iter("class"):
        name = cls.get("filename")
        if not name:
            continue
        total = covered = 0
        for ln in cls.iter("line"):
            total += 1
            covered += 1 if int(ln.get("hits", "0") or 0) > 0 else 0
        t, c = files.get(name, (0, 0))
        files[name] = (t + total, c + covered)
    return files


def parse_jacoco(text):
    root = _safe_xml(text)
    files = {}
    for pkg in root.iter("package"):
        base = (pkg.get("name") or "").strip("/")
        for sf in pkg.iter("sourcefile"):
            for counter in sf.findall("counter"):
                if counter.get("type") == "LINE":
                    missed, cov = int(counter.get("missed", 0)), int(counter.get("covered", 0))
                    files[f"{base}/{sf.get('name')}".strip("/")] = (missed + cov, cov)
    return files


def parse_lcov(text):
    files, cur, total, cov = {}, None, 0, 0
    for raw in text.splitlines():
        ln = raw.strip()
        if ln.startswith("SF:"):
            cur, total, cov = ln[3:], 0, 0
        elif ln.startswith("DA:") and cur:
            parts = ln[3:].split(",")
            total += 1
            cov += 1 if len(parts) > 1 and parts[1].strip() not in ("0", "") else 0
        elif ln == "end_of_record" and cur:
            t, c = files.get(cur, (0, 0))
            files[cur] = (t + total, c + cov)
            cur = None
    return files


PARSERS = {"cobertura": parse_cobertura, "jacoco": parse_jacoco, "lcov": parse_lcov}


def analyse(text, fmt=None, threshold=60.0, source="coverage", asset=None, today=None):
    """Returns (findings, summary). `summary` has overall coverage and how many security-relevant files fell below the threshold."""
    import datetime
    fmt = fmt or detect(text)
    if fmt not in PARSERS:
        raise CoverageError(f"format must be one of {', '.join(PARSERS)}")
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        raise CoverageError("threshold must be a number between 1 and 100") from None
    if not 1 <= threshold <= 100:
        raise CoverageError("threshold must be a number between 1 and 100")
    files = PARSERS[fmt](text)
    if len(files) > MAX_FILES:
        raise CoverageError(f"More than {MAX_FILES} files in one report.")
    today = today or datetime.date.today().isoformat()
    total = sum(t for t, _ in files.values())
    covered = sum(c for _, c in files.values())
    findings, relevant = [], 0
    for path, (t, c) in sorted(files.items()):
        if t == 0 or not SECURITY_PATH.search(path):
            continue
        relevant += 1
        pct = 100.0 * c / t
        if pct >= threshold:
            continue
        severity = "Medium" if (pct < 30 and STRONG.search(path)) else "Low"
        findings.append({
            "source_ref": path, "title": f"Low test coverage on security-relevant code: {path} ({pct:.0f}%)",
            "severity": severity, "cvss": None, "cve": None, "cwe": [], "rule_id": "COV001", "tool": f"coverage ({fmt})",
            "scan_type": "coverage",
            "asset": {"name": asset or source, "ip": None, "type": "code-repository", "os": None},
            "description": (f"{c} of {t} executable lines in {path} are exercised by the tests ({pct:.0f}%, threshold {threshold:.0f}%). The path suggests "
                            "security-relevant code (authentication, authorization, cryptography, validation, payments or similar); this is a heuristic on the file name."),
            "recommended_fix": "Add tests for abuse cases (hostile and invalid input, missing permission), not only the happy path, and raise a coverage floor for changed code in CI.",
            "location": {"file": path, "line": None, "end_line": None, "url": None, "snippet": None},
            "remediation_domain": None, "first_seen": today, "last_seen": today, "kev": None, "epss": None,
        })
    summary = {"format": fmt, "files": len(files), "overall_pct": round(100.0 * covered / total, 1) if total else None,
               "security_relevant_files": relevant, "below_threshold": len(findings), "threshold": threshold}
    return findings, summary
