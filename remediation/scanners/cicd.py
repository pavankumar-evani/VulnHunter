"""
CI/CD pipeline checks: deterministic rules over pipeline definition files.

Looks at GitHub Actions workflows, GitLab CI files and Jenkinsfiles (and Azure Pipelines / CircleCI files for the
rules that are textual) for the weaknesses in the OWASP Top 10 CI/CD Security Risks that can be seen in the file
itself: unpinned third-party code, poisoned-pipeline patterns, script injection from attacker-controlled fields,
over-broad token permissions, secrets written into the file or echoed, and piping the internet into a shell.

It is a set of explicit rules, not a model: the same file always gives the same result, each finding carries its
rule id, the OWASP CI/CD risk it relates to, a CWE, the file and line, and a fix. What it cannot see is
anything outside the file (branch protection, who can approve a release, runner configuration, repository
settings), so a clean result means "no file-level weaknesses found", not "the pipeline is secure".

    findings = scan_path("/path/to/repo")        # Quanta Finding dicts (scan_type "cicd")
    sarif = to_sarif(findings)                    # the same, as SARIF, to upload with an API key

Rules (GitHub Actions unless noted):
  GHA001 third-party action not pinned to a commit SHA          CICD-SEC-3   CWE-829
  GHA002 pull_request_target that checks out the pull request   CICD-SEC-4   CWE-94    (critical)
  GHA003 untrusted event field used inside a run: script        CICD-SEC-4   CWE-94
  GHA004 token permissions not restricted (none set, or write-all)  CICD-SEC-5  CWE-250
  GHA005 secret value echoed or placed on a command line       CICD-SEC-6   CWE-532
  GHA006 credential written into the file                       CICD-SEC-6   CWE-798   (critical)
  GHA007 self-hosted runner reachable from pull requests        CICD-SEC-7   CWE-668
  GHA008 download piped into a shell                            CICD-SEC-3   CWE-494
  GHA009 deprecated set-env / add-path workflow commands        CICD-SEC-4   CWE-94
  GL001  GitLab: image with no tag or `latest`                  CICD-SEC-3   CWE-829
  GL002  GitLab: download piped into a shell                    CICD-SEC-3   CWE-494
  GL003  GitLab: credential written into the file               CICD-SEC-6   CWE-798   (critical)
  JK001  Jenkins: parameter or environment value interpolated into a sh step  CICD-SEC-4  CWE-78
  JK002  Jenkins: credential written into the file              CICD-SEC-6   CWE-798   (critical)
  JK003  Jenkins: download piped into a shell                   CICD-SEC-3   CWE-494
"""
import json
import re
from pathlib import Path

import yaml

OWASP_CICD = {
    "CICD-SEC-3": "Dependency chain abuse", "CICD-SEC-4": "Poisoned pipeline execution", "CICD-SEC-5": "Insufficient pipeline-based access controls",
    "CICD-SEC-6": "Insufficient credential hygiene", "CICD-SEC-7": "Insecure system configuration",
}
RULES = {
    "GHA001": ("Third-party action is not pinned to a commit SHA", "Medium", "CICD-SEC-3", "CWE-829",
               "Pin the action to the full 40-character commit SHA of a release you reviewed (keep the tag in a comment). A tag or branch can be moved by whoever controls the action's repository."),
    "GHA002": ("pull_request_target workflow checks out and runs the pull request's code", "Critical", "CICD-SEC-4", "CWE-94",
               "Do not check out the pull request head in a pull_request_target workflow. Use the pull_request trigger for untrusted code, or split the workflow so the privileged part never runs code from the pull request."),
    "GHA003": ("Untrusted event data is used inside a run: script", "High", "CICD-SEC-4", "CWE-94",
               "Pass the value through an environment variable and reference \"$VAR\" in the script instead of expanding ${{ ... }} into it, so the value cannot become shell syntax."),
    "GHA004": ("Workflow does not restrict the GITHUB_TOKEN permissions", "Medium", "CICD-SEC-5", "CWE-250",
               "Add `permissions: contents: read` at the top of the workflow and grant extra scopes only to the job that needs them."),
    "GHA005": ("A secret is echoed or placed on a command line", "High", "CICD-SEC-6", "CWE-532",
               "Pass the secret as an environment variable to the step that needs it, never echo it, and do not put it in command arguments where logs and process lists can show it."),
    "GHA006": ("A credential is written into the workflow file", "Critical", "CICD-SEC-6", "CWE-798",
               "Treat the credential as compromised: revoke it, store the replacement in the platform's secret store, and reference it as a secret. Prefer short-lived OIDC credentials to the cloud."),
    "GHA007": ("Self-hosted runner can be reached from pull requests", "High", "CICD-SEC-7", "CWE-668",
               "Do not run pull-request workflows from forks on self-hosted runners. Use ephemeral, isolated runners and restrict which repositories and events may use them."),
    "GHA008": ("A downloaded script is piped straight into a shell", "Medium", "CICD-SEC-3", "CWE-494",
               "Download to a file, verify a checksum or signature, then run it; or use a pinned, reviewed action or package instead."),
    "GHA009": ("Deprecated set-env / add-path workflow command", "Medium", "CICD-SEC-4", "CWE-94",
               "Write to the $GITHUB_ENV and $GITHUB_PATH files instead; the old commands allow environment injection."),
    "GL001": ("Container image has no tag or uses :latest", "Medium", "CICD-SEC-3", "CWE-829",
              "Pin the image to a version tag and, for release jobs, to a digest."),
    "GL002": ("A downloaded script is piped straight into a shell", "Medium", "CICD-SEC-3", "CWE-494",
              "Download to a file, verify a checksum or signature, then run it."),
    "GL003": ("A credential is written into the pipeline file", "Critical", "CICD-SEC-6", "CWE-798",
              "Treat the credential as compromised: revoke it and move the replacement to a masked, protected CI/CD variable."),
    "JK001": ("Parameter or environment value is interpolated into a shell step", "Medium", "CICD-SEC-4", "CWE-78",
              "Use single-quoted sh strings and pass values as environment variables ('$VAR') so Groovy does not expand them into the command."),
    "JK002": ("A credential is written into the Jenkinsfile", "Critical", "CICD-SEC-6", "CWE-798",
              "Treat the credential as compromised: revoke it and use withCredentials / the credentials store."),
    "JK003": ("A downloaded script is piped straight into a shell", "Medium", "CICD-SEC-3", "CWE-494",
              "Download to a file, verify a checksum or signature, then run it."),
}

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
PIPE_SHELL_RE = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I)
SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|sk_live_[0-9a-zA-Z]{20,}"
    r"|(?i:(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"\s${][^'\"]{7,}['\"]))")
UNTRUSTED = (r"github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|workflow_run)"
             r"[A-Za-z0-9_.\[\]*]*(?:title|body|name|label|message|email|head_ref|ref|default_branch)|github\.head_ref|github\.event\.commits")
EXPR_RE = re.compile(r"\$\{\{\s*([^}]*)\}\}")
ECHO_SECRET_RE = re.compile(r"(?:echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}|--?(?:password|token|secret|key)[= ]\s*\$\{\{\s*secrets\.", re.I)
JENKINS_INTERP = re.compile(r'\bsh\s*(?:\(\s*)?(?:script\s*:\s*)?"[^"\n]*\$\{?(?:params|env)\.[A-Za-z0-9_]+')


def _finding(rule, path, line, snippet, detail=None):
    title, severity, owasp, cwe, fix = RULES[rule]
    if rule in ("GHA006", "GL003", "JK002"):  # never copy the credential itself into a finding
        snippet = SECRET_RE.sub("***REDACTED***", snippet or "")
    return {
        "rule_id": rule, "title": title, "severity": severity, "cwe": [cwe], "owasp_cicd": owasp,
        "scan_type": "cicd", "tool": "Quanta pipeline checks",
        "description": (detail or title) + f" ({owasp}: {OWASP_CICD[owasp]}.)",
        "recommended_fix": fix,
        "location": {"file": path, "line": line, "end_line": line, "url": None, "snippet": (snippet or "").strip()[:300]},
    }


def _strip_comment(s):
    return re.sub(r"\s+#.*$", "", s)


def scan_github_workflow(path, text):
    findings = []
    lines = text.splitlines()
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        doc = {}
    if not isinstance(doc, dict):
        return findings
    triggers = doc.get("on", doc.get(True, {}))
    names = set(triggers) if isinstance(triggers, (dict, list)) else ({triggers} if triggers else set())
    pr_target = "pull_request_target" in names
    pull_request_like = bool(names & {"pull_request", "pull_request_target", "pull_request_review", "issue_comment", "issues"})

    for i, ln in enumerate(lines, 1):
        code = _strip_comment(ln)
        m = USES_RE.match(code)
        if m:
            ref = m.group(1)
            if not ref.startswith(("./", "docker://")) and "@" in ref:
                repo, version = ref.rsplit("@", 1)
                if not SHA_RE.match(version) and "${{" not in ref:
                    first_party = repo.split("/")[0].lower() in ("actions", "github")
                    f = _finding("GHA001", path, i, ln, f"`{ref}` is referenced by a movable {'tag' if re.match(r'^v?\d', version) else 'branch or tag'} (`{version}`).")
                    if first_party:
                        f["severity"] = "Low"
                    findings.append(f)
        if SECRET_RE.search(code) and "${{" not in code.split(":", 1)[-1][:12]:
            findings.append(_finding("GHA006", path, i, re.sub(r"(['\"])[^'\"]{4,}(['\"])", r"\1***\2", ln)))
        if PIPE_SHELL_RE.search(code):
            findings.append(_finding("GHA008", path, i, ln))
        if "::set-env" in code or "::add-path" in code:
            findings.append(_finding("GHA009", path, i, ln))
        if ECHO_SECRET_RE.search(code):
            findings.append(_finding("GHA005", path, i, ln))

    # run: scripts with untrusted expressions (block scalars included)
    in_run, run_indent = False, 0
    for i, ln in enumerate(lines, 1):
        stripped = ln.lstrip()
        indent = len(ln) - len(stripped)
        m = re.match(r"^-?\s*run:\s*(.*)$", stripped)
        if m:
            body = m.group(1)
            in_run, run_indent = body in ("|", "|-", ">", ">-", "|+") or not body, indent
            scan_text = "" if in_run else body
        elif in_run and (not stripped or indent > run_indent):
            scan_text = ln
        else:
            in_run, scan_text = False, ""
        for expr in EXPR_RE.findall(scan_text):
            if re.search(UNTRUSTED, expr):
                findings.append(_finding("GHA003", path, i, ln, f"`${{{{ {expr.strip()} }}}}` can be controlled by whoever opens the pull request or issue and is expanded into a shell script."))

    # pull_request_target + checkout of the PR head
    if pr_target:
        for i, ln in enumerate(lines, 1):
            if re.search(r"ref:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)", ln) or \
               re.search(r"ref:\s*refs/pull/", ln):
                findings.append(_finding("GHA002", path, i, ln))

    # permissions
    perms = doc.get("permissions")
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    job_perms = [j.get("permissions") for j in jobs.values() if isinstance(j, dict)]
    broad = perms in ("write-all",) or any(p == "write-all" for p in job_perms)
    if broad:
        ln_no = next((i for i, ln in enumerate(lines, 1) if "write-all" in ln), 1)
        findings.append(_finding("GHA004", path, ln_no, lines[ln_no - 1], "`permissions: write-all` gives every step full write access with the token."))
    elif perms is None and not all(p is not None for p in job_perms if job_perms) or (perms is None and not job_perms):
        f = _finding("GHA004", path, 1, lines[0] if lines else "", "No `permissions:` block is set, so the token gets the repository's default permissions, which are often write.")
        f["suggested_patch"] = _permissions_patch(path, lines)
        findings.append(f)

    # self-hosted runners
    if pull_request_like:
        for i, ln in enumerate(lines, 1):
            if re.search(r"runs-on:\s*(?:\[.*self-hosted.*\]|self-hosted)", ln):
                findings.append(_finding("GHA007", path, i, ln))
    return findings


def _permissions_patch(path, lines):
    """A unified diff that adds a read-only permissions block before `jobs:`."""
    idx = next((i for i, ln in enumerate(lines) if re.match(r"^jobs:\s*$", ln)), None)
    if idx is None:
        return None
    ctx_before = lines[max(0, idx - 2):idx]
    ctx_after = lines[idx:idx + 2]
    start = max(0, idx - 2) + 1
    out = [f"--- a/{path}", f"+++ b/{path}", f"@@ -{start},{len(ctx_before) + len(ctx_after)} +{start},{len(ctx_before) + len(ctx_after) + 3} @@"]
    out += [" " + ln for ln in ctx_before]
    out += ["+permissions:", "+  contents: read", "+"]
    out += [" " + ln for ln in ctx_after]
    return "\n".join(out) + "\n"


def scan_gitlab(path, text):
    findings = []
    for i, ln in enumerate(text.splitlines(), 1):
        code = _strip_comment(ln)
        m = re.match(r"^\s*-?\s*image:\s*['\"]?([^\s'\"#]+)", code)
        if m and "$" not in m.group(1):
            img = m.group(1)
            name = img.split("@")[0]
            tag = name.rsplit(":", 1)[1] if ":" in name.rsplit("/", 1)[-1] else None
            if "@sha256:" not in img and (tag is None or tag == "latest"):
                findings.append(_finding("GL001", path, i, ln, f"Image `{img}` has {'no tag' if tag is None else 'the :latest tag'}."))
        if PIPE_SHELL_RE.search(code):
            findings.append(_finding("GL002", path, i, ln))
        if SECRET_RE.search(code):
            findings.append(_finding("GL003", path, i, re.sub(r"(['\"])[^'\"]{4,}(['\"])", r"\1***\2", ln)))
    return findings


def scan_jenkins(path, text):
    findings = []
    for i, ln in enumerate(text.splitlines(), 1):
        if JENKINS_INTERP.search(ln):
            findings.append(_finding("JK001", path, i, ln))
        if PIPE_SHELL_RE.search(ln):
            findings.append(_finding("JK003", path, i, ln))
        if SECRET_RE.search(ln) and "credentials(" not in ln:
            findings.append(_finding("JK002", path, i, re.sub(r"(['\"])[^'\"]{4,}(['\"])", r"\1***\2", ln)))
    return findings


def scan_file(path, text, rel=None):
    rel = rel or str(path)
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if "/.github/workflows/" in "/" + p and name.endswith((".yml", ".yaml")):
        return scan_github_workflow(rel, text)
    if name in (".gitlab-ci.yml", ".gitlab-ci.yaml") or (name.endswith((".yml", ".yaml")) and "/.gitlab/" in "/" + p):
        return scan_gitlab(rel, text)
    if name == "Jenkinsfile" or name.startswith("Jenkinsfile."):
        return scan_jenkins(rel, text)
    return []


def discover(root):
    root = Path(root)
    pats = [".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml", ".gitlab-ci.yaml", "Jenkinsfile", "Jenkinsfile.*", ".gitlab/**/*.yml"]
    seen = []
    for pat in pats:
        seen += [p for p in root.glob(pat) if p.is_file()]
    return sorted(set(seen))


def scan_path(root, max_files=500):
    """Findings for every pipeline file under a repository root. Returns (findings, files_scanned)."""
    root = Path(root)
    files = discover(root)[:max_files]
    findings = []
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings += scan_file(p, text, rel=p.relative_to(root).as_posix())
    return findings, len(files)


def to_sarif(findings, tool_name="Quanta pipeline checks"):
    """The findings as a SARIF 2.1.0 document, so a CI job can upload them with an API key."""
    rules, seen = [], set()
    level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
    for f in findings:
        if f["rule_id"] not in seen:
            seen.add(f["rule_id"])
            rules.append({"id": f["rule_id"], "name": f["title"], "shortDescription": {"text": f["title"]}, "help": {"text": f["recommended_fix"]},
                          "properties": {"tags": f["cwe"] + [f["owasp_cicd"]]}})
    results = []
    for f in findings:
        loc = f["location"]
        r = {"ruleId": f["rule_id"], "level": level[f["severity"]], "message": {"text": f["description"]},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc["file"]},
                                                 "region": {"startLine": loc["line"] or 1, "snippet": {"text": loc["snippet"] or ""}}}}]}
        if f["severity"] == "Critical":
            r["properties"] = {"security-severity": "9.5"}
        if f.get("suggested_patch"):
            r.setdefault("properties", {})["patch"] = f["suggested_patch"]
        results.append(r)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": tool_name, "informationUri": "https://owasp.org/www-project-top-10-ci-cd-security-risks/", "rules": rules}},
                      "results": results}]}


if __name__ == "__main__":
    import sys
    fs, n = scan_path(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(json.dumps(to_sarif(fs), indent=2))
