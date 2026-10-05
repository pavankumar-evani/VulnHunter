"""
Shift-left API testing: results from a pipeline (GitHub Actions, GitLab CI or any other runner) and the pass/fail gate.

Quanta does not run API tests. Your pipeline runs a tester of your choice against a staging deployment, then posts what it found:

  POST /api/ingest/api-test-results            (API key with the api:write scope)
  {"tool": "...", "repository": "org/shop-api", "pipeline": "github-actions", "run_url": "...", "commit": "...", "branch": "main", "environment": "staging",
   "results": [{"method": "GET", "path": "/users/{id}", "test": "object-level authorization", "owasp": "API1:2023", "status": "fail", "severity": "High",
                "evidence": "...", "curl": "curl ..."}]}

The response says whether the gate passed (`gate.passed`) so the pipeline can fail the job. Failures become findings in the main queue (source api-ci-<repository>), a
passing upload records that the tests ran (the DevSecOps control library counts it), and a SARIF file can be sent to /api/ingest/sarif instead with scan_type=dast.
`report_only=true` records and gates but tells the pipeline to pass, for the first weeks of a rollout. Built against common CI conventions and tested with fakes;
never run inside a live pipeline.
"""
import re

from remediation.apisec import config, rules
from remediation.devsecops import controls as dso_controls

STATUSES = ("pass", "fail", "error", "skipped")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
LEVELS = ["Low", "Medium", "High", "Critical"]


def source_for(repository):
    return ("api-ci-" + re.sub(r"[^a-z0-9]+", "-", str(repository).lower()).strip("-"))[:40].rstrip("-")


def parse(body):
    """Validates an upload. Raises ValueError with a message naming the problem."""
    if not isinstance(body, dict):
        raise ValueError("Expected a JSON object")
    repo = str(body.get("repository") or "").strip()
    if not repo or len(repo) > 200:
        raise ValueError("repository is required (for example org/shop-api)")
    results = body.get("results")
    if not isinstance(results, list):
        raise ValueError("results must be a list")
    mx = config.load()["ci"]["max_results_per_upload"]
    if len(results) > mx:
        raise ValueError(f"At most {mx:,} results per upload")
    clean, errors = [], []
    for i, r in enumerate(results):
        try:
            if not isinstance(r, dict):
                raise ValueError("not an object")
            method = str(r.get("method") or "").upper()
            if method not in _METHODS:
                raise ValueError("method must be an HTTP method")
            path = str(r.get("path") or "").strip()
            if not path.startswith("/") or len(path) > 400:
                raise ValueError("path must start with /")
            status = str(r.get("status") or "").lower()
            if status not in STATUSES:
                raise ValueError(f"status must be one of {', '.join(STATUSES)}")
            sev = str(r.get("severity") or "Medium").title()
            if sev not in LEVELS:
                raise ValueError("severity must be Critical, High, Medium or Low")
            owasp = str(r.get("owasp") or "").strip()
            if owasp and owasp not in rules.OWASP:
                raise ValueError(f"owasp must be one of {', '.join(rules.OWASP)}")
            clean.append({"method": method, "path": path, "test": str(r.get("test") or "API security test")[:200], "owasp": owasp or None, "status": status, "severity": sev,
                          "evidence": _CTRL.sub(" ", str(r.get("evidence") or ""))[:1000], "curl": _CTRL.sub(" ", str(r.get("curl") or ""))[:800] or None})
        except ValueError as exc:
            errors.append({"index": i, "error": str(exc)})
    return {"tool": str(body.get("tool") or "api-test")[:120], "repository": repo, "service": str(body.get("service") or "")[:120] or None, "pipeline": str(body.get("pipeline") or "")[:60] or None,
            "run_url": str(body.get("run_url") or "")[:300] or None, "commit": str(body.get("commit") or "")[:64] or None, "branch": str(body.get("branch") or "")[:120] or None,
            "environment": str(body.get("environment") or "")[:60] or None, "results": clean, "errors": errors}


def gate(results, fail_on=None):
    fail_on = (fail_on or config.load()["ci"]["fail_on"]).title()
    if fail_on not in LEVELS:
        raise ValueError("fail_on must be Critical, High, Medium or Low")
    threshold = LEVELS.index(fail_on)
    fails = [r for r in results if r["status"] == "fail"]
    blocking = [r for r in fails if LEVELS.index(r["severity"]) >= threshold]
    by = {s: sum(1 for r in fails if r["severity"] == s) for s in reversed(LEVELS)}
    errors = sum(1 for r in results if r["status"] == "error")
    return {"passed": not blocking, "fail_on": fail_on, "failed": len(fails), "blocking": len(blocking), "by_severity": by, "errors": errors,
            "passed_tests": sum(1 for r in results if r["status"] == "pass"), "skipped": sum(1 for r in results if r["status"] == "skipped"),
            "message": ("Gate passed." if not blocking else f"Gate failed: {len(blocking)} failing test(s) at {fail_on} or above.") + (f" {errors} test(s) could not run." if errors else "")}


def to_queue_items(up):
    items = []
    for r in up["results"]:
        if r["status"] != "fail":
            continue
        lines = [f"API test failed in CI ({up['tool']}, {up['pipeline'] or 'pipeline'}" + (f", {up['environment']}" if up["environment"] else "") + ").", f"Test: {r['test']}.", f"Endpoint: {r['method']} {r['path']}."]
        if r["owasp"]:
            lines.append(f"{r['owasp']} {rules.OWASP[r['owasp']]}.")
        if r["evidence"]:
            lines += ["", "Evidence:", r["evidence"]]
        if r["curl"]:
            lines += ["", "Request to reproduce (supplied by the test tool; review before running):", r["curl"]]
        if up["run_url"]:
            lines += ["", f"Run: {up['run_url']}"]
        items.append({"title": (f"[{r['owasp']}] " if r["owasp"] else "[API test] ") + f"{r['test']}: {r['method']} {r['path']}"[:260], "severity": r["severity"],
                      "asset": {"name": up["repository"], "type": "code-repository"}, "source_ref": f"{r['owasp'] or 'api-test'}:{r['method']}:{r['path']}:{r['test']}"[:200],
                      "description": "\n".join(lines)[:6000], "recommended_fix": rules.FIX.get(r["owasp"] or "", "Reproduce with the request above, fix the cause, and re-run the pipeline."),
                      "scan_type": "dast", "cwe": rules.CWE.get(r["owasp"] or "", []), "rule_id": r["owasp"] or "api-test", "tool": up["tool"],
                      "location": {"url": f"{r['method']} {r['path']}"}})
    return items


def record_run(up, actor, engine=None):
    cfg = config.load()["ci"]
    dso_controls.record_scan_run(up["repository"], cfg["scan_type"], up["tool"], source_for(up["repository"]), sum(1 for r in up["results"] if r["status"] == "fail"), actor, engine)


TEMPLATES = {
    "github-actions": """# .github/workflows/api-security.yml  (a starting point: pin every action to a commit SHA you have reviewed)
name: api-security
on: { pull_request: {}, push: { branches: [main] } }
permissions: { contents: read }
jobs:
  api-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # pin to a commit SHA
      - name: Run your API security tester against staging and write results.json
        run: ./ci/run-api-tests.sh "$STAGING_URL" > results.json     # your tool; output shaped as Quanta's results format
        env: { STAGING_URL: "${{ vars.STAGING_URL }}" }
      - name: Send results to Quanta and apply the gate
        env: { QUANTA_URL: "${{ vars.QUANTA_URL }}", QUANTA_API_KEY: "${{ secrets.QUANTA_API_KEY }}" }
        run: |
          jq --arg repo "$GITHUB_REPOSITORY" --arg run "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" \\
             --arg commit "$GITHUB_SHA" --arg branch "$GITHUB_REF_NAME" \\
             '. + {repository:$repo, pipeline:"github-actions", run_url:$run, commit:$commit, branch:$branch, environment:"staging"}' results.json > upload.json
          curl -sS --fail-with-body -X POST "$QUANTA_URL/api/ingest/api-test-results?reconcile=true" \\
               -H "Authorization: Bearer $QUANTA_API_KEY" -H "Content-Type: application/json" -d @upload.json | tee response.json
          test "$(jq -r '.gate.passed' response.json)" = "true"      # fails the job when the gate fails (add &report_only=true to the URL to only report)
      - name: Optional - upload a SARIF file from a scanner that writes one
        if: always()
        run: curl -sS -X POST "$QUANTA_URL/api/ingest/sarif?scan_type=dast&asset=$GITHUB_REPOSITORY&source=api-sarif" -H "Authorization: Bearer $QUANTA_API_KEY" --data-binary @results.sarif
        env: { QUANTA_URL: "${{ vars.QUANTA_URL }}", QUANTA_API_KEY: "${{ secrets.QUANTA_API_KEY }}" }
""",
    "gitlab-ci": """# .gitlab-ci.yml  (a starting point; set QUANTA_URL and QUANTA_API_KEY as masked CI/CD variables)
api-security:
  stage: test
  image: alpine:3.20                       # pin by digest
  before_script: [apk add --no-cache curl jq]
  script:
    - ./ci/run-api-tests.sh "$STAGING_URL" > results.json         # your tool; output shaped as Quanta's results format
    - >
      jq --arg repo "$CI_PROJECT_PATH" --arg run "$CI_PIPELINE_URL" --arg commit "$CI_COMMIT_SHA" --arg branch "$CI_COMMIT_REF_NAME"
      '. + {repository:$repo, pipeline:"gitlab-ci", run_url:$run, commit:$commit, branch:$branch, environment:"staging"}' results.json > upload.json
    - curl -sS --fail-with-body -X POST "$QUANTA_URL/api/ingest/api-test-results?reconcile=true" -H "Authorization: Bearer $QUANTA_API_KEY" -H "Content-Type: application/json" -d @upload.json | tee response.json
    - test "$(jq -r '.gate.passed' response.json)" = "true"      # fails the job when the gate fails
  rules: [{ if: '$CI_PIPELINE_SOURCE == "merge_request_event"' }, { if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH' }]
""",
    "spec-drift": """# Upload the specification you are about to ship and get the drift against observed traffic (shadow and documented-but-unseen endpoints)
curl -sS -X POST "$QUANTA_URL/api/ingest/openapi?service=shop-api" -H "Authorization: Bearer $QUANTA_API_KEY" -H "Content-Type: text/plain" --data-binary @openapi.yaml
""",
    "results-format": """{
  "tool": "my-api-tester",
  "results": [
    {"method": "GET", "path": "/users/{id}", "test": "object-level authorization", "owasp": "API1:2023", "status": "fail", "severity": "High",
     "evidence": "User B's token returned user A's record (200).", "curl": "curl -i -H 'Authorization: Bearer $TOKEN_B' https://staging.example.com/users/1001"},
    {"method": "POST", "path": "/login", "test": "rate limiting", "owasp": "API4:2023", "status": "pass", "severity": "Medium"}
  ]
}
""",
}
