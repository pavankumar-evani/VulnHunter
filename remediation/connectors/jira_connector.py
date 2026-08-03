"""
Jira Cloud connector - creates an Issue per finding, idempotently, keyed off a label.

Implements Atlassian Jira Cloud's documented REST API v3:
  - Auth: HTTP Basic with an Atlassian account email + API token.
  - GET  /rest/api/3/search        (jql=labels = "vulnhunter-<finding_id>")
  - POST /rest/api/3/issue         ({"fields": {...}})

Reference: https://developer.atlassian.com/cloud/jira/platform/rest/v3/

Jira has no built-in correlation-id field the way ServiceNow's Table API does, so this
connector uses a `vulnhunter-{finding_id}` label as the idempotency key instead: it's
searched for before create, and every created issue is tagged with it.

Like the Tenable/Armis/ServiceNow connectors, this was built against Jira Cloud's
publicly documented API contract and has NOT been exercised against a real Jira Cloud
site - no credentials were available while building it. See
remediation/connectors/README.md for what "tested" means here.
"""
import requests

DEFAULT_ISSUE_TYPE = "Bug"


class JiraError(RuntimeError):
    pass


def _idempotency_label(finding_id):
    return f"vulnhunter-{finding_id}"


def build_issue_body(finding, project_key, issue_type=DEFAULT_ISSUE_TYPE):
    """Builds the issue-create request body for one finding - pure function, no
    network, so callers (like the dashboard's preview mode) can show exactly what
    would be sent without needing real credentials or a live site."""
    severity = finding.get("severity", "Medium")
    asset = finding.get("asset", {})
    kev = finding.get("kev") or {}
    epss = finding.get("epss") or {}

    summary_lines = [
        finding.get("description", ""),
        f"Asset: {asset.get('name', '?')} ({asset.get('ip', '?')}, {asset.get('type', '?')})",
        f"CVE: {finding.get('cve') or 'N/A'}",
        f"Severity: {severity}",
    ]
    if kev.get("listed"):
        summary_lines.append(f"KEV-listed since {kev.get('date_added', '?')} (actively exploited)")
    if epss.get("score") is not None:
        summary_lines.append(f"EPSS score: {epss['score']:.1%}")
    summary_lines.append(f"Recommended fix: {finding.get('recommended_fix', '?')}")

    # Atlassian Document Format (ADF) "text" nodes hold a single run of plain text and
    # aren't meant to contain raw newlines (real newlines need separate paragraph or
    # hardBreak nodes). Since the goal here is a minimal, valid ADF doc rather than a
    # richly formatted one, the summary lines are joined with " | " into one text node
    # inside one paragraph, instead of building out a multi-paragraph document.
    description_text = " | ".join(line for line in summary_lines if line)

    return {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[VulnHunter {finding['id']}] {finding.get('title', '')}",
            "issuetype": {"name": issue_type},
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": description_text},
                        ],
                    },
                ],
            },
            "labels": [_idempotency_label(finding["id"])],
        },
    }


class JiraConnector:
    def __init__(self, base_url, email, api_token, project_key, session=None):
        # Unlike ServiceNow's "instance name -> https://{instance}.service-now.com"
        # convention, Jira Cloud sites don't have a single predictable URL shape a
        # caller-supplied instance name could reliably build, so this takes the full
        # base_url (e.g. "https://yourcompany.atlassian.net") directly.
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        self.session = session or requests.Session()
        self.session.auth = (email, api_token)
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    def find_existing_issue(self, finding_id):
        """Looks up an issue already created for this finding, keyed by the
        `vulnhunter-{finding_id}` label - prevents creating a duplicate ticket every
        time the pipeline re-runs against the same finding."""
        resp = self.session.get(
            f"{self.base_url}/rest/api/3/search",
            params={"jql": f'labels = "{_idempotency_label(finding_id)}"'},
        )
        resp.raise_for_status()
        issues = resp.json().get("issues", [])
        return issues[0] if issues else None

    def create_issue(self, finding, skip_if_exists=True):
        """Creates one issue for a normalized finding (see
        remediation/schema/normalized-finding-schema.md). Returns the created (or
        pre-existing, if skip_if_exists found one) issue record."""
        finding_id = finding["id"]

        if skip_if_exists:
            existing = self.find_existing_issue(finding_id)
            if existing:
                return {**existing, "_vulnhunter_status": "already_existed"}

        body = build_issue_body(finding, self.project_key)
        resp = self.session.post(f"{self.base_url}/rest/api/3/issue", json=body)
        resp.raise_for_status()
        result = resp.json()
        if not result.get("key"):
            raise JiraError(f"Unexpected create-issue response shape: {result!r}")
        return {**result, "_vulnhunter_status": "created"}

    def create_issues_for_findings(self, findings, skip_if_exists=True):
        """Creates (or finds existing) issues for a whole findings list. Returns a
        list of {finding_id, status, issue_key, error} - never raises for a single
        finding's failure, so one bad record doesn't abort the whole batch."""
        results = []
        for f in findings:
            try:
                issue = self.create_issue(f, skip_if_exists=skip_if_exists)
                results.append({
                    "finding_id": f["id"],
                    "status": issue.get("_vulnhunter_status", "created"),
                    "issue_key": issue.get("key"),
                    "error": None,
                })
            except Exception as exc:  # noqa: BLE001 - one failure must not abort the batch
                results.append({
                    "finding_id": f.get("id", "?"),
                    "status": "error",
                    "issue_key": None,
                    "error": str(exc),
                })
        return results
