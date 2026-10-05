"""
Git host connectors (GitHub and GitLab): the only code in Quanta that writes to a customer's repository, and it can do exactly four things on a branch of its
own making: read a file, create a branch, commit files to that branch, and open a pull request (GitLab: merge request). It never merges, never pushes to
the default branch (the connector itself refuses), never force-pushes, never deletes anything and never changes repository settings.

Implements the public REST APIs:
  GitHub  https://docs.github.com/en/rest   (repos, git/refs, contents, pulls, pulls/{n}/reviews, commits/{sha}/check-runs)
  GitLab  https://docs.gitlab.com/ee/api/   (projects, repository/branches, repository/files, repository/commits, merge_requests, approvals)
Auth is a token in a header, supplied by the caller (a stored connection); it is never logged and never appears in an error message. The token
should be scoped as narrowly as the host allows: GitHub fine-grained token with Contents and Pull requests read/write on the one repository; GitLab project
access token with the `api` scope and the Developer role.

Writes are not retried: a retried "open pull request" after a timeout could open two. Reads retry on connection errors.

Built against the vendors' public documentation and unit-tested against a hand-rolled fake session. It has not been run against a live GitHub or GitLab
instance from this repository, and the first run in a customer's environment should be against a test repository.
"""
import base64
from urllib.parse import quote

import requests

from remediation.utils.retry import retry_with_backoff

_RETRY = (requests.exceptions.ConnectionError, requests.exceptions.Timeout)
MAX_FILE_BYTES = 2_000_000


class GitHostError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class _Base:
    provider = ""

    def __init__(self, token, base_url=None, session=None):
        if not token:
            raise GitHostError("A token is required")
        self._token = token
        self.base_url = (base_url or self.DEFAULT_URL).rstrip("/")
        self.session = session or requests.Session()
        self._defaults = {}

    # -- transport -------------------------------------------------------------------------------------------------
    def _headers(self):
        raise NotImplementedError

    def _request(self, method, path, retry=False, **kw):
        def call():
            r = self.session.request(method, self.base_url + path, headers=self._headers(), timeout=30, **kw)
            if r.status_code >= 400:
                detail = ""
                try:
                    body = r.json()
                    detail = body.get("message") or body.get("error") or ""
                    if isinstance(detail, (dict, list)):
                        detail = str(detail)
                except ValueError:
                    pass
                raise GitHostError(f"{self.provider} answered {r.status_code} for {method} {path.split('?')[0]}" + (f": {str(detail)[:200]}" if detail else ""), r.status_code)
            return r.json() if r.content else {}
        return retry_with_backoff(call, retryable_exceptions=_RETRY) if retry else call()

    def _refuse_default(self, repo, branch):
        if branch == self.default_branch(repo):
            raise GitHostError("Refusing to write to the repository's default branch")

    # -- shared contract -------------------------------------------------------------------------------------------
    def default_branch(self, repo):
        if repo not in self._defaults:
            self._defaults[repo] = self.test_connection(repo)["default_branch"]
        return self._defaults[repo]


class GitHubConnector(_Base):
    provider = "github"
    DEFAULT_URL = "https://api.github.com"

    def _headers(self):
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

    def whoami(self):
        """Proves the token is valid without naming a repository: GET /user."""
        d = self._request("GET", "/user", retry=True)
        return {"user": d.get("login"), "provider": self.provider}

    def test_connection(self, repo):
        """The cheapest authenticated call that proves the token can see the repository: GET /repos/{repo}."""
        d = self._request("GET", f"/repos/{repo}", retry=True)
        perms = d.get("permissions") or {}
        self._defaults[repo] = d.get("default_branch") or "main"
        return {"default_branch": self._defaults[repo], "can_write": bool(perms.get("push") or perms.get("admin") or perms.get("maintain")), "private": bool(d.get("private")),
                "full_name": d.get("full_name")}

    def branch_sha(self, repo, branch):
        try:
            return self._request("GET", f"/repos/{repo}/git/ref/heads/{quote(branch, safe='/')}", retry=True)["object"]["sha"]
        except GitHostError as exc:
            if exc.status == 404:
                return None
            raise

    def create_branch(self, repo, branch, from_branch):
        self._refuse_default(repo, branch)
        sha = self.branch_sha(repo, from_branch)
        if sha is None:
            raise GitHostError(f"The base branch {from_branch} does not exist")
        self._request("POST", f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})
        return sha

    def get_file(self, repo, path, ref):
        try:
            d = self._request("GET", f"/repos/{repo}/contents/{quote(path, safe='/')}", retry=True, params={"ref": ref})
        except GitHostError as exc:
            if exc.status == 404:
                return None
            raise
        if isinstance(d, list) or d.get("type") != "file":
            raise GitHostError(f"{path} is not a file")
        if d.get("size", 0) > MAX_FILE_BYTES:
            raise GitHostError(f"{path} is too large to read ({d.get('size')} bytes)")
        return {"content": base64.b64decode(d.get("content") or "").decode("utf-8"), "sha": d.get("sha")}

    def commit_files(self, repo, branch, message, files):
        """One commit per file (the contents API commits a single file at a time). Returns the commit ids."""
        self._refuse_default(repo, branch)
        ids = []
        for f in files:
            existing = self.get_file(repo, f["path"], branch)
            body = {"message": message, "content": base64.b64encode(f["content"].encode("utf-8")).decode("ascii"), "branch": branch}
            if existing:
                body["sha"] = existing["sha"]
            d = self._request("PUT", f"/repos/{repo}/contents/{quote(f['path'], safe='/')}", json=body)
            ids.append((d.get("commit") or {}).get("sha"))
        return ids

    def open_change_request(self, repo, head, base, title, body, draft=False, labels=None, reviewers=None):
        if head == base:
            raise GitHostError("The branch to merge and its target are the same")
        d = self._request("POST", f"/repos/{repo}/pulls", json={"title": title, "head": head, "base": base, "body": body, "draft": bool(draft)})
        number = d["number"]
        warn = []
        if labels:
            try:
                self._request("POST", f"/repos/{repo}/issues/{number}/labels", json={"labels": list(labels)})
            except GitHostError as exc:
                warn.append(f"labels not added: {exc}")
        if reviewers:
            try:
                self._request("POST", f"/repos/{repo}/pulls/{number}/requested_reviewers", json={"reviewers": list(reviewers)})
            except GitHostError as exc:
                warn.append(f"reviewers not requested: {exc}")
        return {"number": number, "url": d.get("html_url"), "warnings": warn}

    def get_change_request(self, repo, number):
        d = self._request("GET", f"/repos/{repo}/pulls/{int(number)}", retry=True)
        state = "merged" if d.get("merged") or d.get("merged_at") else ("closed" if d.get("state") == "closed" else "open")
        review = "none"
        checks = "none"
        if state == "open":
            reviews = self._request("GET", f"/repos/{repo}/pulls/{int(number)}/reviews", retry=True)
            latest = {}
            for r in reviews if isinstance(reviews, list) else []:
                if r.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
                    latest[(r.get("user") or {}).get("login")] = r["state"]
            if "CHANGES_REQUESTED" in latest.values():
                review = "changes-requested"
            elif "APPROVED" in latest.values():
                review = "approved"
            elif d.get("requested_reviewers") or d.get("requested_teams") or reviews:
                review = "review-requested"
            sha = (d.get("head") or {}).get("sha")
            if sha:
                runs = (self._request("GET", f"/repos/{repo}/commits/{sha}/check-runs", retry=True) or {}).get("check_runs") or []
                if runs:
                    done = [r for r in runs if r.get("status") == "completed"]
                    if any(r.get("conclusion") in ("failure", "timed_out", "cancelled", "action_required") for r in done):
                        checks = "failing"
                    elif len(done) < len(runs):
                        checks = "pending"
                    else:
                        checks = "passing"
        return {"state": state, "merged_at": d.get("merged_at"), "closed_at": d.get("closed_at"), "draft": bool(d.get("draft")), "review_state": review, "checks_state": checks,
                "url": d.get("html_url")}


class GitLabConnector(_Base):
    provider = "gitlab"
    DEFAULT_URL = "https://gitlab.com"

    def _headers(self):
        return {"PRIVATE-TOKEN": self._token}

    @staticmethod
    def _pid(repo):
        return quote(repo, safe="")

    def _p(self, repo, tail=""):
        return f"/api/v4/projects/{self._pid(repo)}{tail}"

    def whoami(self):
        d = self._request("GET", "/api/v4/user", retry=True)
        return {"user": d.get("username"), "provider": self.provider}

    def test_connection(self, repo):
        d = self._request("GET", self._p(repo), retry=True)
        access = max([(d.get("permissions") or {}).get(k, {}).get("access_level", 0) if isinstance((d.get("permissions") or {}).get(k), dict) else 0
                      for k in ("project_access", "group_access")] or [0])
        self._defaults[repo] = d.get("default_branch") or "main"
        return {"default_branch": self._defaults[repo], "can_write": access >= 30, "private": d.get("visibility") != "public", "full_name": d.get("path_with_namespace")}

    def branch_sha(self, repo, branch):
        try:
            return self._request("GET", self._p(repo, f"/repository/branches/{quote(branch, safe='')}"), retry=True)["commit"]["id"]
        except GitHostError as exc:
            if exc.status == 404:
                return None
            raise

    def create_branch(self, repo, branch, from_branch):
        self._refuse_default(repo, branch)
        sha = self.branch_sha(repo, from_branch)
        if sha is None:
            raise GitHostError(f"The base branch {from_branch} does not exist")
        self._request("POST", self._p(repo, "/repository/branches"), params={"branch": branch, "ref": from_branch})
        return sha

    def get_file(self, repo, path, ref):
        try:
            d = self._request("GET", self._p(repo, f"/repository/files/{quote(path, safe='')}"), retry=True, params={"ref": ref})
        except GitHostError as exc:
            if exc.status == 404:
                return None
            raise
        if d.get("size", 0) > MAX_FILE_BYTES:
            raise GitHostError(f"{path} is too large to read ({d.get('size')} bytes)")
        return {"content": base64.b64decode(d.get("content") or "").decode("utf-8"), "sha": d.get("blob_id") or d.get("content_sha256")}

    def commit_files(self, repo, branch, message, files):
        """One commit with every file (GitLab's commits API takes a list of actions)."""
        self._refuse_default(repo, branch)
        actions = []
        for f in files:
            actions.append({"action": "update" if self.get_file(repo, f["path"], branch) else "create", "file_path": f["path"], "content": f["content"]})
        d = self._request("POST", self._p(repo, "/repository/commits"), json={"branch": branch, "commit_message": message, "actions": actions})
        return [d.get("id")]

    def open_change_request(self, repo, head, base, title, body, draft=False, labels=None, reviewers=None):
        if head == base:
            raise GitHostError("The branch to merge and its target are the same")
        payload = {"source_branch": head, "target_branch": base, "title": ("Draft: " + title) if draft and not title.lower().startswith("draft:") else title,
                   "description": body, "remove_source_branch": True}
        if labels:
            payload["labels"] = ",".join(labels)
        d = self._request("POST", self._p(repo, "/merge_requests"), json=payload)
        return {"number": d["iid"], "url": d.get("web_url"), "warnings": []}

    def get_change_request(self, repo, number):
        d = self._request("GET", self._p(repo, f"/merge_requests/{int(number)}"), retry=True)
        gl = d.get("state")
        state = "merged" if gl == "merged" else ("closed" if gl in ("closed", "locked") else "open")
        review, checks = "none", "none"
        if state == "open":
            ap = self._request("GET", self._p(repo, f"/merge_requests/{int(number)}/approvals"), retry=True)
            if ap.get("approved"):
                review = "approved"
            elif (d.get("reviewers") or []) or ap.get("approved_by"):
                review = "review-requested"
            if str(d.get("detailed_merge_status")) == "requested_changes":
                review = "changes-requested"
            ps = ((d.get("head_pipeline") or {}).get("status") or "")
            checks = {"success": "passing", "failed": "failing", "canceled": "failing", "running": "pending", "pending": "pending", "created": "pending"}.get(ps, "none")
        return {"state": state, "merged_at": d.get("merged_at"), "closed_at": d.get("closed_at"), "draft": bool(d.get("draft") or d.get("work_in_progress")), "review_state": review,
                "checks_state": checks, "url": d.get("web_url")}


def build(provider, token, base_url=None, session=None):
    cls = {"github": GitHubConnector, "gitlab": GitLabConnector}.get(provider)
    if cls is None:
        raise GitHostError(f"Unknown Git provider {provider!r}")
    return cls(token, base_url=base_url or None, session=session)
