"""
Tests for the pull-request workflow: manifest upgrade edits, diffs, the Git host connectors (against a hand-rolled fake session), the proposal lifecycle
with its guards, state tracking, verification and velocity.
"""
import base64
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlalchemy import create_engine  # noqa: E402

from remediation.appsec import analysis, store  # noqa: E402
from remediation.connectors import git_host_connector as gh  # noqa: E402
from remediation.devsecops import factory  # noqa: E402
from remediation.gitops import diffing, policy, proposals, upgrade, velocity  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from appsec_fixtures import SBOM, code_finding, dep_finding  # noqa: E402


class UpgradeTests(unittest.TestCase):
    def test_requirements_bump_keeps_extras_markers_and_comments(self):
        txt = "flask==2.0.1\nrequests[security]>=2.20 ; python_version>'3'  # http\nPyYAML\n"
        r = upgrade.patch_manifest("requirements.txt", txt, "requests", "2.31.0")
        self.assertIn("requests[security]==2.31.0 ; python_version>'3'  # http", r["new_text"])
        self.assertIn("-requests[security]>=2.20", r["diff"])
        self.assertTrue(upgrade.declares("requirements.txt", txt, "Requests"))
        self.assertFalse(upgrade.declares("requirements.txt", txt, "urllib3"))
        with self.assertRaises(upgrade.PatchError):
            upgrade.patch_manifest("requirements.txt", "flask==2.0.1\n", "flask", "2.0.1")

    def test_requirements_transitive_gets_a_pin(self):
        r = upgrade.patch_manifest("requirements.txt", "flask==2.0.1\n", "urllib3", "1.26.18", reason="CVE-1")
        self.assertTrue(r["new_text"].endswith("urllib3==1.26.18  # added by Quanta: CVE-1\n"))
        self.assertIn("transitive", r["changes"][0])

    def test_package_json_keeps_range_style_and_indent(self):
        txt = json.dumps({"name": "w", "dependencies": {"lodash": "^4.17.0", "left": "1.0.0"}}, indent=4) + "\n"
        r = upgrade.patch_manifest("web/package.json", txt, "lodash", "4.17.21")
        self.assertIn('"lodash": "^4.17.21"', r["new_text"])
        self.assertIn('\n    "name"', r["new_text"])  # four-space indent preserved
        self.assertTrue(r["new_text"].endswith("\n"))
        t = upgrade.patch_manifest("package.json", txt, "minimist", "1.2.8")
        self.assertEqual(json.loads(t["new_text"])["overrides"], {"minimist": "1.2.8"})
        with self.assertRaises(upgrade.PatchError):
            upgrade.patch_manifest("package.json", json.dumps({"dependencies": {"x": "git+https://h/x.git"}}), "x", "2.0.0")
        with self.assertRaises(upgrade.PatchError):
            upgrade.patch_manifest("package.json", "{broken", "x", "2.0.0")

    POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.12.4</version></dependency>
    <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
  </dependencies>
</project>
"""

    def test_pom_updates_the_property_or_the_version(self):
        r = upgrade.patch_manifest("pom.xml", self.POM, "log4j-core", "2.17.1")
        self.assertIn("<log4j.version>2.17.1</log4j.version>", r["new_text"])
        self.assertIn("property log4j.version: 2.14.1 -> 2.17.1", r["changes"][0])
        r = upgrade.patch_manifest("pom.xml", self.POM, "com.fasterxml.jackson.core:jackson-databind", "2.12.7.1")
        self.assertIn("<version>2.12.7.1</version>", r["new_text"])
        self.assertIn("2.12.4 -> 2.12.7.1", r["changes"][0])

    def test_pom_adds_dependency_management_for_a_transitive_or_managed_package(self):
        r = upgrade.patch_manifest("pom.xml", self.POM, "snakeyaml", "1.33", group="org.yaml")
        self.assertIn("<dependencyManagement>", r["new_text"])
        self.assertIn("<artifactId>snakeyaml</artifactId>", r["new_text"])
        self.assertIn("<version>1.33</version>", r["new_text"])
        with self.assertRaises(upgrade.PatchError):
            upgrade.patch_manifest("pom.xml", self.POM, "snakeyaml", "1.33")  # no groupId known
        again = upgrade.patch_manifest("pom.xml", r["new_text"], "snakeyaml", "1.34", group="org.yaml")
        self.assertEqual(again["new_text"].count("<artifactId>snakeyaml</artifactId>"), 1)

    def test_go_mod(self):
        gm = "module m\n\nrequire (\n\tgolang.org/x/text v0.3.0\n)\n"
        r = upgrade.patch_manifest("go.mod", gm, "golang.org/x/text", "0.3.8")
        self.assertIn("golang.org/x/text v0.3.8", r["new_text"])
        t = upgrade.patch_manifest("go.mod", gm, "golang.org/x/net", "v0.7.0")
        self.assertIn("require golang.org/x/net v0.7.0 // indirect", t["new_text"])

    def test_unsupported_file(self):
        with self.assertRaises(upgrade.PatchError):
            upgrade.patch_manifest("Gemfile", "x", "a", "1")


FILE = "def q(db, name):\n    cur = db.cursor()\n    cur.execute(\"SELECT * FROM u WHERE n = '\" + name + \"'\")\n    return cur.fetchall()\n"
PATCH = "--- a/app/db.py\n+++ b/app/db.py\n@@ -1,4 +1,4 @@\n def q(db, name):\n     cur = db.cursor()\n-    cur.execute(\"SELECT * FROM u WHERE n = '\" + name + \"'\")\n+    cur.execute(\"SELECT * FROM u WHERE n = ?\", (name,))\n     return cur.fetchall()\n"


class DiffTests(unittest.TestCase):
    def test_apply_round_trip_and_drifted_line_numbers(self):
        new = diffing.apply(FILE, PATCH)
        self.assertIn("(name,)", new)
        self.assertEqual(diffing.unified(FILE, new, "app/db.py").count("\n+"), 2)
        shifted = "# header\n# header\n\n" + FILE
        self.assertIn("(name,)", diffing.apply(shifted, PATCH))  # the hunk is found a few lines further down

    def test_a_patch_that_does_not_fit_is_refused(self):
        with self.assertRaises(diffing.PatchRefused) as cx:
            diffing.apply(FILE.replace("cursor", "conn"), PATCH)
        self.assertIn("does not match", str(cx.exception))
        with self.assertRaises(diffing.PatchRefused):
            diffing.apply(FILE, "just words")
        with self.assertRaises(diffing.PatchRefused):
            diffing.apply(FILE, "@@ -1,1 +1,1 @@\n def q(db, name):\n")  # no change

    def test_stats(self):
        self.assertEqual(diffing.stats(PATCH), {"added": 1, "removed": 1})


class FakeSession:
    """A hand-rolled GitHub/GitLab: records every request and answers from a tiny in-memory repository."""

    def __init__(self, provider="github", files=None):
        self.provider, self.calls = provider, []
        self.files = dict(files or {})
        self.branches = {"main": "sha-main"}
        self.pr = {"state": "open", "merged": False}
        self.reviews = []

    class R:
        def __init__(self, status, body=None):
            self.status_code, self._b = status, body
            self.content = b"x" if body is not None else b""

        def json(self):
            return self._b

    def request(self, method, url, headers=None, timeout=None, **kw):
        self.calls.append((method, url, kw, headers))
        R = self.R
        path = url.split("//", 1)[1].split("/", 1)[1]
        if self.provider == "github":
            if method == "GET" and path == "user":
                return R(200, {"login": "bot"})
            if method == "GET" and path.count("/") == 2 and path.startswith("repos/"):
                return R(200, {"default_branch": "main", "permissions": {"push": True}, "private": True, "full_name": path[6:]})
            if "/git/ref/heads/" in path:
                b = path.split("/git/ref/heads/")[1]
                return R(200, {"object": {"sha": self.branches[b]}}) if b in self.branches else R(404, {"message": "Not Found"})
            if method == "POST" and path.endswith("/git/refs"):
                self.branches[kw["json"]["ref"].split("refs/heads/")[1]] = kw["json"]["sha"]
                return R(201, {})
            if "/contents/" in path and method == "GET":
                p = path.split("/contents/")[1]
                return R(200, {"type": "file", "size": 10, "sha": "blob-" + p, "content": base64.b64encode(self.files[p].encode()).decode()}) if p in self.files else R(404, {"message": "Not Found"})
            if "/contents/" in path and method == "PUT":
                p = path.split("/contents/")[1]
                self.files[p] = base64.b64decode(kw["json"]["content"]).decode()
                return R(200, {"commit": {"sha": "c1"}})
            if method == "POST" and path.endswith("/pulls"):
                return R(201, {"number": 7, "html_url": "https://github.example/acme/orders/pull/7"})
            if method == "POST" and ("/labels" in path or "requested_reviewers" in path):
                return R(200, {})
            if method == "GET" and path.endswith("/pulls/7"):
                return R(200, {**self.pr, "html_url": "u", "head": {"sha": "h1"}, "requested_reviewers": [], "merged_at": self.pr.get("merged_at")})
            if method == "GET" and path.endswith("/pulls/7/reviews"):
                return R(200, self.reviews)
            if method == "GET" and "/check-runs" in path:
                return R(200, {"check_runs": [{"status": "completed", "conclusion": "success"}]})
        else:
            if method == "GET" and path == "api/v4/user":
                return R(200, {"username": "bot"})
            if method == "GET" and path == "api/v4/projects/acme%2Forders":
                return R(200, {"default_branch": "main", "permissions": {"project_access": {"access_level": 30}}, "visibility": "private", "path_with_namespace": "acme/orders"})
            if "/repository/branches/" in path and method == "GET":
                b = path.split("/repository/branches/")[1]
                return R(200, {"commit": {"id": self.branches[b]}}) if b in self.branches else R(404, {"message": "404 Branch Not Found"})
            if method == "POST" and path.endswith("/repository/branches"):
                self.branches[kw["params"]["branch"]] = "sha"
                return R(201, {})
            if "/repository/files/" in path:
                p = path.split("/repository/files/")[1].replace("%2F", "/")
                return R(200, {"size": 5, "blob_id": "b", "content": base64.b64encode(self.files[p].encode()).decode()}) if p in self.files else R(404, {"message": "404 File Not Found"})
            if method == "POST" and path.endswith("/repository/commits"):
                for a in kw["json"]["actions"]:
                    self.files[a["file_path"]] = a["content"]
                return R(201, {"id": "c1"})
            if method == "POST" and path.endswith("/merge_requests"):
                return R(201, {"iid": 3, "web_url": "https://gitlab.example/acme/orders/-/merge_requests/3"})
            if method == "GET" and path.endswith("/merge_requests/3"):
                return R(200, {"state": self.pr.get("gl", "opened"), "merged_at": self.pr.get("merged_at"), "web_url": "u", "head_pipeline": {"status": "success"}, "reviewers": [{"id": 1}]})
            if method == "GET" and path.endswith("/merge_requests/3/approvals"):
                return R(200, {"approved": True})
        return R(404, {"message": f"unexpected {method} {path}"})


class ConnectorTests(unittest.TestCase):
    def test_github_flow_and_the_default_branch_is_refused(self):
        s = FakeSession("github", {"pom.xml": "<project/>"})
        c = gh.GitHubConnector("tok", session=s)
        self.assertEqual(c.whoami()["user"], "bot")
        info = c.test_connection("acme/orders")
        self.assertEqual((info["default_branch"], info["can_write"]), ("main", True))
        with self.assertRaises(gh.GitHostError):
            c.create_branch("acme/orders", "main", "main")
        with self.assertRaises(gh.GitHostError):
            c.commit_files("acme/orders", "main", "m", [{"path": "pom.xml", "content": "x"}])
        c.create_branch("acme/orders", "quanta/deps-1-x", "main")
        self.assertEqual(c.get_file("acme/orders", "pom.xml", "main")["content"], "<project/>")
        self.assertIsNone(c.get_file("acme/orders", "nope.xml", "main"))
        c.commit_files("acme/orders", "quanta/deps-1-x", "msg", [{"path": "pom.xml", "content": "<new/>"}])
        self.assertEqual(s.files["pom.xml"], "<new/>")
        pr = c.open_change_request("acme/orders", "quanta/deps-1-x", "main", "t", "b", draft=True, labels=["security"], reviewers=["alice"])
        self.assertEqual((pr["number"], pr["url"]), (7, "https://github.example/acme/orders/pull/7"))
        post = next(k for m, u, k, h in s.calls if m == "POST" and u.endswith("/pulls"))
        self.assertTrue(post["json"]["draft"])
        self.assertEqual(post["json"]["head"], "quanta/deps-1-x")
        self.assertTrue(all(h["Authorization"] == "Bearer tok" for _, _, _, h in s.calls))
        with self.assertRaises(gh.GitHostError):
            c.open_change_request("acme/orders", "main", "main", "t", "b")

    def test_github_pull_request_state_mapping(self):
        s = FakeSession("github")
        c = gh.GitHubConnector("tok", session=s)
        self.assertEqual(c.get_change_request("acme/orders", 7)["state"], "open")
        s.reviews = [{"state": "APPROVED", "user": {"login": "a"}}]
        r = c.get_change_request("acme/orders", 7)
        self.assertEqual((r["review_state"], r["checks_state"]), ("approved", "passing"))
        s.reviews = [{"state": "APPROVED", "user": {"login": "a"}}, {"state": "CHANGES_REQUESTED", "user": {"login": "b"}}]
        self.assertEqual(c.get_change_request("acme/orders", 7)["review_state"], "changes-requested")
        s.pr = {"state": "closed", "merged": True, "merged_at": "2026-10-02T10:00:00Z"}
        r = c.get_change_request("acme/orders", 7)
        self.assertEqual((r["state"], r["merged_at"]), ("merged", "2026-10-02T10:00:00Z"))

    def test_gitlab_flow(self):
        s = FakeSession("gitlab", {"pom.xml": "<project/>"})
        c = gh.GitLabConnector("tok", session=s)
        self.assertEqual(c.whoami()["user"], "bot")
        self.assertTrue(c.test_connection("acme/orders")["can_write"])
        c.create_branch("acme/orders", "quanta/deps-1-x", "main")
        c.commit_files("acme/orders", "quanta/deps-1-x", "msg", [{"path": "pom.xml", "content": "<new/>"}, {"path": "new.txt", "content": "n"}])
        commit = next(k for m, u, k, h in s.calls if u.endswith("/repository/commits"))
        self.assertEqual([a["action"] for a in commit["json"]["actions"]], ["update", "create"])
        pr = c.open_change_request("acme/orders", "quanta/deps-1-x", "main", "Title", "b", draft=True, labels=["a", "b"])
        self.assertEqual(pr["number"], 3)
        mr = next(k for m, u, k, h in s.calls if u.endswith("/merge_requests") and m == "POST")
        self.assertEqual((mr["json"]["title"], mr["json"]["labels"]), ("Draft: Title", "a,b"))
        self.assertTrue(all(h.get("PRIVATE-TOKEN") == "tok" for _, _, _, h in s.calls))
        self.assertEqual(c.get_change_request("acme/orders", 3)["review_state"], "approved")
        s.pr = {"gl": "merged", "merged_at": "2026-10-02T10:00:00Z"}
        self.assertEqual(c.get_change_request("acme/orders", 3)["state"], "merged")

    def test_errors_never_carry_the_token(self):
        s = FakeSession("github")
        c = gh.GitHubConnector("SECRET-TOKEN-123", session=s)
        with self.assertRaises(gh.GitHostError) as cx:
            c.test_connection("acme/missing/deep")
        self.assertNotIn("SECRET-TOKEN-123", str(cx.exception))
        with self.assertRaises(gh.GitHostError):
            gh.GitHubConnector("")
        with self.assertRaises(gh.GitHostError):
            gh.build("bitbucket", "t")


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.pol = policy.load()

    def test_branches(self):
        self.assertEqual(policy.branch_name(self.pol, 12, "dependency-upgrade", "log4j-core"), "quanta/deps-12-log4j-core")
        self.assertEqual(policy.branch_name(self.pol, 12, "code-fix", "SQL injection in db.py!", attempt=2), "quanta/code-12-sql-injection-in-db-py-r2")
        policy.check_branch(self.pol, "quanta/deps-1-x", base="main")
        for bad in ("main", "release/1.2", "production", "quanta/../x", "a b"):
            with self.assertRaises(policy.PolicyError, msg=bad):
                policy.check_branch(self.pol, bad, base="main")
        with self.assertRaises(policy.PolicyError):
            policy.check_branch(self.pol, "feature-x", base="main", default="feature-x")

    def test_denied_paths_and_limits(self):
        for path in (".github/workflows/ci.yml", ".gitlab-ci.yml", "CODEOWNERS", "docs/CODEOWNERS", "keys/server.pem", ".env", "svc/.env.prod", "../x", "/etc/passwd"):
            with self.assertRaises(policy.PolicyError, msg=path):
                policy.check_files(self.pol, [{"path": path, "content": "x"}])
        policy.check_files(self.pol, [{"path": "services/api/pom.xml", "content": "x"}])
        with self.assertRaises(policy.PolicyError):
            policy.check_files(self.pol, [{"path": f"f{i}.py", "content": "x"} for i in range(11)])
        with self.assertRaises(policy.PolicyError):
            policy.check_files(self.pol, [{"path": "a.py", "content": "x" * 600000}])
        with self.assertRaises(policy.PolicyError):
            policy.check_files(self.pol, [])

    def test_code_scope(self):
        policy.check_code_scope(self.pol, [{"path": "app/db.py"}], "app/db.py")
        with self.assertRaises(policy.PolicyError):
            policy.check_code_scope(self.pol, [{"path": "app/other.py"}], "app/db.py")
        wide = {**self.pol, "code_fix": {"scope": "same-directory"}}
        policy.check_code_scope(wide, [{"path": "app/test_db.py"}], "app/db.py")
        with self.assertRaises(policy.PolicyError):
            policy.check_code_scope(wide, [{"path": "lib/x.py"}], "app/db.py")

    def test_overrides_merge_by_repository(self):
        pol = {**self.pol, "overrides": [{"match": "acme/legacy-*", "pull_request": {"draft": True}, "approval": {"require_distinct_approver": True}}]}
        self.assertTrue(policy.for_repo(pol, "acme/legacy-billing")["pull_request"]["draft"])
        self.assertTrue(policy.for_repo(pol, "acme/legacy-billing")["pull_request"]["labels"])  # untouched keys remain
        self.assertFalse(policy.for_repo(pol, "acme/orders")["pull_request"]["draft"])

    def test_template_must_keep_the_id(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "p.yaml"
            import yaml
            bad = yaml.safe_load(policy.PATH.read_text(encoding="utf-8"))
            bad["branch"]["template"] = "fixed-name"
            p.write_text(yaml.safe_dump(bad), encoding="utf-8")
            with self.assertRaises(policy.PolicyError):
                policy.load(p)


class FlowBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.engine)
        self.app = store.upsert_application("orders", {"environment": "production", "internet_facing": True, "business_criticality": "high", "repo_provider": "github", "repo": "acme/orders",
                                                       "default_branch": "main", "manifest_paths": ["pom.xml"]}, "admin", self.engine)
        store.set_sbom("orders", SBOM, "ci", "admin", self.engine)
        self.fs = [dep_finding(1, "log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", sev="Critical", cvss=10.0, kev=True, epss=0.97),
                   dep_finding(2, "log4j-core", "2.14.1", "2.15.0", "CVE-2021-45046", cvss=9.0), code_finding(5, "app/db.py")]
        self.a = analysis.analyse("orders", self.fs, engine=self.engine)
        self.item = next(i for i in self.a["work_items"] if i.get("package") == "log4j-core")
        self.compact = [f for f in self.a["findings"] if f["id"] in self.item["finding_ids"]]
        self.pom = TestPom
        self.session = FakeSession("github", {"pom.xml": TestPom, "app/db.py": FILE})
        self.conn = gh.GitHubConnector("tok", session=self.session)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def make(self, **kw):
        return proposals.create_dependency(self.app, self.item, self.compact, self.a["reachability"], {"pom.xml": TestPom}, "alice", engine=self.engine, group="org.apache.logging.log4j", **kw)


TestPom = UpgradeTests.POM


class ProposalTests(FlowBase):
    def test_a_dependency_proposal_carries_the_evidence(self):
        p = self.make(lockfiles=[])
        self.assertEqual((p["status"], p["kind"], p["branch"]), ("draft", "dependency-upgrade", f"quanta/deps-{p['id']}-log4j-core"))
        self.assertEqual(p["finding_ids"], ["FIND-1", "FIND-2"])
        self.assertEqual(p["files"][0]["path"], "pom.xml")
        self.assertIn("<log4j.version>2.17.1</log4j.version>", p["files"][0]["new_content"])
        body = p["pr_body"]
        low = body.lower()
        for needle in ("## Evidence", "CVE-2021-44228", "known exploited", "**P1**", "Exposure: **internet**", "## How to verify", "mvn -U dependency:tree -Dincludes=log4j-core", "## Rollback",
                       "## Process", "Quanta never merges", "refresh it on this branch"):
            self.assertIn(needle.lower(), low, needle)
        self.assertEqual(p["pr_title"], "fix(deps): upgrade log4j-core to 2.17.1 [FIND-1, FIND-2]")
        self.assertNotIn("Approved in Quanta", body)

    def test_the_same_change_cannot_be_proposed_twice_while_active(self):
        p = self.make()
        with self.assertRaises(ValueError) as cx:
            self.make()
        self.assertIn(f"Proposal {p['id']}", str(cx.exception))
        proposals.discard(p["id"], "alice", "wrong", self.engine)
        self.assertEqual(self.make()["status"], "draft")

    def test_no_fixed_version_means_no_proposal(self):
        item = {**self.item, "target_version": None}
        with self.assertRaises(ValueError) as cx:
            proposals.create_dependency(self.app, item, self.compact, None, {"pom.xml": TestPom}, "alice", engine=self.engine)
        self.assertIn("No fixed version", str(cx.exception))

    def test_wrong_ecosystem_files_are_refused(self):
        with self.assertRaises(ValueError):
            proposals.create_dependency(self.app, self.item, self.compact, None, {"package.json": "{}"}, "alice", engine=self.engine)

    def test_approval_rules(self):
        p = self.make()
        with self.assertRaises(ValueError):
            proposals.open_pr(p["id"], "alice", confirm=False, engine=self.engine)  # not approved yet
        strict = {**policy.load(), "approval": {**policy.load()["approval"], "require_distinct_approver": True}}
        with self.assertRaises(ValueError):
            proposals.approve(p["id"], "alice", self.engine, policy=strict)
        a = proposals.approve(p["id"], "bob", self.engine, policy=strict)
        self.assertEqual((a["status"], a["approved_by"]), ("approved", "bob"))
        self.assertIn("Approved in Quanta by bob", a["pr_body"])
        with self.assertRaises(ValueError):
            proposals.approve(p["id"], "bob", self.engine)

    def test_dry_run_sends_nothing_and_shows_the_plan(self):
        p = self.make()
        proposals.approve(p["id"], "bob", self.engine)
        r = proposals.open_pr(p["id"], "bob", confirm=False, connection_name="GitHub (prod)", engine=self.engine)
        self.assertTrue(r["preview_only"])
        self.assertEqual(r["plan"]["branch"], p["branch"])
        self.assertIn("Quanta does not merge", " ".join(r["plan"]["steps"]))
        self.assertEqual(r["plan"]["files"][0]["path"], "pom.xml")
        self.assertEqual(self.session.calls, [])
        self.assertEqual(proposals.get(p["id"], self.engine)["status"], "approved")

    def test_open_pr_creates_branch_commits_and_opens(self):
        p = self.make(lockfiles=["package-lock.json"])
        proposals.approve(p["id"], "bob", self.engine)
        r = proposals.open_pr(p["id"], "bob", confirm=True, connector=self.conn, findings=self.fs, engine=self.engine)
        self.assertFalse(r["preview_only"])
        q = proposals.get(p["id"], self.engine)
        self.assertEqual((q["status"], q["pr_number"], q["pr_state"], q["opened_by"]), ("pr-opened", 7, "open", "bob"))
        self.assertIn(p["branch"], self.session.branches)
        self.assertIn("2.17.1", self.session.files["pom.xml"])
        post = next(k for m, u, k, h in self.session.calls if m == "POST" and u.endswith("/pulls"))
        self.assertTrue(post["json"]["draft"])  # a lock file is present, so it opens as a draft
        self.assertEqual(post["json"]["base"], "main")
        self.assertNotIn("main", [k["json"]["branch"] for m, u, k, h in self.session.calls if m == "PUT"])
        queued = {i["finding_id"]: i for i in factory.items(self.fs, self.engine)}
        self.assertEqual(queued["FIND-1"]["state"], "pr-opened")
        self.assertTrue(queued["FIND-1"]["pr_url"].endswith("/pull/7"))

    def test_open_pr_refuses_an_existing_branch_and_a_read_only_token(self):
        p = self.make()
        proposals.approve(p["id"], "bob", self.engine)
        self.session.branches[p["branch"]] = "sha"
        with self.assertRaises(ValueError) as cx:
            proposals.open_pr(p["id"], "bob", confirm=True, connector=self.conn, engine=self.engine)
        self.assertIn("already exists", str(cx.exception))
        self.assertEqual(proposals.get(p["id"], self.engine)["status"], "failed")
        self.assertFalse(any(m in ("PUT", "POST") for m, u, k, h in self.session.calls))  # nothing was written

        class ReadOnly(gh.GitHubConnector):
            def test_connection(self, repo):
                return {"default_branch": "main", "can_write": False}
        with self.assertRaises(ValueError) as cx:
            proposals.open_pr(p["id"], "bob", confirm=True, connector=ReadOnly("t", session=self.session), engine=self.engine)
        self.assertIn("cannot write", str(cx.exception))

    def test_a_failure_midway_is_recorded_and_the_retry_uses_a_new_branch(self):
        p = self.make()
        proposals.approve(p["id"], "bob", self.engine)

        class Boom(gh.GitHubConnector):
            def commit_files(self, *a, **k):
                raise gh.GitHostError("commit refused")
        with self.assertRaises(ValueError) as cx:
            proposals.open_pr(p["id"], "bob", confirm=True, connector=Boom("t", session=self.session), engine=self.engine)
        self.assertIn("left in place", str(cx.exception))
        q = proposals.get(p["id"], self.engine)
        self.assertEqual(q["status"], "failed")
        self.assertIn("commit refused", q["last_error"])
        proposals.open_pr(p["id"], "bob", confirm=True, connector=self.conn, engine=self.engine)
        q = proposals.get(p["id"], self.engine)
        self.assertEqual((q["status"], q["branch"]), ("pr-opened", p["branch"] + "-r2"))

    def test_open_without_a_connection_or_repository(self):
        p = self.make()
        proposals.approve(p["id"], "bob", self.engine)
        with self.assertRaises(ValueError) as cx:
            proposals.open_pr(p["id"], "bob", confirm=True, connector=None, engine=self.engine)
        self.assertIn("connection", str(cx.exception))
        store.upsert_application("bare", {}, "a", self.engine)
        bare = store.get_application("bare", self.engine)
        item = {**self.item}
        p2 = proposals.create_dependency(bare, item, self.compact, None, {"pom.xml": TestPom}, "alice", engine=self.engine, group="g")
        proposals.approve(p2["id"], "bob", self.engine)
        with self.assertRaises(ValueError) as cx:
            proposals.open_pr(p2["id"], "bob", confirm=False, engine=self.engine)
        self.assertIn("repository", str(cx.exception))

    def test_a_denied_path_never_leaves(self):
        item = {**self.item, "ecosystem": "maven"}
        with self.assertRaises(policy.PolicyError):
            proposals.create_dependency(self.app, item, self.compact, None, {".github/pom.xml": TestPom}, "alice", engine=self.engine, group="g")

    def test_code_fix_proposal_applies_strictly_and_stays_in_scope(self):
        f = self.fs[2]
        compact = next(c for c in self.a["findings"] if c["id"] == "FIND-5")
        p = proposals.create_code(self.app, f, compact, self.a["reachability"], {"app/db.py": FILE}, {"app/db.py": PATCH}, "Use a parameterised query.",
                                  {"confirmed_vulnerable": True, "business_logic": "Same rows returned", "risks": ["none known"]}, "alice", engine=self.engine)
        self.assertEqual((p["kind"], p["branch"].startswith("quanta/code-")), ("code-fix", True))
        self.assertIn("(name,)", p["files"][0]["new_content"])
        self.assertIn("These are the fix author's statements, not test results.", p["pr_body"])
        self.assertIn("Confirmed the problem exists: True", p["pr_body"])
        with self.assertRaises(ValueError) as cx:
            proposals.create_code(self.app, {**f, "id": "FIND-9"}, compact, None, {"app/other.py": FILE}, {"app/other.py": PATCH}, "", {}, "alice", engine=self.engine)
        self.assertIn("may change only", str(cx.exception))
        with self.assertRaises(ValueError) as cx:
            proposals.create_code(self.app, {**f, "id": "FIND-8"}, compact, None, {"app/db.py": FILE.replace("cursor", "conn")}, {"app/db.py": PATCH}, "", {}, "alice", engine=self.engine)
        self.assertIn("does not match", str(cx.exception))


class TrackingTests(FlowBase):
    def opened(self):
        p = self.make()
        proposals.approve(p["id"], "bob", self.engine)
        proposals.open_pr(p["id"], "bob", confirm=True, connector=self.conn, findings=self.fs, engine=self.engine)
        return p["id"]

    def test_sync_follows_review_and_merge(self):
        pid = self.opened()
        self.session.reviews = [{"state": "APPROVED", "user": {"login": "a"}}]
        rep = proposals.sync(lambda p: self.conn, self.engine)
        self.assertEqual((rep[0]["ok"], rep[0]["status"], rep[0]["review_state"]), (True, "in-review", "approved"))
        self.session.pr = {"state": "closed", "merged": True, "merged_at": "2026-10-02T10:00:00Z"}
        proposals.sync(lambda p: self.conn, self.engine)
        q = proposals.get(pid, self.engine)
        self.assertEqual((q["status"], q["merged_at"]), ("merged", "2026-10-02T10:00:00Z"))
        self.assertEqual(factory.items(self.fs, self.engine)[0]["state"], "merged")
        self.assertEqual(proposals.sync(lambda p: self.conn, self.engine), [])  # nothing left to poll

    def test_sync_reports_a_missing_connection_and_a_failing_host(self):
        self.opened()
        self.assertFalse(proposals.sync(lambda p: None, self.engine)[0]["ok"])

        class Down:
            def get_change_request(self, *a):
                raise gh.GitHostError("host down")
        rep = proposals.sync(lambda p: Down(), self.engine)
        self.assertFalse(rep[0]["ok"])
        self.assertIn("host down", proposals.list_proposals(engine=self.engine)[0]["last_error"])

    def test_closed_without_merge(self):
        pid = self.opened()
        self.session.pr = {"state": "closed", "merged": False}
        proposals.sync(lambda p: self.conn, self.engine)
        self.assertEqual(proposals.get(pid, self.engine)["status"], "closed")

    def test_inbound_state_by_number_or_url(self):
        pid = self.opened()
        q = proposals.record_external(str(pid), "merged", "2026-10-03T09:00:00Z", "apikey:ci", self.engine)
        self.assertEqual((q["status"], q["merged_at"]), ("merged", "2026-10-03T09:00:00Z"))
        with self.assertRaises(KeyError):
            proposals.record_external("999", "merged", None, "k", self.engine)
        with self.assertRaises(ValueError):
            proposals.record_external(str(pid), "weird", None, "k", self.engine)
        d = proposals.create_code(self.app, self.fs[2], self.a["findings"][-1], None, {"app/db.py": FILE}, {"app/db.py": PATCH}, "", {}, "alice", engine=self.engine)
        with self.assertRaises(ValueError):
            proposals.record_external(str(d["id"]), "merged", None, "k", self.engine)

    def test_verification_after_merge(self):
        pid = self.opened()
        self.assertEqual(proposals.verify_one(proposals.get(pid, self.engine), {})["state"], "not-merged")
        proposals.record_external(str(pid), "merged", "2026-10-02T10:00:00Z", "k", self.engine)
        p = proposals.get(pid, self.engine)
        seen_after = {f["id"]: {**f, "last_seen": "2026-10-03"} for f in self.fs}
        self.assertEqual(proposals.verify_one(p, seen_after)["state"], "still-present")
        seen_before = {f["id"]: {**f, "last_seen": "2026-10-01"} for f in self.fs}
        self.assertEqual(proposals.verify_one(p, seen_before)["state"], "awaiting-rescan")
        partly = {"FIND-2": seen_before["FIND-2"]}
        self.assertEqual(proposals.verify_one(p, partly)["state"], "awaiting-rescan")
        self.assertEqual(proposals.verify_one(p, {})["state"], "verified")
        out = proposals.verify_all([], self.engine)
        self.assertEqual(out[0]["state"], "verified")
        q = proposals.get(pid, self.engine)
        self.assertEqual(q["verified_state"], "verified")
        self.assertIsNotNone(q["verified_at"])
        # the loop: after a merge that did not fix it, the same change can be proposed again
        proposals.verify_all(list(seen_after.values()), self.engine)
        self.assertEqual(proposals.get(pid, self.engine)["verified_state"], "still-present")
        self.assertEqual(self.make()["status"], "draft")


class VelocityTests(unittest.TestCase):
    def test_times_outcomes_and_throughput(self):
        now = datetime.datetime(2026, 10, 2, 12, 0, tzinfo=datetime.timezone.utc)
        p = lambda **k: {"application": "orders", "finding_ids": ["FIND-1"], "status": "draft", "created_at": None, "approved_at": None, "opened_at": None, "merged_at": None, "verified_at": None,  # noqa: E731
                         "verified_state": None, "review_state": None, "checks_state": None, **k}
        ps = [p(status="merged", created_at="2026-09-28T08:00:00Z", approved_at="2026-09-28T10:00:00Z", opened_at="2026-09-28T11:00:00Z", merged_at="2026-09-30T11:00:00Z",
                verified_at="2026-10-01T11:00:00Z", verified_state="verified"),
              p(status="merged", created_at="2026-09-29T08:00:00Z", approved_at="2026-09-29T12:00:00Z", opened_at="2026-09-29T13:00:00Z", merged_at="2026-09-29T23:00:00Z", verified_state="still-present"),
              p(status="in-review", opened_at="2026-10-01T12:00:00Z", review_state="changes-requested", checks_state="failing"), p(status="draft")]
        v = velocity.compute(ps, [{"id": "FIND-1", "first_seen": "2026-09-20"}], now=now)
        self.assertEqual(v["by_status"], {"merged": 2, "in-review": 1, "draft": 1})
        self.assertEqual(v["open_pull_requests"], {"count": 1, "oldest_hours": 24.0, "median_age_hours": 24.0, "waiting_for_review": 0, "changes_requested": 1, "failing_checks": 1})
        self.assertEqual(v["stages"]["created_to_approved"], {"n": 2, "median_hours": 3.0, "p90_hours": 4.0})
        self.assertEqual(v["stages"]["opened_to_merged"]["n"], 2)
        self.assertEqual(v["stages"]["merged_to_verified"], {"n": 1, "median_hours": 24.0, "p90_hours": 24.0})
        self.assertEqual(v["stages"]["detected_to_pull_request"]["n"], 3)
        self.assertEqual(v["outcomes"]["merged"], 2)
        self.assertEqual((v["outcomes"]["verified"], v["outcomes"]["still_present"]), (1, 1))
        self.assertEqual(sum(w["merged"] for w in v["merged_per_week"]), 2)
        self.assertEqual(len(v["merged_per_week"]), 12)
        self.assertEqual(v["by_application"][0]["verified"], 1)

    def test_empty_stages_report_no_number(self):
        v = velocity.compute([], [])
        self.assertIsNone(v["stages"]["opened_to_merged"]["median_hours"])
        self.assertEqual(v["proposals"], 0)


if __name__ == "__main__":
    unittest.main()
