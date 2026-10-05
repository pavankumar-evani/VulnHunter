"""
Tests for keeping pull requests in step without a person clicking: signed webhooks, the scheduled sync, the rescan after a merge, and the demo seeding command.
"""
import hashlib
import hmac
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as dashboard_app_module  # noqa: E402
import appsec_api  # noqa: E402
from appsec_fixtures import SBOM  # noqa: E402
from remediation.appsec import demo, store as app_store  # noqa: E402
from remediation.connectors import git_host_connector as gh  # noqa: E402
from remediation.gitops import proposals, service, webhooks  # noqa: E402
from test_appsec_api import ApiBase  # noqa: E402
from test_gitops import FakeSession, TestPom  # noqa: E402

SECRET = "whsec-test-secret-value"


def sign(body):
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


class WebhookUnitTests(unittest.TestCase):
    def test_github_signature(self):
        body = b'{"a": 1}'
        webhooks.verify_github(SECRET, body, sign(body))
        for bad in (None, "", "sha1=abc", "sha256=" + "0" * 64, sign(b"other")):
            with self.assertRaises(webhooks.WebhookError) as cx:
                webhooks.verify_github(SECRET, body, bad)
            self.assertEqual(cx.exception.status, 401)
        with self.assertRaises(webhooks.WebhookError) as cx:
            webhooks.verify_github("", body, sign(body))
        self.assertEqual(cx.exception.status, 503)  # no secret configured: refuse everything

    def test_gitlab_token(self):
        webhooks.verify_gitlab(SECRET, SECRET)
        for bad in (None, "", "nope"):
            with self.assertRaises(webhooks.WebhookError):
                webhooks.verify_gitlab(SECRET, bad)
        with self.assertRaises(webhooks.WebhookError) as cx:
            webhooks.verify_gitlab("", SECRET)
        self.assertEqual(cx.exception.status, 503)

    def test_provider_detection_is_case_insensitive(self):
        self.assertEqual(webhooks.provider_of({"X-Hub-Signature-256": "x"}), "github")
        self.assertEqual(webhooks.provider_of({"x-gitlab-event": "Merge Request Hook"}), "gitlab")
        self.assertIsNone(webhooks.provider_of({"content-type": "application/json"}))

    def test_github_events(self):
        pr = {"html_url": "https://github.example/a/b/pull/7", "merged": True, "merged_at": "2026-10-03T08:00:00Z"}
        self.assertEqual(webhooks.parse_github("pull_request", {"action": "closed", "pull_request": pr}), {"pr_url": pr["html_url"], "state": "merged", "merged_at": pr["merged_at"]})
        self.assertEqual(webhooks.parse_github("pull_request", {"action": "closed", "pull_request": {**pr, "merged": False}})["state"], "closed")
        self.assertEqual(webhooks.parse_github("pull_request", {"action": "reopened", "pull_request": pr})["state"], "open")
        self.assertIsNone(webhooks.parse_github("ping", {}))
        self.assertIsNone(webhooks.parse_github("pull_request", {"action": "labeled", "pull_request": pr}))
        self.assertIsNone(webhooks.parse_github("pull_request", {"action": "closed", "pull_request": {}}))

    def test_gitlab_events(self):
        mr = {"url": "https://gitlab.example/a/b/-/merge_requests/3", "state": "merged", "merged_at": "2026-10-03 08:00:00 UTC"}
        self.assertEqual(webhooks.parse_gitlab("Merge Request Hook", {"object_attributes": mr})["state"], "merged")
        self.assertEqual(webhooks.parse_gitlab("Merge Request Hook", {"object_attributes": {**mr, "state": "closed"}})["merged_at"], None)
        self.assertIsNone(webhooks.parse_gitlab("Push Hook", {"object_attributes": mr}))
        self.assertIsNone(webhooks.parse_gitlab("Merge Request Hook", {"object_attributes": {**mr, "state": "weird"}}))


class AutomationApiTests(ApiBase):
    def setUp(self):
        super().setUp()
        self.login("admin@t.local")
        self.make_app()
        self.client.post("/api/applications/orders/sbom", content=json.dumps(SBOM))
        self.session = FakeSession("github", {"pom.xml": TestPom})
        self.conn = gh.GitHubConnector("tok", session=self.session)
        self.patches = [patch.object(appsec_api.gitops_service, "connector", return_value=(self.conn, {"name": "GitHub"})),
                        patch.object(appsec_api.gitops_service, "find_connection", return_value=({"name": "GitHub"}, {}))]
        for p in self.patches:
            p.start()
        r = self.client.post("/api/gitops/proposals/dependency", json={"application": "orders", "item_id": "dep:log4j-core", "manifests": {"pom.xml": TestPom}})
        self.pid = r.json()["id"]
        self.client.post(f"/api/gitops/proposals/{self.pid}/approve")
        out = self.client.post(f"/api/gitops/proposals/{self.pid}/open", json={"confirm": True})
        self.assertEqual(out.status_code, 200, out.text)
        self.pr_url = out.json()["pr_url"]
        self.client.cookies.clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        super().tearDown()

    def hook(self, payload, secret_env=SECRET, sig=None, headers=None):
        body = json.dumps(payload).encode()
        h = {"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sign(body) if sig is None else sig, "Content-Type": "application/json", **(headers or {})}
        with patch.dict(os.environ, {"QUANTA_GIT_WEBHOOK_SECRET": secret_env}):
            return self.client.post("/api/inbound/git-webhook", content=body, headers=h)

    def merged_payload(self, url=None):
        return {"action": "closed", "pull_request": {"html_url": url or self.pr_url, "merged": True, "merged_at": "2026-10-03T08:00:00Z"}}

    def test_a_signed_github_merge_updates_the_proposal_without_a_login(self):
        r = self.hook(self.merged_payload())
        self.assertEqual((r.status_code, r.json()["status"]), (200, "merged"), r.text)
        p = proposals.get(self.pid, self.engine)
        self.assertEqual((p["status"], p["merged_at"]), ("merged", "2026-10-03T08:00:00Z"))

    def test_bad_or_missing_signature_and_unconfigured_secret_are_refused(self):
        self.assertEqual(self.hook(self.merged_payload(), sig="sha256=" + "0" * 64).status_code, 401)
        self.assertEqual(self.hook(self.merged_payload(), secret_env="").status_code, 503)
        self.assertEqual(proposals.get(self.pid, self.engine)["status"], "pr-opened")  # nothing changed
        with patch.dict(os.environ, {"QUANTA_GIT_WEBHOOK_SECRET": SECRET}):
            self.assertEqual(self.client.post("/api/inbound/git-webhook", json={"x": 1}).status_code, 400)  # not a GitHub or GitLab delivery

    def test_unrelated_pull_requests_and_events_are_ignored_quietly(self):
        r = self.hook(self.merged_payload("https://github.example/other/repo/pull/99"))
        self.assertEqual((r.status_code, "ignored" in r.json()), (200, True))
        r = self.hook({"action": "labeled", "pull_request": {"html_url": self.pr_url}})
        self.assertIn("ignored", r.json())
        r = self.hook({"zen": "hi"}, headers={"X-GitHub-Event": "ping"})
        self.assertIn("ignored", r.json())
        self.assertEqual(proposals.get(self.pid, self.engine)["status"], "pr-opened")

    def test_gitlab_token_delivery(self):
        mr = {"object_attributes": {"url": self.pr_url, "state": "merged", "merged_at": "2026-10-03T09:00:00Z"}}
        with patch.dict(os.environ, {"QUANTA_GIT_WEBHOOK_SECRET": SECRET}):
            bad = self.client.post("/api/inbound/git-webhook", json=mr, headers={"X-Gitlab-Event": "Merge Request Hook", "X-Gitlab-Token": "wrong"})
            ok = self.client.post("/api/inbound/git-webhook", json=mr, headers={"X-Gitlab-Event": "Merge Request Hook", "X-Gitlab-Token": SECRET})
        self.assertEqual(bad.status_code, 401)
        self.assertEqual((ok.status_code, ok.json()["status"]), (200, "merged"))

    def test_rescan_after_merge_queues_syncs_or_says_there_is_nothing_to_queue(self):
        self.hook(self.merged_payload())
        self.login("user@t.local")
        self.assertEqual(self.client.post(f"/api/gitops/proposals/{self.pid}/rescan").status_code, 403)
        self.login("admin@t.local")
        r = self.client.post(f"/api/gitops/proposals/{self.pid}/rescan")
        self.assertEqual((r.status_code, r.json()["queued"]), (200, []))
        self.assertIn("No enabled scanner connection", r.json()["message"])
        with patch.object(service, "scanner_connections", return_value=[{"id": 5, "name": "Tenable (prod)"}]):
            r3 = self.client.post(f"/api/gitops/proposals/{self.pid}/rescan")
        self.assertEqual(r3.status_code, 200, r3.text)
        self.assertEqual([q["connection"] for q in r3.json()["queued"]], ["Tenable (prod)"])
        self.assertTrue(isinstance(r3.json()["queued"][0]["job"], int))
        self.assertEqual(self.client.post("/api/gitops/proposals/9999/rescan").status_code, 404)

    def test_rescan_is_refused_before_a_merge(self):
        self.login("admin@t.local")
        self.assertEqual(self.client.post(f"/api/gitops/proposals/{self.pid}/rescan").status_code, 409)

    def test_policy_endpoint_reports_the_automation_state(self):
        self.login("user@t.local")
        with patch.dict(os.environ, {"QUANTA_GIT_WEBHOOK_SECRET": "", "QUANTA_GITOPS_SYNC": "false"}):
            a = self.client.get("/api/gitops/policy").json()["automation"]
        self.assertEqual(a, {"webhook_configured": False, "scheduled_sync": False})
        with patch.dict(os.environ, {"QUANTA_GIT_WEBHOOK_SECRET": SECRET, "QUANTA_GITOPS_SYNC": "true"}):
            a = self.client.get("/api/gitops/policy").json()["automation"]
        self.assertEqual(a, {"webhook_configured": True, "scheduled_sync": True})

    def test_the_scheduled_tick_follows_open_pull_requests_and_can_be_switched_off(self):
        calls = []
        with patch.object(dashboard_app_module.gitops_service, "sync_and_verify", side_effect=lambda f: calls.append(f) or ([], [])):
            with patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=[]):
                with patch.dict(os.environ, {"QUANTA_GITOPS_SYNC": "false"}):
                    self.assertIsNone(dashboard_app_module._run_gitops_sync_if_due())
                self.assertEqual(calls, [])
                with patch.dict(os.environ, {"QUANTA_GITOPS_SYNC": "true"}):
                    dashboard_app_module._run_gitops_sync_if_due()
                self.assertEqual(len(calls), 1)  # one proposal has an open pull request
                proposals.record_external(str(self.pid), "closed", None, "t", self.engine)
                dashboard_app_module._run_gitops_sync_if_due()
                self.assertEqual(len(calls), 1)  # nothing open any more: no host is contacted


class ServiceTests(ApiBase):
    def test_sync_and_verify_with_nothing_open_builds_no_connector(self):
        with patch.object(service, "connector_for_proposal", side_effect=AssertionError("must not be built")):
            self.assertEqual(service.sync_and_verify([], self.engine), ([], []))
        self.assertFalse(service.has_open_pull_requests(self.engine))

    def test_scanner_connections_are_enabled_pull_connections_of_findings_only(self):
        rows = [{"id": 1, "type": "tenable", "enabled": True, "name": "T"}, {"id": 2, "type": "tenable", "enabled": False, "name": "Off"},
                {"id": 3, "type": "jira", "enabled": True, "name": "J"}, {"id": 4, "type": "github", "enabled": True, "name": "G"},
                {"id": 5, "type": "infoblox", "enabled": True, "name": "I"}, {"id": 6, "type": "prismacloud", "enabled": True, "name": "P"}]
        with patch.object(service.conn_store, "list_connections", return_value=rows):
            self.assertEqual([c["name"] for c in service.scanner_connections()], ["T", "P"])


class DemoTests(unittest.TestCase):
    def test_seed_and_remove_touch_only_the_demo_source(self):
        from sqlalchemy import create_engine
        with tempfile.TemporaryDirectory() as d:
            engine = create_engine(f"sqlite:///{Path(d) / 't.db'}")
            path = Path(d) / "f.json"
            other = {"id": "FIND-1", "source": "tenable", "source_ref": "x", "title": "keep me", "severity": "Low", "asset": {"name": "h"}, "cve": None}
            path.write_text(json.dumps([other]), encoding="utf-8")
            out = demo.seed("demo-app", "t", engine, findings_path=path)
            self.assertEqual((out["application"], out["findings"]["added"]), ("demo-app", 5))
            self.assertIn('name: "demo-app"', out["topology_snippet"])
            self.assertIsNotNone(app_store.get_application("demo-app", engine))
            self.assertEqual(len(json.loads(path.read_text(encoding="utf-8"))), 6)
            again = demo.seed("demo-app", "t", engine, findings_path=path)
            self.assertEqual((again["findings"]["added"], again["findings"]["removed"]), (0, 0))  # idempotent
            gone = demo.remove("demo-app", engine, findings_path=path)
            self.assertEqual((gone["application_removed"], gone["findings"]["removed"]), (True, 5))
            self.assertEqual([f["title"] for f in json.loads(path.read_text(encoding="utf-8"))], ["keep me"])
            engine.dispose()


class DemoCommandTests(unittest.TestCase):
    def test_the_admin_command_parses_runs_and_prints_the_topology_entry(self):
        import contextlib
        import io

        import quanta_admin
        args = quanta_admin.build_parser().parse_args(["seed-appsec-demo", "--name", "x-app"])
        self.assertEqual((args.name, args.remove), ("x-app", False))
        with patch.object(demo, "seed", return_value={"application": "x-app", "components": 6, "findings": {"added": 5}, "topology_snippet": 'name: "x-app"'}) as seed:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(quanta_admin.cmd_seed_appsec_demo(args), 0)
        seed.assert_called_once()
        out = buf.getvalue()
        self.assertIn('"application": "x-app"', out)
        self.assertIn("network_topology.yaml", out)
        self.assertIn('name: "x-app"', out)
        rm = quanta_admin.build_parser().parse_args(["seed-appsec-demo", "--remove"])
        with patch.object(demo, "remove", return_value={"application_removed": True}) as remove:
            with contextlib.redirect_stdout(io.StringIO()):
                quanta_admin.cmd_seed_appsec_demo(rm)
        remove.assert_called_once_with("orders-service")


if __name__ == "__main__":
    unittest.main()
