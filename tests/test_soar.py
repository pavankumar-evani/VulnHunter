"""
Tests for SOAR: the signed response and notification webhooks, playbook validation, the run engine (dry runs, approvals, conditions,
failures, automatic runs), and the API.
"""
import datetime
import hashlib
import hmac
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.connections import registry  # noqa: E402
from remediation.connectors import webhook_connector as wh  # noqa: E402
from remediation.hunting import service, store  # noqa: E402
from remediation.soar import engine as soar, playbooks  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
NOW = datetime.datetime(2026, 10, 15, 12, 0, tzinfo=datetime.timezone.utc)
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}


def fnd(i, host="WEB-1"):
    return {"id": f"FIND-{i}", "title": "Vuln", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": host}, "attack_techniques": [T1190], "kev": {"listed": True}, "epss": {"score": 0.9}}


class FakePost:
    def __init__(self, status=200):
        self.calls, self.status = [], status

    def post(self, url, data=None, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "data": data, "json": json, "headers": headers})

        class R:
            status_code = self.status
        return R()


class WebhookTests(unittest.TestCase):
    def test_signature_covers_timestamp_and_body(self):
        fake = FakePost()
        w = wh.ResponseWebhook("https://soar.example/h", "s3cret", session=fake, clock=lambda: 1_790_000_000)
        w.send("isolate-host", "WEB-1", {"alert_id": 4, "requested_by": "a@t"})
        call = fake.calls[0]
        body = call["data"]
        want = "sha256=" + hmac.new(b"s3cret", f"1790000000.{body}".encode(), hashlib.sha256).hexdigest()
        self.assertEqual(call["headers"]["X-Quanta-Signature"], want)
        self.assertEqual(call["headers"]["X-Quanta-Timestamp"], "1790000000")
        payload = json.loads(body)
        self.assertEqual((payload["action"], payload["target"], payload["alert_id"]), ("isolate-host", "WEB-1", 4))

    def test_only_known_allowed_actions_with_a_target(self):
        w = wh.ResponseWebhook("https://x", "s", allowed_actions=["create-ticket"], session=FakePost())
        for action, target in (("format-disk", "x"), ("isolate-host", "x"), ("create-ticket", " ")):
            with self.assertRaises(wh.WebhookError):
                w.send(action, target)
        w.send("create-ticket", "T")
        with self.assertRaises(ValueError):
            wh.ResponseWebhook("https://x", "")

    def test_endpoint_errors_are_raised_and_notify_posts_text(self):
        with self.assertRaises(wh.WebhookError):
            wh.ResponseWebhook("https://x", "s", session=FakePost(500)).send("create-ticket", "T")
        fake = FakePost()
        wh.NotifyWebhook("https://hooks.example/x", session=fake).send("hello")
        self.assertEqual(fake.calls[0]["json"], {"text": "hello"})
        with self.assertRaises(wh.WebhookError):
            wh.NotifyWebhook("https://x", session=FakePost(404)).send("hi")

    def test_destructive_flag(self):
        self.assertTrue(wh.ACTIONS["isolate-host"][1])
        self.assertFalse(wh.ACTIONS["create-ticket"][1])


def step(t, **p):
    d = {"type": t, "params": p}
    return d


class ValidationTests(unittest.TestCase):
    def v(self, steps, trigger=None, name="pb"):
        return playbooks.validate(name, trigger, steps)

    def test_every_template_is_valid(self):
        for t in playbooks.templates():
            playbooks.validate(t["name"], t["trigger"], t["steps"])

    def test_a_destructive_action_needs_an_approval_before_it(self):
        with self.assertRaisesRegex(ValueError, "request-approval"):
            self.v([step("response-action", action="isolate-host", target="{asset}")])
        with self.assertRaisesRegex(ValueError, "request-approval"):
            self.v([step("response-action", action="isolate-host", target="x"), step("request-approval")])
        self.v([step("request-approval"), step("response-action", action="isolate-host", target="{asset}")])
        self.v([step("response-action", action="create-ticket", target="t")])  # not destructive

    def test_a_playbook_cannot_close_an_alert_or_use_unknown_things(self):
        with self.assertRaisesRegex(ValueError, "closing an alert"):
            self.v([step("update-alert", status="closed")])
        self.v([step("update-alert", status="investigating")])
        self.v([step("update-alert", assignee="a@t")])
        for bad in ([step("update-alert")], [{"type": "nope", "params": {}}], [step("response-action", action="format-disk", target="x")], [step("add-note", text=" ")],
                    [step("notify", channel="sms", text="x")], [step("notify", channel="email", text="x", to="not-an-email")], [], "steps"):
            with self.assertRaises(ValueError, msg=str(bad)):
                self.v(bad)

    def test_conditions_are_checked(self):
        self.v([{"type": "add-note", "params": {"text": "x"}, "when": {"path": "investigation.verdict", "op": "eq", "value": "a"}}])
        for when in ({"path": "bad path!", "op": "eq"}, {"path": "a", "op": "regex"}, "text"):
            with self.assertRaises(ValueError):
                self.v([{"type": "add-note", "params": {"text": "x"}, "when": when}])

    def test_on_alert_playbooks_may_only_do_safe_things(self):
        on = {"mode": "on-alert", "min_severity": "High"}
        self.v([step("investigate"), step("add-note", text="x"), step("update-alert", status="investigating"), step("notify", channel="webhook", text="x"),
                step("response-action", action="create-ticket", target="t")], on)
        for bad in (step("investigate", reputation=True), step("investigate", siem=True), step("enrich-indicators"), step("request-approval"),
                    step("response-action", action="enrich-asset", target="x") if False else step("response-action", action="block-ip", target="x")):
            with self.assertRaises(ValueError, msg=str(bad)):
                self.v([step("request-approval"), bad] if bad["type"] == "response-action" else [bad], on)

    def test_trigger_and_size_limits(self):
        with self.assertRaises(ValueError):
            self.v([step("add-note", text="x")], {"mode": "cron"})
        with self.assertRaises(ValueError):
            self.v([step("add-note", text="x")] * 26)
        with self.assertRaises(ValueError):
            self.v([step("add-note", text="x")], name=" ")

    def test_trigger_matching(self):
        pb = {"enabled": True, "trigger": {"mode": "on-alert", "min_severity": "High", "techniques": ["T1190"], "rule_contains": "shell"}}
        a = {"severity": "Critical", "technique": "T1190.001", "rule_name": "Web Shell spawn"}
        self.assertTrue(playbooks.matches_trigger(pb, a))
        for change in ({"severity": "Medium"}, {"technique": "T1059"}, {"rule_name": "other"}):
            self.assertFalse(playbooks.matches_trigger(pb, {**a, **change}))
        self.assertFalse(playbooks.matches_trigger({**pb, "enabled": False}, a))
        self.assertFalse(playbooks.matches_trigger({"enabled": True, "trigger": {"mode": "manual"}}, a))


class Recorder:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send(self, *a, **kw):
        if self.fail:
            raise wh.WebhookError("boom")
        self.sent.append((a, kw))
        return {"status": 200}


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        self.alert, _ = store.receive_alert({"source": "s", "external_id": "1", "title": "Shell from w3wp", "severity": "High", "asset": "WEB-1", "technique": "T1190",
                                             "rule_name": "R", "detail": "beacon to 185.220.101.9"}, self.e)
        self.notify, self.resp = Recorder(), Recorder()
        self.saved = []
        self.prov = soar.Providers(lookup=lambda v: {"result": "seen", "malicious": 30, "total": 80}, siem_run=lambda q, earliest: {"count": 2, "rows": [{"host": "WEB-1"}]},
                                   notify_webhook=self.notify, response=self.resp, findings=[fnd(1)], save_investigation=lambda inv, md: self.saved.append(inv["verdict"]))

    def pb(self, steps, trigger=None, name="pb"):
        return playbooks.save(name, "", trigger, steps, "admin@t", engine=self.e)

    def go(self, pb, dry_run=False, actor="a@t", prov=None):
        return soar.start(pb, store.get_alert(self.alert["id"], self.e), actor, dry_run, prov or self.prov, self.e, NOW)

    CONTAIN = [step("investigate", reputation=True, siem=True), step("request-approval", message="Isolate {asset}?"),
               step("response-action", action="isolate-host", target="{asset}", reason="verdict {verdict}"), step("notify", channel="webhook", text="Isolated {asset}")]

    def test_a_dry_run_contacts_nothing_and_changes_nothing(self):
        r = self.go(self.pb(self.CONTAIN + [step("add-note", text="n"), step("update-alert", status="investigating")]), dry_run=True)
        self.assertEqual(r["status"], "completed")
        self.assertEqual((self.notify.sent, self.resp.sent, self.saved), ([], [], []))
        self.assertEqual(store.get_alert(self.alert["id"], self.e)["status"], "new")
        self.assertEqual(store.get_alert(self.alert["id"], self.e)["notes"], "")
        statuses = [e["status"] for e in r["log"]]
        self.assertEqual(statuses, ["ok", "dry-run", "dry-run", "dry-run", "dry-run", "dry-run"])
        self.assertIn("Would ask your endpoint to isolate-host WEB-1", r["log"][2]["detail"])
        self.assertIn("skipped in a dry run", r["log"][0]["detail"])

    def test_a_real_run_waits_for_a_second_person_then_acts(self):
        r = self.go(self.pb(self.CONTAIN), actor="starter@t")
        self.assertEqual((r["status"], r["next_step"]), ("waiting-approval", 2))
        self.assertEqual(self.resp.sent, [])
        self.assertEqual(self.saved, ["likely-true-positive"])
        with self.assertRaises(PermissionError):
            soar.approve(r["id"], "starter@t", self.prov, self.e, NOW)
        done = soar.approve(r["id"], "second@t", self.prov, self.e, NOW)
        self.assertEqual(done["status"], "completed")
        (call,) = self.resp.sent
        self.assertEqual(call[0][:2], ("isolate-host", "WEB-1"))
        self.assertEqual((call[0][2]["approved_by"], call[0][2]["requested_by"], call[0][2]["reason"]), ("second@t", "starter@t", "verdict likely-true-positive"))
        self.assertEqual(len(self.notify.sent), 1)
        self.assertEqual(self.notify.sent[0][0][0], "Isolated WEB-1")
        with self.assertRaises(ValueError):
            soar.approve(r["id"], "third@t", self.prov, self.e, NOW)  # no longer waiting

    def test_rejecting_or_cancelling_ends_the_run_without_acting(self):
        r = self.go(self.pb(self.CONTAIN))
        rj = soar.reject(r["id"], "second@t", "not convinced", self.e, NOW)
        self.assertEqual(rj["status"], "rejected")
        self.assertIn("not convinced", rj["log"][-1]["detail"])
        self.assertEqual(self.resp.sent, [])
        r2 = self.go(self.pb(self.CONTAIN, name="pb2"))
        self.assertEqual(soar.cancel(r2["id"], "x@t", self.e, NOW)["status"], "cancelled")
        with self.assertRaises(ValueError):
            soar.cancel(r2["id"], "x@t", self.e, NOW)
        with self.assertRaises(KeyError):
            soar.approve(999, "x", self.prov, self.e)

    def test_the_second_person_rule_can_be_the_policy(self):
        r = self.go(self.pb(self.CONTAIN), actor="same@t")
        with patch.object(playbooks, "policy", return_value={**playbooks.policy(), "require_second_person": False}):
            self.assertEqual(soar.approve(r["id"], "same@t", self.prov, self.e, NOW)["status"], "completed")

    def test_a_skipped_approval_cannot_unlock_a_destructive_action(self):
        # The approval is conditional on a false condition, the action on a true one: the runtime check still refuses.
        steps = [step("investigate"), {"type": "request-approval", "params": {"message": "m"}, "when": {"path": "investigation.verdict", "op": "eq", "value": "never"}},
                 {"type": "response-action", "params": {"action": "isolate-host", "target": "{asset}", "reason": ""}, "when": {"path": "alert.severity", "op": "eq", "value": "High"}}]
        r = self.go(self.pb(steps))
        self.assertEqual(r["status"], "failed")
        self.assertIn("needs an approval recorded", r["log"][-1]["detail"])
        self.assertEqual(self.resp.sent, [])

    def test_conditions_skip_steps(self):
        r = self.go(self.pb([step("investigate"), {"type": "notify", "params": {"channel": "webhook", "text": "x"}, "when": {"path": "investigation.verdict", "op": "eq", "value": "likely-false-positive"}},
                              {"type": "add-note", "params": {"text": "verdict {verdict}"}, "when": {"path": "alert.severity", "op": "gte", "value": "High"}}]))
        self.assertEqual([e["status"] for e in r["log"]], ["ok", "skipped", "ok"])
        self.assertEqual(self.notify.sent, [])
        self.assertIn("verdict escalate-l2", store.get_alert(self.alert["id"], self.e)["notes"])

    def test_a_failing_step_stops_the_run_with_a_reason(self):
        r = self.go(self.pb([step("notify", channel="webhook", text="x"), step("add-note", text="never")]), prov=soar.Providers(notify_webhook=Recorder(fail=True)))
        self.assertEqual((r["status"], r["log"][0]["status"]), ("failed", "failed"))
        self.assertEqual(len(r["log"]), 1)
        self.assertEqual(store.get_alert(self.alert["id"], self.e)["notes"], "")

    def test_missing_connections_fail_clearly_rather_than_skip(self):
        for steps, text in (([step("investigate", reputation=True)], "reputation"), ([step("investigate", siem=True)], "Splunk search"),
                            ([step("notify", channel="webhook", text="x")], "notification webhook"), ([step("notify", channel="email", text="x", to=["a@b.co"])], "Email"),
                            ([step("request-approval"), step("response-action", action="block-ip", target="1.2.3.4")], "response webhook")):
            r = self.go(self.pb(steps, name=text), prov=soar.Providers(findings=[]))
            if steps[0]["type"] == "request-approval":
                r = soar.approve(r["id"], "other@t", soar.Providers(findings=[]), self.e, NOW)
            self.assertEqual(r["status"], "failed", text)
            self.assertIn(text, r["log"][-1]["detail"])

    def test_playbooks_set_investigating_and_assign_but_never_close(self):
        self.go(self.pb([step("update-alert", status="investigating", assignee="l1@t")]))
        a = store.get_alert(self.alert["id"], self.e)
        self.assertEqual((a["status"], a["assignee"]), ("investigating", "l1@t"))
        store.update_alert(a["id"], {"status": "closed", "disposition": "benign"}, self.e)
        self.go(self.pb([step("update-alert", status="investigating")], name="again"))
        self.assertEqual(store.get_alert(a["id"], self.e)["status"], "closed")  # a closed alert is left alone

    def test_email_notifications_use_the_provider(self):
        sent = []
        r = self.go(self.pb([step("notify", channel="email", text="{title} on {asset}", to=["oncall@t.co"])]), prov=soar.Providers(send_email=lambda to, subject, body: sent.append((to, subject, body))))
        self.assertEqual(r["status"], "completed")
        self.assertEqual(sent, [(["oncall@t.co"], "Quanta: Shell from w3wp", "Shell from w3wp on WEB-1")])

    def test_auto_runs_match_the_trigger_and_respect_the_hourly_cap(self):
        self.pb([step("investigate"), step("add-note", text="auto")], {"mode": "on-alert", "min_severity": "High"}, name="auto")
        self.pb([step("add-note", text="x")], {"mode": "on-alert", "min_severity": "Critical"}, name="critical only")
        self.pb([step("add-note", text="x")], name="manual")
        runs = soar.auto_run(store.get_alert(self.alert["id"], self.e), lambda: self.prov, self.e, NOW)
        self.assertEqual([r["playbook_name"] for r in runs], ["auto"])
        self.assertEqual(runs[0]["started_by"], "automation")
        with patch.object(playbooks, "policy", return_value={**playbooks.policy(), "auto_runs_per_hour": 1}):
            self.assertEqual(soar.auto_run(store.get_alert(self.alert["id"], self.e), lambda: self.prov, self.e, NOW), [])

    def test_list_and_filter_runs(self):
        self.go(self.pb([step("add-note", text="x")]), dry_run=True)
        r2 = self.go(self.pb(self.CONTAIN, name="c"))
        self.assertEqual(len(soar.list_runs(self.e)), 2)
        self.assertEqual([r["id"] for r in soar.list_runs(self.e, status="waiting-approval")], [r2["id"]])
        self.assertEqual(len(soar.list_runs(self.e, alert_id=self.alert["id"])), 2)
        self.assertEqual(soar.list_runs(self.e, alert_id=999), [])


class SoarApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=[fnd(1)])]
        for x in self.p:
            x.start()
        for email in ("admin@t.local", "admin2@t.local"):
            auth_users.create_user(email, PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")
        self.key = self.client.post("/api/api-keys", json={"name": "siem", "scopes": ["soc:write"]}).json()["key"]
        self.client.cookies.clear()

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def push(self, n=1, severity="High", ext="x"):
        return self.client.post("/api/ingest/alerts", json={"alerts": [{"external_id": f"{ext}{i}", "title": "Shell", "severity": severity, "asset": "WEB-1", "technique": "T1190"} for i in range(n)]},
                                headers={"Authorization": f"Bearer {self.key}"})

    def test_admin_only(self):
        for method, path in (("get", "/api/soar/playbooks"), ("get", "/api/soar/runs"), ("post", "/api/soar/runs/1/approve")):
            self.assertEqual(getattr(self.client, method)(path).status_code, 401, path)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/soar/playbooks").status_code, 403)

    def test_playbook_crud_and_validation(self):
        self.login("admin@t.local")
        cat = self.client.get("/api/soar/playbooks").json()
        self.assertEqual(len(cat["templates"]), 5)
        self.assertTrue(cat["actions"]["isolate-host"]["destructive"] and not cat["actions"]["create-ticket"]["destructive"])
        t = cat["templates"][0]
        made = self.client.post("/api/soar/playbooks", json={"name": t["name"], "description": t["description"], "trigger": t["trigger"], "steps": t["steps"]})
        self.assertEqual(made.status_code, 200, made.text)
        pid = made.json()["id"]
        self.assertEqual(self.client.post("/api/soar/playbooks", json={"name": t["name"], "steps": t["steps"]}).status_code, 400)  # duplicate name
        self.assertEqual(self.client.post("/api/soar/playbooks", json={"name": "bad", "steps": [{"type": "response-action", "params": {"action": "isolate-host", "target": "x"}}]}).status_code, 400)
        upd = self.client.put(f"/api/soar/playbooks/{pid}", json={"name": "Renamed", "steps": t["steps"], "enabled": False})
        self.assertEqual((upd.status_code, upd.json()["name"], upd.json()["enabled"]), (200, "Renamed", False))
        self.assertEqual(self.client.put("/api/soar/playbooks/999", json={"name": "x", "steps": t["steps"]}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/soar/playbooks/{pid}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/soar/playbooks/{pid}").status_code, 404)

    def test_runs_are_dry_by_default_and_real_ones_need_confirmation_and_a_second_approver(self):
        self.login("admin@t.local")
        self.push()
        aid = self.client.get("/api/soc/alerts").json()["alerts"][0]["id"]
        contain = next(t for t in self.client.get("/api/soar/playbooks").json()["templates"] if t["id"] == "contain-compromised-host")
        pid = self.client.post("/api/soar/playbooks", json={"name": contain["name"], "trigger": contain["trigger"], "steps": contain["steps"]}).json()["id"]
        dry = self.client.post(f"/api/soar/playbooks/{pid}/run", json={"alert_id": aid})
        self.assertEqual((dry.status_code, dry.json()["dry_run"], dry.json()["status"]), (200, True, "completed"), dry.text)
        pre = self.client.post(f"/api/soar/playbooks/{pid}/run", json={"alert_id": aid, "dry_run": False})
        self.assertTrue(pre.json()["preview_only"])
        self.assertEqual(self.client.post(f"/api/soar/playbooks/{pid}/run", json={"alert_id": 999}).status_code, 404)
        self.assertEqual(self.client.post("/api/soar/playbooks/999/run", json={"alert_id": aid}).status_code, 404)
        sent = Recorder()
        fake_prov = soar.Providers(lookup=lambda v: {"result": "seen", "malicious": 40, "total": 80}, siem_run=lambda q, e: {"count": 1, "rows": []}, response=sent, notify_webhook=Recorder(),
                                   findings=[fnd(1)])
        with patch.object(dashboard_app_module, "_soar_providers", return_value=fake_prov):
            real = self.client.post(f"/api/soar/playbooks/{pid}/run", json={"alert_id": aid, "dry_run": False, "confirm": True})
            self.assertEqual((real.status_code, real.json()["status"]), (200, "waiting-approval"), real.text)
            rid = real.json()["id"]
            self.assertEqual(self.client.post(f"/api/soar/runs/{rid}/approve").status_code, 403)  # same person
            self.login("admin2@t.local")
            ok = self.client.post(f"/api/soar/runs/{rid}/approve")
            self.assertEqual((ok.status_code, ok.json()["status"]), (200, "completed"), ok.text)
        self.assertEqual(sent.sent[0][0][:2], ("isolate-host", "WEB-1"))
        self.assertEqual(len(self.client.get(f"/api/soar/runs?alert_id={aid}").json()["runs"]), 2)
        self.assertEqual(self.client.get(f"/api/soar/runs/{rid}").json()["context"]["approvals"][0]["by"], "admin2@t.local")
        self.assertEqual(self.client.get("/api/soar/runs/999").status_code, 404)
        self.assertEqual(self.client.post(f"/api/soar/runs/{rid}/reject", json={}).status_code, 400)  # already finished
        self.assertEqual(self.client.post("/api/soar/runs/999/cancel").status_code, 404)

    def test_on_alert_playbooks_run_by_themselves_for_new_alerts_only(self):
        self.login("admin@t.local")
        t = next(t for t in self.client.get("/api/soar/playbooks").json()["templates"] if t["id"] == "triage-and-notify")
        steps = [s for s in t["steps"] if s["type"] != "notify"]
        self.assertEqual(self.client.post("/api/soar/playbooks", json={"name": "auto triage", "trigger": {"mode": "on-alert", "min_severity": "High"}, "steps": steps}).status_code, 200)
        self.client.cookies.clear()
        self.push(2, ext="a")
        self.push(2, ext="a")  # the same alerts again: no new runs
        self.push(1, severity="Low", ext="low")  # below the trigger
        self.login("admin@t.local")
        runs = self.client.get("/api/soar/runs").json()["runs"]
        self.assertEqual(len(runs), 2)
        self.assertTrue(all(r["started_by"] == "automation" and r["status"] == "completed" for r in runs))
        alerts = {a["external_id"]: a for a in self.client.get("/api/soc/alerts").json()["alerts"]}
        self.assertEqual(alerts["a0"]["status"], "investigating")
        self.assertEqual(alerts["low0"]["status"], "new")


class RegistryTests(unittest.TestCase):
    def test_webhook_connections_validate_and_are_tools(self):
        with patch("remediation.connectors.url_safety.assert_safe_target"):
            cfg, sec = registry.split_values("response-webhook", {"url": "https://soar.example/h", "signing_secret": "s", "allowed_actions": "create-ticket"})
            self.assertEqual((cfg["allowed_actions"], sec["signing_secret"]), ("create-ticket", "s"))
            built = registry.SPECS["response-webhook"]["build"]({**cfg, **sec})
            self.assertEqual(built.allowed, {"create-ticket"})
            with self.assertRaises(ValueError):
                registry.split_values("response-webhook", {"url": "https://soar.example/h"})
            self.assertEqual(registry.split_values("notify-webhook", {"url": "https://hooks.example/x"})[1], {"url": "https://hooks.example/x"})
        kinds = {t["type"]: t["kind"] for t in registry.public_catalog()}
        self.assertEqual((kinds["response-webhook"], kinds["notify-webhook"]), ("tool", "tool"))


if __name__ == "__main__":
    unittest.main()
