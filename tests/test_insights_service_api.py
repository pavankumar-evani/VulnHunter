"""Insights: persistence and idempotent refresh, snooze/dismiss/acted, role and team filtering, learning, settings, the migration, licensing, and the HTTP API (auth, permissions, structured ask)."""
import datetime
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, inspect  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "dashboard"))
import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.insights import detectors, service  # noqa: E402
from remediation.licensing import license as lic  # noqa: E402
from remediation.utils import db as db_module, migrations  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, 12, 0, tzinfo=datetime.timezone.utc)
TODAY = NOW.date()


def day(n):
    return (TODAY - datetime.timedelta(days=n)).isoformat()


def findings():
    out = [{"id": f"U{i}", "title": "x", "severity": "Critical", "asset": {"name": f"orphan-{i}", "type": "unix-server"}, "first_seen": day(50), "last_seen": day(0), "kev": {"listed": False}} for i in range(2)]
    out.append({"id": "T1", "title": "team", "severity": "Critical", "asset": {"name": "blue-1", "type": "unix-server"}, "first_seen": day(50), "last_seen": day(0), "kev": {"listed": False}})
    return out


ASSETS = [{"name": "orphan-0"}, {"name": "orphan-1"}, {"name": "blue-1", "team": "Blue"}]


def snapshot(**over):
    base = {"now": NOW, "findings": findings(), "assets": ASSETS, "exceptions": [], "approvals": [], "activity": [], "alerts": [], "hunts": [], "cases": [],
            "connections": [{"name": "tenable", "enabled": True, "schedule_minutes": 60, "last_run_at": day(9)}], "api_keys": [{"name": "ci", "prefix": "p", "expires_at": (TODAY + datetime.timedelta(days=3)).isoformat(), "revoked_at": None}], "ai_events": [], "grc_evidence": [],
            "grc_mappings": {}, "controls": [], "license": {}, "baseline": None}
    base.update(over)
    return base


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.cfg_path = Path(self.tmp.name) / "insights.yaml"
        shutil.copy(service.CONFIG_PATH, self.cfg_path)
        self.admin = {"email": "a@x", "role": "admin", "team": None}
        self.user = {"email": "u@x", "role": "user", "team": None}
        self.red = {"email": "r@x", "role": "user", "team": "Red"}
        self.blue = {"email": "b@x", "role": "user", "team": "Blue"}

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def refresh(self, **over):
        return service.refresh(self.engine, snapshot=snapshot(**over), now=NOW)

    def test_refresh_is_idempotent_and_ids_are_stable(self):
        first = self.refresh()
        self.assertGreater(first["produced"], 0)
        self.assertEqual(first["new"], first["produced"])
        ids = {i["id"] for i in service.list_insights(self.admin, self.engine, now=NOW)}
        second = self.refresh()
        self.assertEqual(second["new"], 0)
        self.assertEqual({i["id"] for i in service.list_insights(self.admin, self.engine, now=NOW)}, ids)

    def test_states_survive_a_refresh_and_hide_the_insight(self):
        self.refresh()
        top = service.list_insights(self.admin, self.engine, now=NOW)[0]
        service.set_state(top["id"], "snoozed", self.admin, snooze_days=2, engine=self.engine, now=NOW)
        self.refresh()
        self.assertNotIn(top["id"], [i["id"] for i in service.list_insights(self.admin, self.engine, now=NOW)])
        later = NOW + datetime.timedelta(days=3)
        self.assertEqual(service.get_insight(top["id"], self.admin, self.engine, now=later)["state"], "open")      # snooze lapsed
        self.assertIn(top["id"], [i["id"] for i in service.list_insights(self.admin, self.engine, now=NOW, include_closed=True)])

    def test_dismiss_needs_a_reason_and_acted_is_recorded(self):
        self.refresh()
        ins = service.list_insights(self.admin, self.engine, now=NOW)
        with self.assertRaises(ValueError):
            service.set_state(ins[0]["id"], "dismissed", self.admin, reason="  ", engine=self.engine, now=NOW)
        d = service.set_state(ins[0]["id"], "dismissed", self.admin, reason="known", engine=self.engine, now=NOW)
        self.assertEqual((d["state"], d["state_reason"], d["state_by"]), ("dismissed", "known", "a@x"))
        a = service.set_state(ins[1]["id"], "acted", self.admin, engine=self.engine, now=NOW)
        self.assertEqual(a["state"], "acted")
        with self.assertRaises(KeyError):
            service.set_state("ins_nope", "acted", self.admin, engine=self.engine, now=NOW)
        with self.assertRaises(ValueError):
            service.set_state(ins[2]["id"], "snoozed", self.admin, snooze_days=500, engine=self.engine, now=NOW)

    def test_an_insight_that_stops_being_produced_disappears_after_the_window(self):
        self.refresh()
        self.refresh(api_keys=[])                                                      # the key detector no longer fires
        keyed = [i for i in service.list_insights(self.admin, self.engine, now=NOW + datetime.timedelta(days=5), include_closed=True)]
        self.assertEqual(keyed, [])                                                    # nothing was seen for 5 days > resolve_after_days

    def test_role_and_team_filtering(self):
        self.refresh()
        self.assertTrue(any(i["admin_only"] for i in service.list_insights(self.admin, self.engine, now=NOW)))         # the API-key expiry
        self.assertFalse(any(i["admin_only"] for i in service.list_insights(self.user, self.engine, now=NOW)))
        for i in service.list_insights(self.red, self.engine, now=NOW):
            self.assertTrue(not i["teams"] or "Red" in i["teams"])
        # An insight limited to team Blue: Blue and admins see it, Red does not.
        from remediation.insights import model
        blue_only = model.make("t", "k", "gap", "infra", "blue thing", "w", "y", teams=["Blue"], impact=0.9, confidence=0.9, urgency=0.9, roles={"analyst": 1})
        service_snapshot = snapshot()
        service.refresh(self.engine, snapshot=service_snapshot, now=NOW)
        import json
        from sqlalchemy import insert
        with self.engine.begin() as conn:
            conn.execute(insert(db_module.insights).values(id=blue_only["id"], detector="t", kind="gap", module="infra", state="open", payload=json.dumps(blue_only),
                                                           first_seen="2026-10-06T00:00:00Z", last_seen="2026-10-06T11:00:00Z"))
        titles = lambda u: [i["title"] for i in service.list_insights(u, self.engine, now=NOW)]  # noqa: E731
        self.assertIn("blue thing", titles(self.blue))
        self.assertIn("blue thing", titles(self.admin))
        self.assertNotIn("blue thing", titles(self.red))
        self.assertIsNone(service.get_insight(blue_only["id"], self.red, self.engine, now=NOW))

    def test_role_lens_changes_ranking_and_cap_applies(self):
        self.refresh()
        a = service.list_insights(self.admin, self.engine, role="exec", now=NOW)
        self.assertTrue(all(i["breakdown"]["role"] == "exec" for i in a))
        self.assertLessEqual(len(service.list_insights(self.admin, self.engine, limit=1, now=NOW)), 1)
        cfg = service.load_config()
        cfg["max_per_role"] = 1
        self.assertEqual(len(service.list_insights(self.admin, self.engine, now=NOW, config=cfg)), 1)

    def test_learning_from_actions_is_bounded_and_visible(self):
        self.refresh()
        ids = [i["id"] for i in service.list_insights(self.admin, self.engine, now=NOW)]
        det = service.get_insight(ids[0], self.admin, self.engine, now=NOW)["detector"]
        before = service.get_insight(ids[0], self.admin, self.engine, now=NOW)["breakdown"]["learned_weight"]
        self.assertEqual(before, 1.0)
        # Many dismissals of one detector push its weight down, but never below the floor.
        from sqlalchemy import insert
        with self.engine.begin() as conn:
            for n in range(40):
                conn.execute(insert(db_module.insights).values(id=f"ins_x{n}", detector=det, kind="gap", module="infra", state="dismissed", payload="{}", first_seen="x", last_seen="x"))
        after = service.get_insight(ids[0], self.admin, self.engine, now=NOW)["breakdown"]["learned_weight"]
        self.assertEqual(after, 0.6)
        view = service.settings_view(self.engine)
        row = [d for d in view["detectors"] if d["name"] == det][0]
        self.assertEqual((row["dismissed"], row["weight"]), (40, 0.6))
        # Snoozes are not counted as a verdict.
        self.assertEqual(service.learning_counts(self.engine)[det]["acted"], 0)

    def test_settings_validation_and_persistence(self):
        cfg = service.update_config({"max_per_role": 4, "detectors": {"finding_burst": {"z": 5}}}, path=self.cfg_path)
        self.assertEqual((cfg["max_per_role"], cfg["detectors"]["finding_burst"]["z"]), (4, 5))
        self.assertEqual(yaml.safe_load(self.cfg_path.read_text())["max_per_role"], 4)
        self.assertEqual(yaml.safe_load(self.cfg_path.read_text())["detectors"]["finding_burst"]["min_count"], 5)   # untouched keys remain
        for bad in ({"nope": 1}, {"max_per_role": "ten"}, {"max_per_role": 0}, {"max_per_role": 500}, {"detectors": {"made_up": {}}}, {"detectors": {"sla_trend": {"enabled": "yes"}}},
                    {"detectors": {"sla_trend": {"extra": 1}}}, {"learning": {"min_weight": 2}}, {"max_per_role": -1}, {"drift": {"action_prefixes": "x"}}):
            with self.subTest(bad), self.assertRaises(service.SettingsError):
                service.update_config(bad, path=self.cfg_path)
        self.assertEqual(yaml.safe_load(self.cfg_path.read_text())["max_per_role"], 4)       # a rejected change wrote nothing

    def test_disabled_detector_in_config_is_skipped(self):
        cfg = service.load_config()
        cfg["detectors"]["unowned_critical"]["enabled"] = False
        service.refresh(self.engine, snapshot=snapshot(), now=NOW, config=cfg)
        self.assertFalse([i for i in service.list_insights(self.admin, self.engine, now=NOW) if i["detector"] == "unowned_critical"])

    def test_gaps_are_reported_and_baselines_enable_change_detection(self):
        r = self.refresh()
        self.assertTrue(any("exposure_change" in g for g in r["gaps"]))                # first refresh has no earlier snapshot
        self.assertEqual(service.last_refresh(self.engine)["produced"], r["produced"])
        changed = [{"name": "orphan-0", "facing": "internet"}, {"name": "orphan-1"}, {"name": "blue-1", "team": "Blue"}]
        r2 = self.refresh(assets=[{**a, "facing": "internet"} if a["name"] == "orphan-0" else a for a in changed])
        titles = [i["title"] for i in service.list_insights(self.admin, self.engine, now=NOW)]
        self.assertFalse([g for g in r2["gaps"] if "exposure_change" in g])
        self.assertTrue(any("internet-facing" in t for t in titles))

    def test_real_loader_on_an_empty_database_yields_gaps_not_errors(self):
        from remediation.insights import loader
        snap = loader.load(self.engine, findings=None, assets=None, now=NOW)
        self.assertIsNone(snap["findings"])                                            # no data handed in is a gap, never an empty list
        self.assertEqual((snap["alerts"], snap["api_keys"], snap["connections"]), ([], [], []))
        r = service.refresh(self.engine, findings=[], assets=[], now=NOW)
        self.assertEqual(r["errors"], [])
        self.assertEqual(r["produced"], 0)

    def test_tick_is_hourly_and_can_be_switched_off(self):
        calls = []
        fn = lambda: (calls.append(1), [])[1]  # noqa: E731
        with patch.dict("os.environ", {"QUANTA_INSIGHTS": "false"}):
            self.assertIsNone(service.run_tick(fn, fn, self.engine))
        self.assertEqual(calls, [])
        with patch("remediation.insights.loader.load", return_value=snapshot()):
            self.assertIsNotNone(service.run_tick(fn, fn, self.engine))
            self.assertIsNone(service.run_tick(fn, fn, self.engine))                    # within the hour: nothing
        with patch.dict("os.environ", {"QUANTA_INSIGHTS": "true"}):
            self.assertTrue(service.enabled())


class Plumbing(unittest.TestCase):
    def test_migration_12_creates_the_tables_and_is_idempotent(self):
        self.assertIn((12, "insights_tables"), [(v, n) for v, n, _ in migrations.MIGRATIONS])
        self.assertEqual(len({v for v, _, _ in migrations.MIGRATIONS}), len(migrations.MIGRATIONS))     # numbers stay unique
        with tempfile.TemporaryDirectory() as tmp:
            eng = create_engine(f"sqlite:///{Path(tmp) / 'm.db'}")
            migrations.apply(eng)
            self.assertTrue({"insights", "insight_baselines"} <= set(inspect(eng).get_table_names()))
            self.assertEqual(migrations.apply(eng), [])
            migrations._m012_insights_tables(eng)                                       # safe to run again
            eng.dispose()

    def test_licensing_lists_the_new_prefixes_as_core(self):
        cfg = lic.config()
        for prefix in ("/api/insights", "/api/ask"):
            self.assertIn(prefix, cfg["core"])
        self.assertEqual(lic.module_for_path("/api/insights/ins_1/dismiss")[0], "core")
        self.assertEqual(lic.module_for_path("/api/ask/structured")[0], "core")

    def test_every_detector_declares_needs_and_a_config_entry(self):
        cfg = service.load_config()
        for d in detectors.DETECTORS:
            self.assertTrue(d.needs, d.name)
            self.assertIn(d.name, cfg["detectors"])
        self.assertEqual({d.name for d in detectors.DETECTORS}, set(cfg["detectors"]))


class ApiTests(unittest.TestCase):
    PW = "test-password-123"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.cfg_path = Path(self.tmp.name) / "insights.yaml"
        shutil.copy(service.CONFIG_PATH, self.cfg_path)
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10 ** 9, 60)),
                  patch.object(service, "CONFIG_PATH", self.cfg_path),
                  patch("remediation.insights.loader.load", side_effect=lambda *a, **k: snapshot()),
                  patch.object(dashboard_app_module, "_insights_inputs", return_value=(findings(), [dict(a) for a in ASSETS])),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", side_effect=lambda: [dict(f) for f in findings()]),
                  patch.object(dashboard_app_module.dashboard_data, "_load_scored_assets", return_value=(None, [dict(a) for a in ASSETS]))]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", self.PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", self.PW, "User", role="user", engine=self.engine)
        auth_users.create_user("blue@t.local", self.PW, "Blue", role="user", team="Blue", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        r = self.client.post("/api/auth/login", json={"email": email, "password": self.PW})
        self.assertEqual(r.status_code, 200, r.text)

    def test_every_route_needs_a_login(self):
        for method, path in (("get", "/api/insights"), ("get", "/api/insights/ins_x"), ("post", "/api/insights/ins_x/snooze"), ("post", "/api/insights/ins_x/dismiss"),
                             ("post", "/api/insights/ins_x/acted"), ("post", "/api/insights/refresh"), ("get", "/api/insights/settings"), ("put", "/api/insights/settings"),
                             ("post", "/api/ask/structured")):
            with self.subTest(path):
                r = getattr(self.client, method)(path, json={"query": "x", "settings": {}, "reason": "r"}) if method != "get" else self.client.get(path)
                self.assertEqual(r.status_code, 401)

    def test_admin_only_routes_reject_a_plain_user(self):
        self.login("user@t.local")
        self.assertEqual(self.client.post("/api/insights/refresh").status_code, 403)
        self.assertEqual(self.client.get("/api/insights/settings").status_code, 403)
        self.assertEqual(self.client.put("/api/insights/settings", json={"settings": {"max_per_role": 3}}).status_code, 403)

    def test_refresh_list_get_and_state_changes(self):
        self.login("admin@t.local")
        r = self.client.post("/api/insights/refresh")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(r.json()["produced"], 0)
        lst = self.client.get("/api/insights").json()
        self.assertTrue(lst["enabled"])
        self.assertEqual(lst["role"], "admin")
        first = lst["insights"][0]
        for k in ("id", "kind", "module", "title", "what", "why", "evidence", "impact", "confidence", "action", "score", "breakdown", "state"):
            self.assertIn(k, first)
        self.assertEqual(self.client.get(f"/api/insights/{first['id']}").json()["id"], first["id"])
        self.assertEqual(self.client.get("/api/insights/ins_missing").status_code, 404)
        self.assertEqual(self.client.post(f"/api/insights/{first['id']}/dismiss", json={}).status_code, 400)            # reason required
        self.assertEqual(self.client.post(f"/api/insights/{first['id']}/dismiss", json={"reason": "not relevant"}).json()["state"], "dismissed")
        self.assertNotIn(first["id"], [i["id"] for i in self.client.get("/api/insights").json()["insights"]])
        second = self.client.get("/api/insights").json()["insights"][0]
        self.assertEqual(self.client.post(f"/api/insights/{second['id']}/snooze", json={"days": 3}).json()["state"], "snoozed")
        third = self.client.get("/api/insights").json()["insights"][0]
        self.assertEqual(self.client.post(f"/api/insights/{third['id']}/acted", json={}).json()["state"], "acted")
        self.assertEqual(self.client.post("/api/insights/ins_missing/acted", json={}).status_code, 404)
        self.assertEqual(self.client.get("/api/insights?limit=1&role=exec").json()["role"], "exec")
        # Every state change is written to the activity log.
        from remediation.audit import activity_log
        actions = {e["action"] for e in activity_log.list_activity(engine=self.engine)}
        self.assertTrue({"insights.dismissed", "insights.snoozed", "insights.acted"} <= actions)

    def test_user_sees_no_admin_only_insights(self):
        self.login("admin@t.local")
        self.client.post("/api/insights/refresh")
        admin_ids = {i["id"] for i in self.client.get("/api/insights?limit=50").json()["insights"] if i["admin_only"]}
        self.assertTrue(admin_ids)
        self.login("user@t.local")
        self.assertFalse(admin_ids & {i["id"] for i in self.client.get("/api/insights?limit=50").json()["insights"]})
        self.assertEqual(self.client.get(f"/api/insights/{next(iter(admin_ids))}").status_code, 404)

    def test_settings_get_put_and_validation(self):
        self.login("admin@t.local")
        view = self.client.get("/api/insights/settings").json()
        self.assertEqual(len(view["detectors"]), len(detectors.DETECTORS))
        self.assertIn("weight", view["detectors"][0])
        ok = self.client.put("/api/insights/settings", json={"settings": {"max_per_role": 3}})
        self.assertEqual(ok.json()["config"]["max_per_role"], 3)
        self.assertEqual(self.client.put("/api/insights/settings", json={"settings": {"bogus": 1}}).status_code, 400)
        self.assertEqual(yaml.safe_load(self.cfg_path.read_text())["max_per_role"], 3)

    def test_switched_off_with_the_environment_flag(self):
        self.login("admin@t.local")
        with patch.dict("os.environ", {"QUANTA_INSIGHTS": "false"}):
            self.assertEqual(self.client.get("/api/insights").json(), {"enabled": False, "insights": [], "last_refresh": None})
            self.assertEqual(self.client.post("/api/insights/refresh").status_code, 409)

    def test_structured_ask_runs_with_the_askers_permissions(self):
        self.login("user@t.local")
        r = self.client.post("/api/ask/structured", json={"query": "how many critical findings"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["query"]["intent"], "findings.list")
        self.assertEqual(r.json()["result"]["count"], 3)
        self.assertEqual(self.client.post("/api/ask/structured", json={"query": "hunts for T1059"}).status_code, 403)
        self.assertEqual(self.client.post("/api/ask/structured", json={"query": "my cases"}).status_code, 403)
        nope = self.client.post("/api/ask/structured", json={"query": "tell me a joke"}).json()
        self.assertFalse(nope["parsed"])
        self.assertTrue(nope["suggestions"])
        hostile = self.client.post("/api/ask/structured", json={"query": "'; DROP TABLE users; --"}).json()
        self.assertFalse(hostile["parsed"])
        self.login("admin@t.local")
        self.assertEqual(self.client.post("/api/ask/structured", json={"query": "hunts for T1059"}).status_code, 200)

    def test_structured_ask_is_team_scoped(self):
        self.login("blue@t.local")
        r = self.client.post("/api/ask/structured", json={"query": "how many critical findings"})
        self.assertEqual(r.json()["result"]["count"], 1)                                # only blue-1's finding
        owner = self.client.post("/api/ask/structured", json={"query": "who owns host orphan-0"}).json()
        self.assertIn("No asset named", owner["result"]["summary"])                     # another team's asset is not visible


if __name__ == "__main__":
    unittest.main()
