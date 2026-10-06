"""
Tests for the simulation layer: one fictional estate, a replay transport, and per-connector renderers that push recorded
vendor-format responses through each connector's REAL code (parsing, classify, merge, store).

No test touches the network. KEV/EPSS enrichment is patched or switched off. Fakes are hand-rolled.
"""
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

import requests  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.connections import crypto, registry, store, sync  # noqa: E402
from remediation.connectors.openvas_connector import OpenVasConnector  # noqa: E402
from remediation.connectors.qualys_connector import QualysConnector  # noqa: E402
from remediation.connectors.tenable_connector import TenableConnector  # noqa: E402
from remediation.ingest import merge  # noqa: E402
from remediation.simulation import estate as estate_mod  # noqa: E402
from remediation.simulation import renderers, service  # noqa: E402
from remediation.simulation.replay import ReplaySession, UnmatchedRequestError  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
SCANNERS = ("tenable", "qualys", "openvas")
REQUIRED = ("id", "source", "asset", "title", "cve", "cvss", "severity", "first_seen", "last_seen", "source_mode")


def clean_env(**extra):
    """dev environment, simulation allowed by default, no inherited flags."""
    env = {"QUANTA_ENV": "dev", "QUANTA_ALLOW_SIMULATION": "", "QUANTA_PRODUCTION": "", "QUANTA_ENCRYPTION_KEY": ""}
    env.update(extra)
    return patch.dict(os.environ, env)


class EstateTests(unittest.TestCase):
    def test_same_arguments_give_the_same_estate(self):
        self.assertEqual(estate_mod.build(1, "small").to_dict(), estate_mod.build(1, "small").to_dict())
        self.assertNotEqual(estate_mod.build(1, "small").to_dict(), estate_mod.build(2, "small").to_dict())

    def test_size_and_validation(self):
        self.assertGreater(len(estate_mod.build(1, "medium").hosts), len(estate_mod.build(1, "small").hosts))
        with self.assertRaises(ValueError):
            estate_mod.build(1, "huge")

    def test_dates_come_from_the_reference_date_not_the_clock(self):
        e = estate_mod.build()
        for d in e.detections:
            self.assertLessEqual(d["first_seen"], d["last_seen"])
            self.assertLessEqual(d["last_seen"], e.reference_date.isoformat())

    def test_hosts_are_fictional_and_vulnerabilities_are_real_cves(self):
        e = estate_mod.build()
        for h in e.hosts:
            self.assertTrue(h["fqdn"].endswith(".corp.test"))
            self.assertTrue(h["ip"].startswith("10."))
        sample = (REPO_ROOT / "remediation" / "sample-data" / "tenable_export.csv").read_text(encoding="utf-8")
        cves = {v["cve"] for v in e.vulnerabilities}
        self.assertTrue({"CVE-2021-34527", "CVE-2021-44228", "CVE-2024-3400"} <= cves)
        self.assertTrue(all(c in sample for c in ("CVE-2021-34527", "CVE-2021-44228", "CVE-2024-3400")))

    def test_the_same_hosts_feed_every_scanner(self):
        e = estate_mod.build()
        names = [set(e.host_names(s)) for s in SCANNERS]
        common = names[0] & names[1] & names[2]
        self.assertGreaterEqual(len(common), 5)
        self.assertEqual(names[0], set(e.host_names()))  # Tenable sees everything; the others a subset of the SAME hosts
        self.assertTrue(names[1] <= names[0] and names[2] <= names[0])


class ReplaySessionTests(unittest.TestCase):
    def make(self):
        return ReplaySession([
            ("GET", r"/ping$", lambda req: (200, None, {"ok": True, "q": req.params})),
            ("GET", r"/page$", lambda req: (200, None, {"items": list(range(int(req.params.get("offset", 0)), min(int(req.params.get("offset", 0)) + 2, 5))),
                                                       "next": int(req.params.get("offset", 0)) + 2 if int(req.params.get("offset", 0)) + 2 < 5 else None})),
            ("POST", r"/echo$", lambda req: (201, {"X-Seen": "1"}, req.json)),
            ("GET", r"/text$", lambda req: (200, None, "hello")),
            ("GET", r"/missing$", lambda req: (404, None, "nope")),
            ("GET", r"/item/(?P<n>\d+)$", lambda req: (200, None, {"n": req.match.group("n")})),
        ])

    def test_unmatched_url_raises_and_names_the_url(self):
        s = self.make()
        with self.assertRaises(UnmatchedRequestError) as cm:
            s.get("https://x.invalid/unknown?a=1")
        self.assertIn("https://x.invalid/unknown?a=1", str(cm.exception))
        self.assertEqual(s.served, [])

    def test_a_method_mismatch_is_unmatched_too(self):
        with self.assertRaises(UnmatchedRequestError):
            self.make().post("https://x.invalid/ping", json={})

    def test_returns_a_real_requests_response(self):
        s = self.make()
        r = s.get("https://x.invalid/ping", params={"a": "1"}, timeout=5)
        self.assertIsInstance(r, requests.Response)
        self.assertEqual((r.status_code, r.json(), r.headers["content-type"]), (200, {"ok": True, "q": {"a": "1"}}, "application/json"))
        r.raise_for_status()
        t = s.get("https://x.invalid/text")
        self.assertEqual((t.text, t.content, b"".join(t.iter_content(2))), ("hello", b"hello", b"hello"))
        e = s.post("https://x.invalid/echo", json={"k": "v"})
        self.assertEqual((e.status_code, e.json(), e.headers["x-seen"]), (201, {"k": "v"}, "1"))
        with self.assertRaises(requests.HTTPError):
            s.get("https://x.invalid/missing").raise_for_status()
        self.assertEqual(s.get("https://x.invalid/item/42").json(), {"n": "42"})

    def test_served_log_and_session_surface(self):
        with self.make() as s:
            s.headers.update({"X-Test": "1"})
            s.auth = ("u", "p")
            s.get("https://x.invalid/ping", params={"z": "9"})
            s.close()
        self.assertTrue(s.closed)
        self.assertEqual([(r["method"], r["params"], r["status"]) for r in s.served], [("GET", {"z": "9"}, 200)])
        self.assertNotIn("X-Test", json.dumps(s.served))  # request headers (where credentials travel) are never logged
        self.assertNotIn('"p"', json.dumps(s.served))

    def test_offset_paging_runs_to_the_end(self):
        s = self.make()
        offset, got = 0, []
        while offset is not None:
            body = s.get("https://x.invalid/page", params={"offset": offset}).json()
            got += body["items"]
            offset = body["next"]
        self.assertEqual(got, [0, 1, 2, 3, 4])
        self.assertEqual(len(s.served), 3)

    def test_qualys_id_min_paging_is_followed_by_the_real_connector(self):
        e = estate_mod.build("1", "medium")
        s = renderers.render_qualys(e)
        hosts = QualysConnector("u", "p", platform_url="https://simulation.invalid", session=s).fetch_all_host_detections()
        self.assertEqual(len(hosts), len(e.hosts_for("qualys")))
        self.assertGreater(len(s.served), 2)  # more than one page really was requested

    def test_qualys_rejects_a_missing_x_requested_with_header(self):
        s = renderers.render_qualys(estate_mod.build())
        r = s.get("https://simulation.invalid/api/2.0/fo/asset/host/vm/detection/", params={"action": "list"})
        self.assertEqual(r.status_code, 400)


class SimulationRegistryTests(unittest.TestCase):
    def setUp(self):
        self.env = clean_env()
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_every_pull_type_has_a_public_mode_field_and_push_types_do_not(self):
        for t, spec in registry.SPECS.items():
            names = [f["name"] for f in spec["fields"]]
            self.assertEqual("mode" in names, spec.get("kind", "pull") == "pull", t)
            if "mode" in names:
                f = next(f for f in spec["fields"] if f["name"] == "mode")
                self.assertFalse(f["secret"])

    def test_a_simulation_connection_needs_no_credentials_url_or_ssrf_check(self):
        with patch.object(registry.url_safety, "assert_safe_target", side_effect=AssertionError("must not be called")):
            for t in SCANNERS:
                config, secrets = registry.split_values(t, {"mode": "simulation"})
                self.assertEqual((config, secrets), ({"mode": "simulation"}, {}))
            # a URL given alongside is simply not kept
            config, _ = registry.split_values("qualys", {"mode": "simulation", "platform_url": "http://169.254.169.254"})
            self.assertEqual(config, {"mode": "simulation"})

    def test_live_mode_still_requires_everything(self):
        with self.assertRaises(ValueError):
            registry.split_values("tenable", {"mode": "live"})
        with self.assertRaises(ValueError):
            registry.split_values("tenable", {"mode": "bogus", "access_key": "a", "secret_key": "b"})
        config, secrets = registry.split_values("tenable", {"access_key": "a", "secret_key": "b"})
        self.assertEqual((config, sorted(secrets)), ({}, ["access_key", "secret_key"]))  # mode live is not stored

    def test_credentials_given_to_a_simulation_connection_are_dropped_not_stored(self):
        engine = create_engine("sqlite:///:memory:")
        c = store.create("Sim", "tenable", {"mode": "simulation", "access_key": "TOP-SECRET", "secret_key": "TOP-SECRET-2"}, "a", engine=engine)
        self.assertEqual((c["mode"], c["secrets_set"], c["config"]), ("simulation", [], {"mode": "simulation"}))
        with engine.connect() as conn:
            raw = json.dumps(dict(conn.execute(db_module.connections.select()).mappings().first()), default=str)
        self.assertNotIn("TOP-SECRET", raw)
        engine.dispose()


class ScannerSyncTests(unittest.TestCase):
    """A full sync.run of a simulation connection for each scanner, through the connector's real parsing."""

    def setUp(self):
        self.env = clean_env()
        self.env.start()
        self.engine = create_engine("sqlite:///:memory:")
        self.fpath = Path(tempfile.mkdtemp()) / "nf.json"

    def tearDown(self):
        self.env.stop()
        self.engine.dispose()

    def run_sim(self, conn_type, enrich=False):
        c = self.sim_connection(conn_type)
        return c, sync.run(c["id"], "admin@t.local", self.engine, self.fpath, enrich=enrich)

    def sim_connection(self, conn_type):
        name = service.connection_name(conn_type)
        existing = [c for c in store.list_connections(self.engine) if c["name"] == name]
        return existing[0] if existing else store.create(name, conn_type, {"mode": "simulation"}, "admin@t.local", engine=self.engine)

    def test_each_scanner_produces_schema_valid_simulated_findings(self):
        e = estate_mod.build()
        for t in SCANNERS:
            with self.subTest(t):
                _, r = self.run_sim(t)
                self.assertTrue(r["ok"], r)
                self.assertIn("Simulation", r["message"])
                mine = [f for f in merge.load(self.fpath) if f["source"] == t]
                self.assertEqual(len(mine), len(e.detections_for(t)))
                known = set(e.host_names(t))
                for f in mine:
                    for k in REQUIRED:
                        self.assertIn(k, f, (t, k))
                    self.assertEqual(f["source_mode"], "simulation")
                    self.assertIn(f["severity"], ("Critical", "High", "Medium", "Low"))
                    self.assertRegex(f["cve"], r"^CVE-\d{4}-\d{4,}$")
                    self.assertIn(f["asset"]["name"], known)
                    self.assertTrue(f["asset"]["ip"].startswith("10."))
                    if t != "openvas":  # GMP results carry no OS, so the real connector leaves the type to title/hostname rules
                        self.assertNotEqual(f["asset"]["type"], "unknown")
                    self.assertLessEqual(f["first_seen"], f["last_seen"])

    def test_the_same_hosts_appear_across_scanners_after_the_real_merge(self):
        for t in SCANNERS:
            self.run_sim(t)
        rows = merge.load(self.fpath)
        by_source = {t: {f["asset"]["name"] for f in rows if f["source"] == t} for t in SCANNERS}
        self.assertGreaterEqual(len(by_source["tenable"] & by_source["qualys"] & by_source["openvas"]), 4)
        # severity for the same CVE on the same host agrees between scanners (one estate feeds them all)
        sev = {}
        for f in rows:
            sev.setdefault((f["asset"]["name"], f["cve"]), set()).add(f["severity"])
        self.assertTrue(all(len(v) == 1 for v in sev.values()))

    def test_a_second_run_is_idempotent(self):
        for t in SCANNERS:
            with self.subTest(t):
                _, first = self.run_sim(t)
                before = merge.load(self.fpath)
                _, second = self.run_sim(t)
                self.assertTrue(second["ok"], second)
                self.assertEqual((second["detail"]["added"], second["detail"]["updated"], second["detail"]["removed"]), (0, 0, 0))
                self.assertEqual(merge.load(self.fpath), before)
                ids = [f["id"] for f in before]
                self.assertEqual(len(ids), len(set(ids)))

    def test_the_connectors_own_parsing_runs_and_the_transport_is_replayed(self):
        spies = {"tenable": (TenableConnector, "to_csv_row"), "qualys": (QualysConnector, "to_csv_rows"), "openvas": (OpenVasConnector, "to_csv_row")}
        transports = []
        real = renderers.session_for

        def capture(t, values=None, estate=None):
            s = real(t, values, estate)
            transports.append(s)
            return s
        for t, (cls, method) in spies.items():
            with self.subTest(t), patch.object(cls, method, wraps=getattr(cls, method)) as spy, patch.object(renderers, "session_for", side_effect=capture):
                _, r = self.run_sim(t)
                self.assertTrue(r["ok"], r)
                self.assertTrue(spy.called, f"{cls.__name__}.{method} was not used")
        self.assertEqual(len(transports), 3)
        self.assertTrue(transports[0].served and transports[1].served)  # the HTTP connectors really made requests
        self.assertEqual([x["method"] for x in transports[0].served][:1], ["POST"])  # the Tenable export flow starts with POST /vulns/export
        self.assertIn(("get_results", "simulation-task"), transports[2].served)  # the OpenVAS connector really called GMP

    def test_simulated_records_never_overwrite_live_ones(self):
        e = estate_mod.build()
        d = e.detections_for("tenable")[0]
        live = {"source": "tenable", "source_ref": d["vuln"]["plugin_id"], "asset": {"name": d["host"]["fqdn"], "ip": d["host"]["ip"], "type": "unix-server"},
                "title": "LIVE TITLE", "cve": d["vuln"]["cve"], "cvss": 1.0, "severity": "Low", "first_seen": "2026-01-01", "last_seen": "2026-01-02"}
        other = dict(live, source_ref="9999", cve="CVE-2099-0001", title="OTHER LIVE")
        merge.merge([live, other], "tenable", self.fpath, source_mode="live")
        _, r = self.run_sim("tenable")  # tenable reconciles: the live record not in the simulation must survive too
        self.assertTrue(r["ok"], r)
        rows = merge.load(self.fpath)
        mine = [f for f in rows if f["title"] == "LIVE TITLE"]
        self.assertEqual(len(mine), 1)
        self.assertEqual((mine[0]["severity"], mine[0]["cvss"], mine[0].get("source_mode", "live")), ("Low", 1.0, "live"))
        self.assertTrue(any(f["title"] == "OTHER LIVE" for f in rows))
        self.assertEqual(r["detail"]["kept_live"], 1)

    def test_a_live_pull_replaces_a_simulated_record_with_the_real_one(self):
        self.run_sim("tenable")
        rows = merge.load(self.fpath)
        target = dict(rows[0])
        merge.merge([{**{k: v for k, v in target.items() if k != "id"}, "title": "REAL TITLE", "severity": "Low"}], "tenable", self.fpath, source_mode="live")
        after = {f["id"]: f for f in merge.load(self.fpath)}
        self.assertEqual((after[target["id"]]["title"], after[target["id"]]["source_mode"]), ("REAL TITLE", "live"))

    def test_removing_simulation_removes_only_simulated_records_and_connections(self):
        live = {"source": "tenable", "source_ref": "1", "asset": {"name": "real-host", "type": "unix-server"}, "title": "Real", "cve": "CVE-2099-0002",
                "severity": "High", "cvss": 7.0, "first_seen": "2026-01-01", "last_seen": "2026-01-02"}
        merge.merge([live], "other-scanner", self.fpath, source_mode="live")
        for t in SCANNERS:
            self.run_sim(t)
        self.assertGreater(len(merge.load(self.fpath)), 1)
        out = service.remove("admin@t.local", self.engine, self.fpath)
        self.assertEqual(out["connections_removed"], 3)
        rows = merge.load(self.fpath)
        self.assertEqual([f["title"] for f in rows], ["Real"])
        self.assertEqual(store.list_connections(self.engine), [])

    def test_enrichment_runs_after_a_simulated_sync_without_the_network(self):
        with patch("remediation.enrichment.kev_epss.enrich_file") as enrich:
            _, r = self.run_sim("qualys", enrich=True)
        self.assertTrue(r["ok"], r)
        enrich.assert_called_once()
        self.assertIn("Threat intel", r["message"])

    def test_no_secret_appears_in_any_result_or_stored_state(self):
        c = store.create("Sim secrets", "tenable", {"mode": "simulation", "access_key": "SEKRET-A", "secret_key": "SEKRET-B"}, "a", engine=self.engine)
        r = sync.run(c["id"], "a", self.engine, self.fpath, enrich=False)
        blob = json.dumps([r, store.get_public(c["id"], self.engine), merge.load(self.fpath)], default=str)
        self.assertNotIn("SEKRET", blob)

    def test_the_loader_creates_one_connection_per_renderer_and_is_idempotent(self):
        with patch("remediation.enrichment.kev_epss.enrich_file"):
            out = service.load("admin@t.local", self.engine, self.fpath)
            n = len(merge.load(self.fpath))
            out2 = service.load("admin@t.local", self.engine, self.fpath)
        self.assertEqual([r["type"] for r in out["results"]], sorted(renderers.RENDERERS))
        self.assertTrue(all(r["ok"] for r in out["results"] + out2["results"]))
        self.assertEqual(len(store.list_connections(self.engine)), len(renderers.RENDERERS))
        self.assertEqual(len(merge.load(self.fpath)), n)
        st = service.status(self.engine, self.fpath)
        self.assertEqual((st["simulated_findings"], st["live_findings"]), (n, 0))


class EnvironmentGateTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        self.fpath = Path(tempfile.mkdtemp()) / "nf.json"

    def tearDown(self):
        self.engine.dispose()

    def make(self):
        return store.create("Sim", "tenable", {"mode": "simulation"}, "a", engine=self.engine)

    def test_prod_refuses_with_a_clear_error_recorded_on_the_connection(self):
        with clean_env(QUANTA_ENV="prod"):
            c = self.make()
            r = sync.run(c["id"], "a", self.engine, self.fpath, enrich=False)
            self.assertFalse(r["ok"])
            self.assertIn("not allowed", r["message"])
            self.assertEqual(store.get_public(c["id"], self.engine)["last_status"], "error")
            self.assertFalse(self.fpath.exists())
            with self.assertRaises(service.SimulationNotAllowed):
                service.load("a", self.engine, self.fpath)
            with self.assertRaises(sync.SimulationRefused):
                sync.test_connection("tenable", {"mode": "simulation"})

    def test_prod_with_the_explicit_flag_allows_it(self):
        with clean_env(QUANTA_ENV="prod", QUANTA_ALLOW_SIMULATION="true"):
            c = self.make()
            r = sync.run(c["id"], "a", self.engine, self.fpath, enrich=False)
            self.assertTrue(r["ok"], r)
            sync.test_connection("tenable", {"mode": "simulation"})

    def test_dev_and_test_allow_it(self):
        for env in ("dev", "test"):
            with clean_env(QUANTA_ENV=env):
                service.ensure_allowed()


class SimulationApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fpath = Path(self.tmp.name) / "nf.json"
        self.env = clean_env(QUANTA_ENCRYPTION_KEY=crypto.generate_key())
        self.env.start()
        self.patches = [patch.object(db_module, "get_engine", return_value=self.engine),
                        patch.object(merge, "DEFAULT_PATH", self.fpath),
                        patch("remediation.enrichment.kev_epss.enrich_file"),
                        patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for p in self.patches:
            p.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        self.env.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/api/auth/login", json={"email": email, "password": PW}).status_code, 200)

    def test_admin_only(self):
        self.assertEqual(self.client.get("/api/simulation/status").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/simulation/status").status_code, 403)
        self.assertEqual(self.client.post("/api/simulation/load", json={"confirm": True}).status_code, 403)
        self.assertEqual(self.client.delete("/api/simulation").status_code, 403)

    def test_load_is_a_preview_until_confirmed_then_loads_and_removes(self):
        self.login("admin@t.local")
        pre = self.client.post("/api/simulation/load", json={})
        self.assertEqual(pre.status_code, 200, pre.text)
        self.assertTrue(pre.json()["preview_only"])
        self.assertEqual(self.client.get("/api/simulation/status").json()["simulated_findings"], 0)
        self.assertFalse(self.fpath.exists())
        done = self.client.post("/api/simulation/load", json={"confirm": True})
        self.assertEqual(done.status_code, 200, done.text)
        self.assertTrue(all(r["ok"] for r in done.json()["results"]))
        st = self.client.get("/api/simulation/status").json()
        self.assertGreater(st["simulated_findings"], 0)
        listing = self.client.get("/api/connections").json()["connections"]
        self.assertTrue(all(c["mode"] == "simulation" for c in listing))
        queue = self.client.get("/api/findings/FIND-1")
        if queue.status_code == 200:
            self.assertEqual(queue.json().get("source_mode"), "simulation")
        gone = self.client.delete("/api/simulation").json()
        self.assertEqual(gone["connections_removed"], len(renderers.RENDERERS))
        self.assertEqual(self.client.get("/api/simulation/status").json()["simulated_findings"], 0)

    def test_refused_with_403_and_a_message_in_prod(self):
        self.login("admin@t.local")
        with patch.dict(os.environ, {"QUANTA_ENV": "prod"}):
            for r in (self.client.get("/api/simulation/status"), self.client.post("/api/simulation/load", json={"confirm": True}),
                      self.client.delete("/api/simulation")):
                self.assertEqual(r.status_code, 403, r.text)
                self.assertIn("not allowed", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
