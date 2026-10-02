"""
Tests for the production data path: deterministic scanner-CSV ingest and merge, encrypted
credential storage, stored connections, scheduled sync and the /api/connections routes.
No test talks to a real vendor; sources are replaced by fakes.
"""
import datetime
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

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.audit.activity_log import list_activity  # noqa: E402
from remediation.connections import crypto, registry, store, sync  # noqa: E402
from remediation.ingest import classify, merge, scanner_csv  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

HEADER = "Plugin ID,CVE,Risk,CVSS v3.0 Base Score,Host,IP Address,FQDN,OS,Name,Synopsis,Solution,Port,Protocol,First Discovered,Last Observed\n"


def write_csv(rows):
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    Path(path).write_text(HEADER + "".join(rows), encoding="utf-8")
    return path


ROW_WIN = '57608,CVE-2021-34527,Critical,8.8,WIN-DC01,10.0.0.1,,Microsoft Windows Server 2019,PrintNightmare,Spooler RCE,Apply KB,445,tcp,"Jul 28, 2026 10:00:00 UTC",2026-08-02\n'
ROW_LNX = "1001,CVE-2022-0847,High,7.8,web01,10.0.0.2,,Ubuntu 20.04,Dirty Pipe,Kernel flaw,Upgrade,0,tcp,2026-07-01,2026-08-02\n"
ROW_INFO = "1002,,None,,web01,10.0.0.2,,Ubuntu 20.04,SSH banner,info,,22,tcp,2026-07-01,2026-08-02\n"
ROW_NOHOST = "1003,,High,7.0,,,,Linux,Orphan,x,,0,tcp,,\n"


class ClassifyTests(unittest.TestCase):
    def test_families(self):
        cases = [("Microsoft Windows Server 2019 Datacenter", "WIN-DC01", "windows-server", "windows-server"),
                 ("Windows 11 Enterprise", "LAPTOP-9", "windows-endpoint", None),
                 ("Ubuntu 22.04", "web01", "unix-server", "unix-server"),
                 ("Cisco IOS XE 17.3", "sw-core", "network-routing-switching", None),
                 ("PAN-OS 10.2", "fw1", "network-security-device", None),
                 ("VMware ESXi 7.0", "esx1", "virtualization-host", None),
                 ("HP LaserJet M608", "prn-3", "printer", None),
                 ("macOS 14", "mbp", "unix-endpoint", None),
                 ("", "mystery", "unknown", None)]
        for os_name, host, typ, dom in cases:
            self.assertEqual(classify.classify(os_name, host, ""), (typ, dom), os_name or host)

    def test_a_server_is_not_mistaken_for_an_endpoint(self):
        self.assertEqual(classify.classify("Windows Server 2022", "x", "")[0], "windows-server")


class CsvTests(unittest.TestCase):
    def test_rows_become_findings_and_noise_is_skipped(self):
        findings, skipped = scanner_csv.parse_csv(write_csv([ROW_WIN, ROW_LNX, ROW_INFO, ROW_NOHOST]), "tenable", today="2026-09-01")
        self.assertEqual([f["asset"]["name"] for f in findings], ["WIN-DC01", "web01"])
        self.assertEqual(skipped, {"informational": 1, "no-host": 1})
        f = findings[0]
        self.assertEqual((f["severity"], f["cvss"], f["cve"], f["remediation_domain"]), ("Critical", 8.8, "CVE-2021-34527", "windows-server"))
        self.assertEqual((f["first_seen"], f["last_seen"]), ("2026-07-28", "2026-08-02"))

    def test_severity_falls_back_to_cvss_and_missing_dates_to_today(self):
        row = "9,CVE-2020-1111,,9.5,h,1.1.1.1,,Linux,t,s,f,0,tcp,,\n"
        (f,), _ = scanner_csv.parse_csv(write_csv([row]), "qualys", today="2026-09-01")
        self.assertEqual((f["severity"], f["first_seen"], f["source"]), ("Critical", "2026-09-01", "qualys"))

    def test_multiple_cves_keep_the_first_and_mention_the_rest(self):
        row = "9,CVE-2020-1111 CVE-2020-2222,High,7.5,h,1.1.1.1,,Linux,t,syn,f,0,tcp,,\n"
        (f,), _ = scanner_csv.parse_csv(write_csv([row]), "tenable")
        self.assertEqual(f["cve"], "CVE-2020-1111")
        self.assertIn("CVE-2020-2222", f["description"])


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = Path(self.dir) / "nf.json"

    def pull(self, rows, today="2026-09-01"):
        return scanner_csv.parse_csv(write_csv(rows), "tenable", today=today)[0]

    def test_first_merge_assigns_sequential_ids(self):
        r = merge.merge(self.pull([ROW_WIN, ROW_LNX]), "tenable", self.path)
        self.assertEqual((r["added"], r["total"]), (2, 2))
        self.assertEqual([f["id"] for f in merge.load(self.path)], ["FIND-1", "FIND-2"])

    def test_remerge_is_idempotent_and_refreshes_last_seen_keeping_id_and_first_seen(self):
        merge.merge(self.pull([ROW_WIN]), "tenable", self.path)
        later = ROW_WIN.replace("2026-08-02", "2026-09-10")
        r = merge.merge(self.pull([later]), "tenable", self.path)
        self.assertEqual((r["added"], r["updated"]), (0, 1))
        (f,) = merge.load(self.path)
        self.assertEqual((f["id"], f["first_seen"], f["last_seen"]), ("FIND-1", "2026-07-28", "2026-09-10"))
        self.assertEqual(merge.merge(self.pull([later]), "tenable", self.path)["updated"], 0)

    def test_enrichment_survives_a_remerge(self):
        merge.merge(self.pull([ROW_WIN]), "tenable", self.path)
        data = merge.load(self.path)
        data[0]["kev"] = {"listed": True}
        self.path.write_text(json.dumps(data), encoding="utf-8")
        merge.merge(self.pull([ROW_WIN.replace("2026-08-02", "2026-09-10")]), "tenable", self.path)
        self.assertEqual(merge.load(self.path)[0]["kev"], {"listed": True})

    def test_reconcile_removes_only_that_sources_unseen_findings(self):
        merge.merge(self.pull([ROW_WIN, ROW_LNX]), "tenable", self.path)
        other = [{"source": "qualys", "asset": {"name": "q1"}, "title": "t", "cve": None, "severity": "High"}]
        merge.merge(other, "qualys", self.path)
        r = merge.merge(self.pull([ROW_WIN]), "tenable", self.path, reconcile=True)
        self.assertEqual(r["removed"], 1)
        self.assertEqual(sorted(f["source"] for f in merge.load(self.path)), ["qualys", "tenable"])

    def test_partial_pull_without_reconcile_never_removes(self):
        merge.merge(self.pull([ROW_WIN, ROW_LNX]), "tenable", self.path)
        self.assertEqual(merge.merge(self.pull([ROW_WIN]), "tenable", self.path)["removed"], 0)

    def test_a_backup_of_the_previous_version_is_kept(self):
        merge.merge(self.pull([ROW_WIN]), "tenable", self.path)
        merge.merge(self.pull([ROW_LNX]), "tenable", self.path)
        self.assertTrue(self.path.with_name("nf.json.bak").exists())


class CryptoTests(unittest.TestCase):
    def test_round_trip_and_no_plaintext(self):
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": crypto.generate_key()}):
            token = crypto.encrypt({"secret_key": "hunter2"})
            self.assertNotIn("hunter2", token)
            self.assertEqual(crypto.decrypt(token), {"secret_key": "hunter2"})

    def test_without_a_key_nothing_can_be_stored(self):
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": ""}):
            self.assertFalse(crypto.available())
            with self.assertRaises(crypto.EncryptionNotConfigured):
                crypto.encrypt({"a": "b"})

    def test_wrong_key_fails_loudly_and_rotation_keeps_data_readable(self):
        old, new = crypto.generate_key(), crypto.generate_key()
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": old}):
            token = crypto.encrypt({"k": "v"})
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": new}):
            with self.assertRaises(crypto.DecryptionFailed):
                crypto.decrypt(token)
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": f"{new},{old}"}):
            self.assertEqual(crypto.decrypt(token), {"k": "v"})
            rotated = crypto.rotate(token)
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": new}):
            self.assertEqual(crypto.decrypt(rotated), {"k": "v"})


FAKE_FINDING = {"source": "fake", "source_ref": "r1", "asset": {"name": "h1", "type": "unix-server"}, "title": "T", "cve": None,
                "severity": "High", "cvss": 7.0, "first_seen": "2026-09-01", "last_seen": "2026-09-01"}


class StoredConnectionTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        self.dir = tempfile.mkdtemp()
        self.fpath = Path(self.dir) / "nf.json"
        self.env = patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": crypto.generate_key()})
        self.env.start()
        self.pulls = []
        fake = {"label": "Fake", "category": "test", "output": "findings",
                "fields": [registry._f("base_url", "URL"), registry._f("token", "Token", secret=True)],
                "safe_targets": ["base_url"], "test": lambda c: None,
                "pull": lambda c: (self.pulls.append(dict(c)), {"kind": "findings", "findings": [dict(FAKE_FINDING)], "reconcile": True, "skipped": {}})[1]}
        self.spec = patch.dict(registry.SPECS, {"fake": fake})
        self.spec.start()

        def guard(target):  # offline stand-in for the DNS-resolving SSRF guard
            if "169.254" in target or "localhost" in target:
                raise registry.url_safety.UnsafeTargetError("blocked")
        self.guard = patch.object(registry.url_safety, "assert_safe_target", side_effect=guard)
        self.guard.start()

    def tearDown(self):
        self.guard.stop()
        self.spec.stop()
        self.env.stop()
        self.engine.dispose()

    def make(self, **kw):
        return store.create("Fake 1", "fake", {"base_url": "https://scanner.example.com", "token": "TOP-SECRET"}, "admin@t.local", engine=self.engine, **kw)

    def test_public_view_never_contains_a_secret(self):
        c = self.make()
        self.assertNotIn("TOP-SECRET", json.dumps(c))
        self.assertEqual((c["secrets_set"], c["config"]), (["token"], {"base_url": "https://scanner.example.com"}))
        with self.engine.connect() as conn:
            raw = conn.execute(db_module.connections.select()).mappings().first()
        self.assertNotIn("TOP-SECRET", json.dumps(dict(raw)))

    def test_validation(self):
        with self.assertRaises(ValueError):
            store.create("x", "fake", {"base_url": "https://s.example.com"}, "a", engine=self.engine)  # token missing
        with self.assertRaises(ValueError):
            store.create("x", "nope", {}, "a", engine=self.engine)
        with self.assertRaises(ValueError):
            store.create("x", "fake", {"base_url": "http://169.254.169.254", "token": "t"}, "a", engine=self.engine)  # SSRF guard
        with self.assertRaises(ValueError):
            self.make(schedule_minutes=5)
        self.make()
        with self.assertRaises(ValueError):
            self.make()  # duplicate name

    def test_no_key_means_no_stored_credentials(self):
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": ""}):
            with self.assertRaises(crypto.EncryptionNotConfigured):
                self.make()

    def test_blank_secret_on_edit_keeps_the_stored_one(self):
        c = self.make()
        store.update_connection(c["id"], "a", values={"base_url": "https://other.example.com", "token": ""}, engine=self.engine)
        _, values = store.get_values(c["id"], self.engine)
        self.assertEqual((values["token"], values["base_url"]), ("TOP-SECRET", "https://other.example.com"))
        store.update_connection(c["id"], "a", values={"token": "NEW"}, engine=self.engine)
        self.assertEqual(store.get_values(c["id"], self.engine)[1]["token"], "NEW")

    def test_sync_merges_findings_records_the_run_and_audits_it(self):
        c = self.make()
        r = sync.run(c["id"], "admin@t.local", self.engine, self.fpath, enrich=False)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.pulls[0]["token"], "TOP-SECRET")
        self.assertEqual(len(merge.load(self.fpath)), 1)
        pub = store.get_public(c["id"], self.engine)
        self.assertEqual((pub["last_status"], pub["last_count"]), ("ok", 1))
        self.assertTrue(list_activity(engine=self.engine, action="connection.sync"))

    def test_a_failing_source_is_recorded_not_raised(self):
        c = self.make()
        registry.SPECS["fake"]["pull"] = lambda v: (_ for _ in ()).throw(RuntimeError("401 Unauthorized"))
        r = sync.run(c["id"], "scheduler", self.engine, self.fpath, enrich=False)
        self.assertFalse(r["ok"])
        pub = store.get_public(c["id"], self.engine)
        self.assertEqual(pub["last_status"], "error")
        self.assertIn("401", pub["last_message"])

    def test_a_running_connection_cannot_be_started_twice(self):
        c = self.make()
        self.assertTrue(store.claim_run(c["id"], self.engine))
        self.assertFalse(store.claim_run(c["id"], self.engine))
        r = sync.run(c["id"], "a", self.engine, self.fpath, enrich=False)
        self.assertFalse(r["ok"])
        # a stale flag from a crashed run is overridden
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=3)
        self.assertTrue(store.claim_run(c["id"], self.engine, later))

    def test_due_selects_scheduled_enabled_connections_whose_interval_elapsed(self):
        now = datetime.datetime(2026, 9, 1, 12, 0, tzinfo=datetime.timezone.utc)
        a = self.make(schedule_minutes=60)
        b = store.create("Manual", "fake", {"base_url": "https://s.example.com", "token": "t"}, "a", engine=self.engine)
        c = store.create("Off", "fake", {"base_url": "https://s.example.com", "token": "t"}, "a", enabled=False, schedule_minutes=60, engine=self.engine)
        self.assertEqual([x["id"] for x in store.due(self.engine, now)], [a["id"]])  # never run yet
        store.finish_run(a["id"], "ok", "m", 1, self.engine, now - datetime.timedelta(minutes=30))
        self.assertEqual(store.due(self.engine, now), [])
        store.finish_run(a["id"], "ok", "m", 1, self.engine, now - datetime.timedelta(minutes=90))
        self.assertEqual([x["id"] for x in store.due(self.engine, now)], [a["id"]])
        self.assertNotIn(b["id"], [x["id"] for x in store.due(self.engine, now)])
        self.assertNotIn(c["id"], [x["id"] for x in store.due(self.engine, now)])

    def test_run_due_runs_what_is_due(self):
        self.make(schedule_minutes=60)
        out = sync.run_due(self.engine, self.fpath)
        self.assertEqual(len(out), 1)


class AssetSourceTests(unittest.TestCase):
    def test_asset_pull_reconciles_into_the_inventory(self):
        engine = create_engine("sqlite:///:memory:")
        fpath = Path(tempfile.mkdtemp()) / "nf.json"
        merge.merge([dict(FAKE_FINDING)], "fake", fpath)
        spec = {"label": "Assets", "category": "t", "output": "assets", "fields": [registry._f("token", "Token", secret=True)], "test": lambda c: None,
                "pull": lambda c: {"kind": "assets", "assets": [{"name": "h1", "ip": "10.1.1.1", "mac": None}]}}
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": crypto.generate_key()}), patch.dict(registry.SPECS, {"assets": spec}), \
                patch("remediation.inventory.asset_inventory.reconcile_pulled_assets", return_value={"matched": ["h1"], "unmatched": [], "skipped": []}) as rec:
            c = store.create("A", "assets", {"token": "t"}, "a", engine=engine)
            r = sync.run(c["id"], "a", engine, fpath, enrich=False)
        self.assertTrue(r["ok"], r)
        self.assertEqual(rec.call_args[0][1], ["h1"])
        engine.dispose()


PW = "test-password-123"


class ConnectionApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.env = patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": crypto.generate_key()})
        self.env.start()
        self.patches = [patch.object(db_module, "get_engine", return_value=self.engine),
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

    BODY = {"name": "Prod Tenable", "type": "tenable", "values": {"access_key": "AK", "secret_key": "SK"}, "schedule_minutes": 60}

    def test_admin_only(self):
        self.assertEqual(self.client.get("/api/connections").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/connections").status_code, 403)
        self.assertEqual(self.client.post("/api/connections", json=self.BODY).status_code, 403)

    def test_create_list_edit_delete_and_secrets_never_returned(self):
        self.login("admin@t.local")
        listing = self.client.get("/api/connections").json()
        self.assertTrue(listing["encryption_available"])
        self.assertIn("tenable", [c["type"] for c in listing["catalog"]])
        r = self.client.post("/api/connections", json=self.BODY)
        self.assertEqual(r.status_code, 200, r.text)
        cid = r.json()["id"]
        self.assertNotIn("SK", self.client.get("/api/connections").text)
        e = self.client.put(f"/api/connections/{cid}", json={"schedule_minutes": 360, "enabled": False})
        self.assertEqual((e.json()["schedule_minutes"], e.json()["enabled"]), (360, False))
        self.assertEqual(self.client.delete(f"/api/connections/{cid}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/connections/{cid}").status_code, 404)

    def test_creation_is_refused_with_a_clear_message_when_no_key_is_set(self):
        self.login("admin@t.local")
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": ""}):
            r = self.client.post("/api/connections", json=self.BODY)
            self.assertEqual(r.status_code, 400)
            self.assertIn("QUANTA_ENCRYPTION_KEY", r.json()["detail"])
            self.assertFalse(self.client.get("/api/connections").json()["encryption_available"])

    def test_test_endpoint_uses_the_source_and_surfaces_failures(self):
        self.login("admin@t.local")
        ok = {"label": "Fake", "fields": [registry._f("token", "Token", secret=True)], "test": lambda c: None, "pull": lambda c: None}
        bad = {**ok, "test": lambda c: (_ for _ in ()).throw(RuntimeError("bad key"))}
        with patch.dict(registry.SPECS, {"okfake": ok, "badfake": bad}):
            self.assertEqual(self.client.post("/api/connections/test", json={"type": "okfake", "values": {"token": "t"}}).status_code, 200)
            r = self.client.post("/api/connections/test", json={"type": "badfake", "values": {"token": "t"}})
            self.assertEqual(r.status_code, 502)
            self.assertIn("bad key", r.json()["detail"])
        self.assertEqual(self.client.post("/api/connections/test", json={"type": "nope", "values": {}}).status_code, 400)

    def test_sync_endpoint_starts_a_background_run(self):
        self.login("admin@t.local")
        cid = self.client.post("/api/connections", json=self.BODY).json()["id"]
        r = self.client.post(f"/api/connections/{cid}/sync")
        self.assertEqual((r.status_code, r.json()), (200, {"started": True, "job": 1}))
        from remediation.coordination import jobs
        queued = jobs.get(1, self.engine)
        self.assertEqual((queued["kind"], queued["payload"]["connection_id"], queued["status"]), ("connection.sync", cid, "queued"))
        self.assertEqual(self.client.post(f"/api/connections/{cid}/sync").json()["job"], 1)  # a second click does not queue a second sync
        self.assertEqual(self.client.post("/api/connections/999/sync").status_code, 404)


if __name__ == "__main__":
    unittest.main()
