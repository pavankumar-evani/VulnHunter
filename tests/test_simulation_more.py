"""
Tests for the simulation renderers of the remaining pull connectors: Prisma Cloud, Cortex XSIAM, Infoblox, Axonius, Active Directory (an injected
LDAP connection, not HTTP) and the Anthropic and OpenAI usage connectors. Same shape as tests/test_simulation.py: a full sync.run of a simulation
connection pushes recorded vendor-format responses through each connector's REAL code, then the normal merge/reconcile/record path.

No test touches the network or the real clock. Fakes are hand-rolled.
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

from sqlalchemy import create_engine, select  # noqa: E402

from remediation.aiusage import store as usage_store  # noqa: E402
from remediation.connections import registry, store, sync  # noqa: E402
from remediation.connectors.active_directory_connector import ActiveDirectoryConnector  # noqa: E402
from remediation.connectors.ai_usage_connector import AnthropicUsageConnector, OpenAIUsageConnector  # noqa: E402
from remediation.connectors.axonius_connector import AxoniusConnector  # noqa: E402
from remediation.connectors.cortex_xsiam_connector import CortexXsiamConnector  # noqa: E402
from remediation.connectors.infoblox_connector import InfobloxConnector  # noqa: E402
from remediation.connectors.prismacloud_connector import PrismaCloudConnector  # noqa: E402
from remediation.ingest import merge  # noqa: E402
from remediation.inventory import asset_inventory  # noqa: E402
from remediation.simulation import estate as estate_mod  # noqa: E402
from remediation.simulation import renderers, service  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NEW_TYPES = ("prismacloud", "cortex-xsiam", "infoblox", "axonius", "active-directory", "anthropic-usage", "openai-usage")
FINDING_TYPES = ("prismacloud", "cortex-xsiam")
ASSET_TYPES = ("infoblox", "axonius", "active-directory")
USAGE_TYPES = ("anthropic-usage", "openai-usage")
FINDING_REQUIRED = ("id", "source", "asset", "title", "cve", "cvss", "severity", "first_seen", "last_seen", "source_mode")
ASSET_KEYS = {"name", "ip", "mac", "type", "source", "source_ref", "extra", "source_mode"}  # sync.run stamps the provenance on each pulled record
USAGE_KEYS = {"ts", "provider", "model", "application", "input_tokens", "output_tokens", "cache_read_tokens", "event_key"}
SECRETS = ("SEKRET-ONE", "SEKRET-TWO", "SEKRET-THREE")


def clean_env(**extra):
    env = {"QUANTA_ENV": "dev", "QUANTA_ALLOW_SIMULATION": "", "QUANTA_PRODUCTION": "", "QUANTA_ENCRYPTION_KEY": ""}
    env.update(extra)
    return patch.dict(os.environ, env)


def spy_static(cls, name):
    """Wraps a static normalising method so the test sees every real call and its result."""
    real = getattr(cls, name)
    out = []

    def wrapper(*a, **k):
        r = real(*a, **k)
        out.append(r)
        return r
    return patch.object(cls, name, staticmethod(wrapper)), out


def spy_method(cls, name):
    real = getattr(cls, name)
    out = []

    def wrapper(self, *a, **k):
        r = real(self, *a, **k)
        out.append(r)
        return r
    return patch.object(cls, name, wrapper), out


class EstateExtensionTests(unittest.TestCase):
    def test_new_data_is_deterministic_and_leaves_the_original_estate_alone(self):
        a, b = estate_mod.build(1, "small"), estate_mod.build(1, "small")
        self.assertEqual(a.to_dict(), b.to_dict())
        self.assertNotEqual(a.cloud_alerts, estate_mod.build(2, "small").cloud_alerts)
        self.assertEqual([h["id"] for h in a.hosts][:3], ["H001", "H002", "H003"])
        self.assertEqual(a.usage_for("anthropic", a.reference_date, "x", "w", "m"), b.usage_for("anthropic", a.reference_date, "x", "w", "m"))

    def test_everything_references_estate_hosts_and_stays_fictional(self):
        for size in estate_mod.SIZES:
            e = estate_mod.build(1, size)
            fqdns = {h["fqdn"] for h in e.hosts}
            self.assertTrue(e.incidents and e.cloud_alerts and e.unmanaged)
            for i in e.incidents:
                self.assertTrue(set(i["hosts"]) <= fqdns)
            cloud_hosts = {h["id"] for h in e.hosts_for("prismacloud")}
            for a in e.cloud_alerts:
                if a["host_id"]:
                    self.assertIn(a["host_id"], cloud_hosts)
                    self.assertEqual(a["resource"]["name"], e.host(a["host_id"])["fqdn"])
                self.assertLessEqual(a["first_seen"], a["last_seen"])
            for u in e.unmanaged:
                self.assertTrue(u["fqdn"].endswith(".corp.test") and u["ip"].startswith("10."))
                self.assertNotIn(u["fqdn"], fqdns)
            self.assertEqual(set(e.coverage["infoblox"]), {h["id"] for h in e.hosts})
            self.assertTrue(all(e.host(i)["family"] == "windows" for i in e.coverage["active-directory"]))

    def test_the_simulated_clock_is_fixed(self):
        now = renderers.sim_now()
        self.assertEqual((now.date(), now.hour, now.utcoffset().total_seconds()), (estate_mod.REFERENCE_DATE, 12, 0))


class RegistryTests(unittest.TestCase):
    def test_every_pull_type_has_a_renderer_and_a_mode_field(self):
        pull = {t for t, s in registry.SPECS.items() if s.get("kind", "pull") == "pull"}
        self.assertEqual(pull, set(renderers.RENDERERS))
        for t in NEW_TYPES:
            self.assertIn("mode", [f["name"] for f in registry.SPECS[t]["fields"]])
            config, secrets = registry.split_values(t, {"mode": "simulation"})
            self.assertEqual((config["mode"], secrets), ("simulation", {}))

    def test_secrets_given_to_a_simulation_connection_are_dropped(self):
        config, secrets = registry.split_values("axonius", {"mode": "simulation", "api_key": SECRETS[0], "api_secret": SECRETS[1], "base_url": "http://169.254.169.254"})
        self.assertEqual((config, secrets), ({"mode": "simulation"}, {}))

    def test_a_simulated_usage_pull_reads_the_fixed_clock_not_the_real_one(self):
        for t in USAGE_TYPES:
            ev = registry.SPECS[t]["pull"]({"mode": "simulation"}, renderers.session_for(t))["events"]
            days = sorted({e["ts"][:10] for e in ev})
            self.assertEqual((days[0], days[-1]), ("2026-07-26", "2026-08-02"), t)

    def test_a_live_usage_connection_still_uses_the_real_clock(self):
        c = registry.SPECS["anthropic-usage"]["build"]({"admin_key": "k"})
        self.assertGreater(c.now.year, 2025)
        self.assertNotEqual(c.now, renderers.sim_now())


class MoreSyncBase(unittest.TestCase):
    def setUp(self):
        self.env = clean_env()
        self.env.start()
        self.engine = create_engine("sqlite:///:memory:")
        self.fpath = Path(tempfile.mkdtemp()) / "nf.json"
        self.estate = estate_mod.build()

    def tearDown(self):
        self.env.stop()
        self.engine.dispose()

    def sim_connection(self, t, **values):
        name = service.connection_name(t)
        existing = [c for c in store.list_connections(self.engine) if c["name"] == name]
        return existing[0] if existing else store.create(name, t, {"mode": "simulation", **values}, "admin@t.local", engine=self.engine)

    def run_sim(self, t, enrich=False, **values):
        c = self.sim_connection(t, **values)
        return sync.run(c["id"], "admin@t.local", self.engine, self.fpath, enrich=enrich)

    def run_scanners(self):
        for t in ("tenable", "qualys", "openvas"):
            self.assertTrue(self.run_sim(t)["ok"])

    def ownership_rows(self):
        t = db_module.asset_ownership
        with self.engine.connect() as conn:
            return {r["asset_name"]: dict(r) for r in conn.execute(select(t)).mappings().all()}

    def usage_rows(self):
        t = db_module.ai_usage_events
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(select(t).order_by(t.c.id)).mappings().all()]


class FindingSourceTests(MoreSyncBase):
    def test_prisma_and_xsiam_produce_schema_valid_simulated_findings_through_the_real_connector(self):
        spies = {"prismacloud": spy_static(PrismaCloudConnector, "normalize_alert"), "cortex-xsiam": spy_static(CortexXsiamConnector, "normalize_incident")}
        expected = {"prismacloud": len([a for a in self.estate.cloud_alerts if a["status"] == "open"]), "cortex-xsiam": len(self.estate.incidents)}
        for t in FINDING_TYPES:
            with self.subTest(t), spies[t][0]:
                r = self.run_sim(t)
                self.assertTrue(r["ok"], r)
                self.assertIn("Simulation", r["message"])
                self.assertEqual(len(spies[t][1]), expected[t])  # the connector's own parser ran once per record
                mine = [f for f in merge.load(self.fpath) if f["source"] == t]
                self.assertEqual(len(mine), expected[t])
                for f in mine:
                    for k in FINDING_REQUIRED:
                        self.assertIn(k, f, (t, k))
                    self.assertEqual(f["source_mode"], "simulation")
                    self.assertIn(f["severity"], ("Critical", "High", "Medium", "Low"))
                    self.assertIsNone(f["cve"])
                    self.assertRegex(f["first_seen"], r"^\d{4}-\d{2}-\d{2}$")  # a date, not raw epoch milliseconds
                    self.assertLessEqual(f["first_seen"], f["last_seen"])
                    self.assertLessEqual(f["last_seen"], "2026-08-02")

    def test_findings_correlate_with_the_hosts_the_scanners_report(self):
        self.run_scanners()
        for t in FINDING_TYPES:
            self.assertTrue(self.run_sim(t)["ok"])
        rows = merge.load(self.fpath)
        scanner_hosts = {f["asset"]["name"] for f in rows if f["source"] == "tenable"}
        prisma = {f["asset"]["name"] for f in rows if f["source"] == "prismacloud"}
        xsiam = {f["asset"]["name"] for f in rows if f["source"] == "cortex-xsiam"}
        host_alerts = {a["resource"]["name"] for a in self.estate.cloud_alerts if a["host_id"] and a["status"] == "open"}
        self.assertTrue(host_alerts and host_alerts <= prisma <= (scanner_hosts | {a["resource"]["name"] for a in self.estate.cloud_alerts}))
        self.assertTrue(host_alerts <= scanner_hosts)
        self.assertTrue(xsiam and xsiam <= scanner_hosts)
        # one host carries scanner findings AND posture alerts or an incident: that is what attack-path correlation needs
        self.assertTrue((prisma | xsiam) & {f["asset"]["name"] for f in rows if f["source"] in ("qualys", "openvas")})

    def test_a_second_run_is_idempotent(self):
        for t in FINDING_TYPES:
            with self.subTest(t):
                self.assertTrue(self.run_sim(t)["ok"])
                before = merge.load(self.fpath)
                second = self.run_sim(t)
                self.assertTrue(second["ok"], second)
                self.assertEqual((second["detail"]["added"], second["detail"]["updated"], second["detail"]["removed"]), (0, 0, 0))
                self.assertEqual(merge.load(self.fpath), before)

    def test_the_transport_was_replayed_and_the_open_filter_applied(self):
        transports = []
        real = renderers.session_for

        def capture(t, values=None, estate=None):
            s = real(t, values, estate)
            transports.append((t, s))
            return s
        with patch.object(renderers, "session_for", side_effect=capture):
            self.run_sim("prismacloud")
            self.run_sim("cortex-xsiam")
        prisma, xsiam = dict(transports)["prismacloud"], dict(transports)["cortex-xsiam"]
        self.assertEqual([(x["method"], x["path_url"].rsplit("/", 1)[-1]) for x in prisma.served], [("POST", "login"), ("POST", "alert")])
        self.assertEqual(xsiam.served[0]["json"]["request_data"]["search_to"], 100)
        self.assertFalse(any(a["status"] == "resolved" for a in self.estate.cloud_alerts if a["id"] in {f["source_ref"] for f in merge.load(self.fpath)}))


class AssetSourceTests(MoreSyncBase):
    SPIES = {"infoblox": (InfobloxConnector, "normalize_host_record"), "axonius": (AxoniusConnector, "normalize_device"),
             "active-directory": (ActiveDirectoryConnector, "normalize_computer_entry")}

    def test_each_asset_source_yields_inventory_shaped_records_via_the_real_connector(self):
        self.run_scanners()
        fqdns = {h["fqdn"] for h in self.estate.hosts}
        for t in ASSET_TYPES:
            cls, method = self.SPIES[t]
            patcher, out = spy_static(cls, method)
            with self.subTest(t), patcher:
                r = self.run_sim(t)
                self.assertTrue(r["ok"], r)
                self.assertEqual(r["count"], len(out))
                for a in out:
                    self.assertEqual(set(a), ASSET_KEYS)
                    self.assertEqual((a["source"], a["source_mode"]), (t, "simulation"))
                    self.assertTrue(a["source_ref"])
                if t == "active-directory":
                    self.assertEqual({a["extra"]["dns_hostname"] for a in out}, {h["fqdn"] for h in self.estate.hosts if h["family"] == "windows"} | {u["fqdn"] for u in self.estate.unmanaged if u["family"] == "workstation"})
                    self.assertTrue(all(a["type"] in ("windows-server", "windows-endpoint") for a in out))
                    self.assertEqual([a["extra"]["enabled"] for a in out if a["name"] == "WS-03"], [False])
                    self.assertEqual(r["detail"]["skipped"], len(out))  # a computer object carries no ip or mac, so nothing is stored (the connector says so)
                else:
                    self.assertEqual({a["name"] for a in out}, fqdns | {u["fqdn"] for u in self.estate.unmanaged})
                    self.assertTrue(all(a["ip"] and a["ip"].startswith("10.") for a in out))
                    self.assertEqual(r["detail"]["matched"], len(self.estate.hosts))  # every scanned host is matched to its findings
                    self.assertEqual(r["detail"]["unmatched"], len(self.estate.unmanaged))  # the devices no scanner sees are kept for when a finding appears

    def test_a_host_a_scanner_reports_is_present_in_infoblox_and_axonius_with_the_same_address(self):
        self.run_scanners()
        rows = merge.load(self.fpath)
        ips = {f["asset"]["name"]: f["asset"]["ip"] for f in rows if f["source"] == "tenable"}
        for t in ("infoblox", "axonius"):
            patcher, out = spy_static(*self.SPIES[t])
            with patcher:
                self.assertTrue(self.run_sim(t)["ok"])
            got = {a["name"]: a["ip"] for a in out}
            self.assertTrue(set(ips) <= set(got), t)
            self.assertTrue(all(got[n] == ips[n] for n in ips), t)
        owned = self.ownership_rows()
        self.assertTrue(all(owned[n]["source_mode"] == "simulation" and owned[n]["ip"] == ips[n] for n in ips))
        self.assertTrue(all(owned[n]["mac"] for n in ips))  # Axonius added the MAC (Infoblox has none)

    def test_axonius_tags_each_device_with_the_adapters_that_know_it(self):
        patcher, out = spy_static(AxoniusConnector, "normalize_device")
        with patcher:
            self.run_sim("axonius")
        by = {a["name"]: a["extra"]["adapters"] for a in out}
        self.assertIn("tenable_io_adapter", by[self.estate.hosts[0]["fqdn"]])
        self.assertEqual(by["cam-01.corp.test"], ["infoblox_adapter"])

    def test_a_second_run_changes_nothing(self):
        self.run_scanners()
        for t in ASSET_TYPES:
            self.run_sim(t)
        before = self.ownership_rows()
        for t in ASSET_TYPES:
            r = self.run_sim(t)
            self.assertTrue(r["ok"], r)
        self.assertEqual(self.ownership_rows(), before)

    def test_a_simulated_pull_never_overwrites_a_live_asset_row(self):
        h = self.estate.hosts[0]
        asset_inventory.set_network_info(h["fqdn"], ip="10.99.99.99", engine=self.engine)
        asset_inventory.set_owner(h["fqdn"], "A. Person", "Real Team", engine=self.engine)
        r = self.run_sim("infoblox")
        self.assertTrue(r["ok"], r)
        row = self.ownership_rows()[h["fqdn"]]
        self.assertEqual((row["ip"], row["owner"], row["source_mode"]), ("10.99.99.99", "A. Person", None))
        self.assertGreaterEqual(r["detail"]["skipped"], 1)

    def test_the_ldap_double_serves_a_base_probe_and_a_computer_search(self):
        ldap = renderers.session_for("active-directory")
        c = ActiveDirectoryConnector("simulation.invalid", "DC=corp,DC=test", connection=ldap)
        self.assertEqual(c.test_connection(), {"ok": True})
        names = [a["name"] for a in c.fetch_and_normalize_computers()]
        self.assertIn("DC-01", names)
        self.assertEqual(len(ldap.searches), 2)
        self.assertFalse(ldap.unbound)  # an injected connection is the caller's to close


class UsageSourceTests(MoreSyncBase):
    SPIES = {"anthropic-usage": AnthropicUsageConnector, "openai-usage": OpenAIUsageConnector}

    def test_usage_events_come_from_the_real_connector_with_provenance(self):
        for t in USAGE_TYPES:
            patcher, out = spy_method(self.SPIES[t], "fetch_events")
            with self.subTest(t), patcher:
                r = self.run_sim(t)
                self.assertTrue(r["ok"], r)
                self.assertIn("usage bucket", r["message"])
                events = out[0]
                self.assertTrue(events)
                self.assertEqual(r["count"], len(events))
                for e in events:
                    self.assertTrue(USAGE_KEYS <= set(e), e)
                    self.assertEqual(e["provider"], t.split("-")[0])
                    self.assertLessEqual(e["ts"][:10], "2026-08-02")
                rows = [x for x in self.usage_rows() if x["provider"] == t.split("-")[0]]
                self.assertEqual(len(rows), len(events))
                self.assertTrue(all(x["source_mode"] == "simulation" and x["source"] == "provider-api" for x in rows))
                self.assertTrue(all(x["cost_basis"] in ("unknown", "estimated") for x in rows))  # never a made-up price
        apps = {x["application"] for x in self.usage_rows()}
        self.assertTrue(any("customer_portal" in a for a in apps))  # the workspaces are the estate's applications

    def test_every_page_is_followed(self):
        transports = []
        real = renderers.session_for

        def capture(t, values=None, estate=None):
            s = real(t, values, estate)
            transports.append((t, s))
            return s
        with patch.object(renderers, "session_for", side_effect=capture):
            for t in USAGE_TYPES:
                self.run_sim(t)
        for t, s in transports:
            self.assertGreaterEqual(len(s.served), 3, t)  # eight daily buckets, three per page
            self.assertTrue(all(x["status"] == 200 for x in s.served))
        self.assertEqual(len({(x["provider"], x["ts"][:10]) for x in self.usage_rows()}), 16)  # 8 days for each of 2 providers

    def test_results_are_identical_on_every_run_and_a_rerun_updates_in_place(self):
        self.run_sim("anthropic-usage")
        first = self.usage_rows()
        r = self.run_sim("anthropic-usage")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["detail"]["recorded"], 0)
        second = self.usage_rows()
        self.assertEqual(len(second), len(first))
        strip = lambda rows: [{k: v for k, v in x.items() if k != "received_at"} for x in rows]  # noqa: E731
        self.assertEqual(strip(second), strip(first))

    def test_a_simulated_batch_never_touches_a_live_event_with_the_same_key(self):
        key = f"anthropic|2026-08-02T00:00:00Z|claude-sonnet-4-20250514|wrkspc_sim_customer_portal|apikey_sim_customer_portal_01|standard"
        usage_store.record([{"ts": "2026-08-02T00:00:00Z", "model": "claude-sonnet-4-20250514", "input_tokens": 7, "event_key": key}], "provider-api", self.engine)
        self.run_sim("anthropic-usage")
        live = [x for x in self.usage_rows() if x["event_key"] == key]
        self.assertEqual([(x["input_tokens"], x["source_mode"]) for x in live], [(7, None)])

    def test_the_connection_test_works_in_simulation(self):
        for t in NEW_TYPES:
            sync.test_connection(t, {"mode": "simulation"})


class RemovalTests(MoreSyncBase):
    def test_remove_clears_simulated_findings_assets_and_usage_and_leaves_live_records(self):
        live_finding = {"source": "other-scanner", "source_ref": "1", "asset": {"name": "real-host", "type": "unix-server"}, "title": "Real", "cve": "CVE-2099-0002",
                        "severity": "High", "cvss": 7.0, "first_seen": "2026-01-01", "last_seen": "2026-01-02"}
        merge.merge([live_finding], "other-scanner", self.fpath, source_mode="live")
        usage_store.record([{"ts": "2026-08-01T00:00:00Z", "model": "m-live", "provider": "anthropic", "input_tokens": 5}], "provider-api", self.engine)
        asset_inventory.set_network_info("real-host", ip="10.55.0.1", engine=self.engine)
        with patch("remediation.enrichment.kev_epss.enrich_file"):
            out = service.load("admin@t.local", self.engine, self.fpath)
        self.assertTrue(all(r["ok"] for r in out["results"]), out)
        self.assertEqual({r["type"] for r in out["results"]}, set(renderers.RENDERERS))
        st = service.status(self.engine, self.fpath)
        self.assertGreater(st["simulated_usage_events"], 0)
        self.assertGreater(st["simulated_assets"], 0)
        res = service.remove("admin@t.local", self.engine, self.fpath)
        self.assertEqual(res["connections_removed"], len(renderers.RENDERERS))
        self.assertGreater(res["usage_events_removed"], 0)
        self.assertGreater(res["assets_removed"], 0)
        self.assertEqual([f["title"] for f in merge.load(self.fpath)], ["Real"])
        self.assertEqual([(x["model"], x["source_mode"]) for x in self.usage_rows()], [("m-live", None)])
        self.assertEqual(list(self.ownership_rows()), ["real-host"])
        st = service.status(self.engine, self.fpath)
        self.assertEqual((st["simulated_findings"], st["simulated_usage_events"], st["simulated_assets"]), (0, 0, 0))
        self.assertEqual(store.list_connections(self.engine), [])

    def test_remove_keeps_an_owner_someone_set_on_a_simulated_asset(self):
        with patch("remediation.enrichment.kev_epss.enrich_file"):
            service.load("admin@t.local", self.engine, self.fpath)
        name = self.estate.hosts[0]["fqdn"]
        asset_inventory.set_owner(name, "A. Person", "Real Team", engine=self.engine)
        service.remove("admin@t.local", self.engine, self.fpath)
        row = self.ownership_rows()[name]
        self.assertEqual((row["owner"], row["ip"], row["source_mode"]), ("A. Person", None, None))

    def test_the_loader_is_idempotent_across_all_ten_types(self):
        with patch("remediation.enrichment.kev_epss.enrich_file"):
            service.load("admin@t.local", self.engine, self.fpath)
            f, o, u = merge.load(self.fpath), self.ownership_rows(), len(self.usage_rows())
            again = service.load("admin@t.local", self.engine, self.fpath)
        self.assertTrue(all(r["ok"] for r in again["results"]))
        self.assertEqual(len(store.list_connections(self.engine)), 10)
        self.assertEqual((merge.load(self.fpath), self.ownership_rows(), len(self.usage_rows())), (f, o, u))
        self.assertTrue(all(c["name"].startswith("Simulated ") for c in store.list_connections(self.engine)))


class GateAndSecretsTests(MoreSyncBase):
    def test_prod_refuses_each_new_type_unless_explicitly_allowed(self):
        for t in NEW_TYPES:
            with self.subTest(t):
                with clean_env(QUANTA_ENV="prod"):
                    c = self.sim_connection(t)
                    r = sync.run(c["id"], "a", self.engine, self.fpath, enrich=False)
                    self.assertFalse(r["ok"])
                    self.assertIn("not allowed", r["message"])
                    with self.assertRaises(sync.SimulationRefused):
                        sync.test_connection(t, {"mode": "simulation"})
                with clean_env(QUANTA_ENV="prod", QUANTA_ALLOW_SIMULATION="true"):
                    self.assertTrue(sync.run(c["id"], "a", self.engine, self.fpath, enrich=False)["ok"])
        self.assertEqual(self.usage_rows() and {x["source_mode"] for x in self.usage_rows()}, {"simulation"})

    def test_no_secret_appears_in_any_result_stored_state_or_replay_log(self):
        fields = {"prismacloud": {"access_key_id": SECRETS[0], "secret_key": SECRETS[1]}, "cortex-xsiam": {"api_key": SECRETS[0], "api_key_id": SECRETS[2]},
                  "infoblox": {"username": "sim-user", "password": SECRETS[0]}, "axonius": {"api_key": SECRETS[0], "api_secret": SECRETS[1]},
                  "active-directory": {"bind_dn": "CN=sim,DC=corp,DC=test", "bind_password": SECRETS[0]}, "anthropic-usage": {"admin_key": SECRETS[0]},
                  "openai-usage": {"admin_key": SECRETS[1]}}
        sessions = []
        real = renderers.session_for

        def capture(t, values=None, estate=None):
            s = real(t, values, estate)
            sessions.append(s)
            return s
        results = []
        with patch.object(renderers, "session_for", side_effect=capture):
            for t in NEW_TYPES:
                c = store.create(f"Sim {t}", t, {"mode": "simulation", **fields[t]}, "a", engine=self.engine)
                results.append([sync.run(c["id"], "a", self.engine, self.fpath, enrich=False), store.get_public(c["id"], self.engine)])
        served = [getattr(s, "served", None) or getattr(s, "searches", None) for s in sessions]
        blob = json.dumps([results, served, merge.load(self.fpath), self.ownership_rows(), self.usage_rows()], default=str)
        for s in SECRETS:
            self.assertNotIn(s, blob)
        self.assertTrue(all(r[0]["ok"] for r in results), results)


if __name__ == "__main__":
    unittest.main()
