"""Tests for external attack surface management: tool output parsers, the delta store, scope rules and the finding rules (remediation/asm/)."""
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine  # noqa: E402

from remediation.asm import findings, parsers, store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

T0 = datetime.datetime(2026, 10, 1, 12, 0, tzinfo=datetime.timezone.utc)


def at(days=0, hours=0):
    return T0 + datetime.timedelta(days=days, hours=hours)


def jl(*objs):
    return "\n".join(json.dumps(o) for o in objs)


SUBFINDER = jl({"host": "www.example.com", "input": "example.com", "source": ["crtsh", "hackertarget"]}, {"host": "api.example.com", "input": "example.com", "source": ["crtsh"]},
               {"host": "old.example.com", "input": "example.com", "source": "alienvault"}, {"host": "other.net", "input": "other.net", "source": ["crtsh"]})
DNSX = jl({"host": "www.example.com", "a": ["203.0.113.10"], "cname": [], "status_code": "NOERROR"},
          {"host": "shop.example.com", "a": [], "cname": ["shop-demo.myshopify.com"], "status_code": "NXDOMAIN"},
          {"host": "api.example.com", "a": ["203.0.113.11"], "aaaa": ["2001:db8::1"], "status_code": "NOERROR"})
HTTPX = jl({"url": "https://www.example.com", "input": "www.example.com", "host": "203.0.113.10", "title": "Welcome", "status_code": 200, "tech": ["Nginx:1.18.0", "PHP:7.4.3"], "webserver": "nginx/1.18.0",
            "port": "443", "scheme": "https", "a": ["203.0.113.10"], "tls": {"not_after": "2026-10-10T00:00:00Z", "not_before": "2026-01-10T00:00:00Z", "subject_cn": "www.example.com", "issuer_cn": "Test CA",
                                                                       "self_signed": False, "expired": False, "mismatched": False, "fingerprint_hash": {"sha256": "aa"}}},
           {"url": "https://api.example.com:8443", "input": "api.example.com", "host": "203.0.113.11", "title": "Grafana", "status_code": 200, "tech": ["Grafana"], "port": "8443", "scheme": "https",
            "tls": {"self_signed": True, "not_after": "2027-01-01T00:00:00Z"}},
           {"url": "https://shop.example.com", "input": "shop.example.com", "title": "Not found", "status_code": 404, "port": "443", "scheme": "https"})
NAABU = jl({"ip": "203.0.113.10", "port": 443, "protocol": "tcp"}, {"ip": "203.0.113.10", "port": 22, "protocol": "tcp"}, {"ip": "203.0.113.11", "host": "api.example.com", "port": 3389, "protocol": "tcp"},
           {"ip": "198.51.100.5", "port": 445, "protocol": "tcp"})
NUCLEI = jl({"template-id": "CVE-2021-41773", "info": {"name": "Apache path traversal", "severity": "critical", "tags": ["cve", "apache"], "description": "Path traversal.",
                                                         "classification": {"cve-id": ["CVE-2021-41773"], "cvss-score": 9.8}}, "type": "http", "host": "https://www.example.com", "matched-at": "https://www.example.com/cgi-bin/x",
             "ip": "203.0.113.10"},
            {"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info", "tags": "tech"}, "host": "https://www.example.com", "matched-at": "https://www.example.com"})
SEEDS = "type,value\ndomain,example.com\ncidr,203.0.113.0/24\n"


def new_engine():
    tmp = tempfile.TemporaryDirectory()
    e = create_engine(f"sqlite:///{Path(tmp.name) / 'a.db'}")
    db_module.ensure_schema(e)
    return tmp, e


class ParserTests(unittest.TestCase):
    def test_each_tool_is_read(self):
        s = parsers.parse("subfinder", SUBFINDER)
        self.assertEqual([o["host"] for o in s["observations"]][:2], ["www.example.com", "api.example.com"])
        self.assertEqual(s["observations"][2]["found_by"], ["alienvault"])
        d = parsers.parse("dnsx", DNSX)["observations"]
        self.assertEqual((d[1]["cname"], d[1]["status"], d[2]["aaaa"]), (["shop-demo.myshopify.com"], "NXDOMAIN", ["2001:db8::1"]))
        h = parsers.parse("httpx", HTTPX)["observations"]
        self.assertEqual((h[0]["ip"], h[0]["port"], h[0]["tls"]["not_after"], h[0]["tls"]["fingerprint"]), ("203.0.113.10", 443, "2026-10-10", "aa"))
        self.assertEqual(h[1]["tls"]["self_signed"], True)
        n = parsers.parse("naabu", NAABU)["observations"]
        self.assertEqual((n[2]["ip"], n[2]["host"], n[2]["port"]), ("203.0.113.11", "api.example.com", 3389))
        u = parsers.parse("nuclei", NUCLEI)["observations"]
        self.assertEqual((u[0]["severity"], u[0]["cves"], u[0]["cvss"], u[0]["tags"]), ("critical", ["CVE-2021-41773"], 9.8, ["cve", "apache"]))
        self.assertEqual((u[1]["severity"], u[1]["tags"]), ("info", ["tech"]))

    def test_seeds_csv_with_or_without_header_and_bare_values(self):
        o = parsers.parse("seeds", "domain,Example.com\ncidr,203.0.113.0/24\n198.51.100.7\nexample.org\n")["observations"]
        self.assertEqual([(x["seed_kind"], x["value"]) for x in o], [("domain", "example.com"), ("cidr", "203.0.113.0/24"), ("cidr", "198.51.100.7/32"), ("domain", "example.org")])
        r = parsers.parse("seeds", "cidr,10.0.0.0/4\ndomain,ok.example.com")
        self.assertEqual(r["skipped"], 1)
        self.assertIn("too wide", r["errors"][0])

    def test_tolerant_of_missing_fields_and_bad_lines_and_arrays(self):
        r = parsers.parse("httpx", jl({"url": "https://a.example.com"}, {"nothing": 1}) + "\nnot json\n[1,2]\n")
        self.assertEqual((len(r["observations"]), r["skipped"]), (1, 3))
        self.assertIsNone(r["observations"][0]["tls"])
        arr = parsers.parse("subfinder", json.dumps([{"host": "a.example.com"}, "x"]))
        self.assertEqual((len(arr["observations"]), arr["skipped"]), (1, 1))

    def test_unknown_tool_empty_and_wrong_tool_output_are_clear_errors(self):
        with self.assertRaises(parsers.ParseError) as c:
            parsers.parse("nmap", "x")
        self.assertIn("subfinder", str(c.exception))
        with self.assertRaises(parsers.ParseError):
            parsers.parse("naabu", "")
        with self.assertRaises(parsers.ParseError) as c:
            parsers.parse("naabu", SUBFINDER)
        self.assertIn("No naabu records", str(c.exception))

    def test_size_and_record_caps(self):
        with self.assertRaises(parsers.ParseError):
            parsers.parse("subfinder", "x" * (parsers.MAX_BYTES + 1))
        many = "\n".join(json.dumps({"host": f"h{i}.example.com"}) for i in range(5))
        with self.assertRaises(parsers.ParseError) as c:
            parsers.parse("subfinder", many, max_records=3)
        self.assertIn("Too many records", str(c.exception))

    def test_product_version_never_guesses(self):
        self.assertEqual(parsers.product_version("nginx/1.18.0 (Ubuntu)"), ("nginx", "1.18.0"))
        self.assertEqual(parsers.product_version("PHP:7.4.3"), ("php", "7.4.3"))
        self.assertEqual(parsers.product_version("Apache HTTP Server:2.4.41"), ("apache", "2.4.41"))
        self.assertEqual(parsers.product_version("Nginx"), ("nginx", None))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.e = new_engine()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.e.dispose)

    def imp(self, tool, text, **kw):
        return store.import_text(tool, text, engine=self.e, now=kw.pop("now", at()), **kw)

    def keys(self, **kw):
        return {a["key"]: a for a in store.all_assets(self.e, **kw)}

    def test_import_builds_assets_with_stable_keys_and_is_idempotent(self):
        self.imp("seeds", SEEDS)
        r = self.imp("httpx", HTTPX)
        k = self.keys()
        self.assertIn("url:https://www.example.com", k)
        self.assertIn("url:https://api.example.com:8443", k)
        self.assertIn("service:203.0.113.10:443/tcp", k)
        self.assertIn("ip:203.0.113.10", k)
        self.assertIn("subdomain:www.example.com", k)
        self.assertIn("domain:example.com", k)
        self.assertGreater(r["new"], 5)
        again = self.imp("httpx", HTTPX, now=at(1))
        self.assertEqual((again["new"], again["changed"], again["disappeared"]), (0, 0, 0))
        self.assertEqual(self.keys()["url:https://www.example.com"]["first_seen"], "2026-10-01T12:00:00Z")
        self.assertEqual(self.keys()["url:https://www.example.com"]["last_seen"], "2026-10-02T12:00:00Z")

    def test_changed_when_a_technology_or_certificate_differs(self):
        self.imp("httpx", jl({"url": "https://www.example.com", "input": "www.example.com", "tech": ["Nginx"], "port": "443", "scheme": "https",
                              "tls": {"not_after": "2026-12-01", "issuer_cn": "A", "fingerprint_hash": {"sha256": "1"}}}))
        r = self.imp("httpx", jl({"url": "https://www.example.com", "input": "www.example.com", "tech": ["Nginx", "WordPress"], "port": "443", "scheme": "https",
                                  "tls": {"not_after": "2027-03-01", "issuer_cn": "B", "fingerprint_hash": {"sha256": "2"}}}), now=at(2))
        self.assertEqual(r["changed"], 1)
        ch = [c for c in store.list_changes(self.e) if c["change"] == "changed"][0]
        self.assertIn("new technology WordPress", ch["detail"])
        self.assertIn("certificate changed", ch["detail"])

    def test_a_new_port_is_a_new_service(self):
        self.imp("naabu", jl({"ip": "203.0.113.10", "port": 443}))
        r = self.imp("naabu", jl({"ip": "203.0.113.10", "port": 443}, {"ip": "203.0.113.10", "port": 3389}), now=at(1))
        self.assertEqual(r["new"], 1)
        self.assertEqual([c["asset_key"] for c in store.list_changes(self.e, change="new")][0], "service:203.0.113.10:3389/tcp")

    def test_disappeared_only_from_a_complete_import_by_a_tool_that_saw_it(self):
        self.imp("subfinder", SUBFINDER)
        partial = self.imp("subfinder", jl({"host": "www.example.com"}), now=at(1))
        self.assertEqual(partial["disappeared"], 0)
        # complete for the whole tool, but scoped to example.com: other.net is untouched
        done = self.imp("subfinder", jl({"host": "www.example.com"}), now=at(2), complete=True, scope_label="example.com")
        self.assertEqual(done["disappeared"], 2)
        k = self.keys()
        self.assertEqual((k["subdomain:api.example.com"]["status"], k["subdomain:other.net"]["status"]), ("gone", "active"))
        self.assertEqual(k["subdomain:api.example.com"]["gone_at"], "2026-10-03T12:00:00Z")
        self.assertEqual({c["change"] for c in store.list_changes(self.e, days=30, now=at(3))}, {"new", "disappeared"})
        # an asset a tool never saw cannot be made to disappear by that tool
        self.imp("naabu", jl({"ip": "198.51.100.5", "port": 445}), now=at(4))
        n = self.imp("subfinder", jl({"host": "www.example.com"}), now=at(5), complete=True)
        self.assertEqual(n["disappeared"], 1)  # other.net now, no service/ip asset
        self.assertEqual(self.keys()["service:198.51.100.5:445/tcp"]["status"], "active")

    def test_reappearing_is_reported_as_new_again(self):
        self.imp("subfinder", jl({"host": "a.example.com"}))
        self.imp("subfinder", jl({"host": "b.example.com"}), now=at(1), complete=True)
        self.assertEqual(self.keys()["subdomain:a.example.com"]["status"], "gone")
        r = self.imp("subfinder", jl({"host": "a.example.com"}), now=at(2))
        self.assertEqual(r["new"], 1)
        self.assertEqual(self.keys()["subdomain:a.example.com"]["status"], "active")
        self.assertIn("reappeared", [c["change"] for c in store.list_changes(self.e)])

    def test_complete_is_ignored_for_a_tool_that_cannot_speak_for_absence(self):
        self.imp("nuclei", NUCLEI)
        r = self.imp("nuclei", NUCLEI, complete=True, now=at(1))
        self.assertFalse(r["complete"])
        self.assertTrue(any("cannot make an asset disappear" in n for n in r["notes"]))

    def test_scope_flags_out_of_scope_and_never_silently_includes(self):
        self.imp("seeds", SEEDS)
        r = self.imp("subfinder", SUBFINDER)
        self.assertEqual(r["out_of_scope"], 1)
        k = self.keys()
        self.assertFalse(k["subdomain:other.net"]["in_scope"])
        self.assertTrue(k["subdomain:www.example.com"]["in_scope"])
        self.imp("naabu", NAABU, now=at(1))
        k = self.keys()
        self.assertTrue(k["ip:203.0.113.10"]["in_scope"])      # in the declared range
        self.assertFalse(k["ip:198.51.100.5"]["in_scope"])     # outside every range
        self.assertEqual(len(self.keys(in_scope=False)), 3)

    def test_an_address_seen_with_an_in_scope_name_is_in_scope(self):
        self.imp("seeds", "domain,example.com\n")
        self.imp("dnsx", jl({"host": "x.example.com", "a": ["192.0.2.50"]}))
        self.assertTrue(self.keys()["ip:192.0.2.50"]["in_scope"])

    def test_no_scope_means_everything_is_in_scope_and_says_so(self):
        r = self.imp("subfinder", SUBFINDER)
        self.assertFalse(r["scope_declared"])
        self.assertTrue(any("No scope is declared" in n for n in r["notes"]))
        self.assertTrue(all(a["in_scope"] for a in store.all_assets(self.e)))

    def test_changing_the_scope_recomputes_every_asset(self):
        self.imp("subfinder", SUBFINDER)
        out = store.set_scope(["example.com"], [], "admin", self.e, now=at())
        self.assertEqual(out["rescoped"], 1)
        self.assertFalse(self.keys()["subdomain:other.net"]["in_scope"])
        with self.assertRaises(ValueError):
            store.set_scope(["10.1.1.1"], [], None, self.e)
        with self.assertRaises(ValueError):
            store.set_scope([], ["0.0.0.0/0"], None, self.e)

    def test_ingest_may_not_declare_scope(self):
        with self.assertRaises(parsers.ParseError):
            store.import_text("seeds", SEEDS, engine=self.e, allow_seeds=False)

    def test_asset_cap_is_enforced(self):
        tool, obs = "subfinder", parsers.parse("subfinder", SUBFINDER)
        assets = {}
        run = store._Run(tool, assets, store.Scope(), "2026-10-01T00:00:00Z", max_assets=2)
        for o in obs["observations"]:
            run.host(o)
        self.assertEqual((len(assets), run.skipped_cap), (2, 2))

    def test_runs_and_change_feed_record_each_import(self):
        self.imp("subfinder", SUBFINDER)
        self.imp("subfinder", SUBFINDER, now=at(1))
        runs = store.list_runs(self.e)
        self.assertEqual([r["new_count"] for r in runs], [0, 4])

    def test_owner_joins_from_the_asset_inventory(self):
        from remediation.inventory import asset_inventory
        self.imp("subfinder", SUBFINDER)
        asset_inventory.set_owner("www.example.com", "Pat", "Web", engine=self.e)
        row = [a for a in store.list_assets(self.e)["assets"] if a["value"] == "www.example.com"][0]
        self.assertEqual((row["owner"], row["team"]), ("Pat", "Web"))


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.e = new_engine()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.e.dispose)
        store.import_text("seeds", SEEDS, engine=self.e, now=at())
        for tool, text in (("subfinder", SUBFINDER), ("dnsx", DNSX), ("httpx", HTTPX), ("naabu", NAABU), ("nuclei", NUCLEI)):
            store.import_text(tool, text, engine=self.e, now=at())

    def run_rules(self, known=None, days=0, **kw):
        return findings.evaluate(store.all_assets(self.e), known if known is not None else {"inventory-host"}, now=at(days), **kw)

    def by_rule(self, res, rule):
        return [f for f in res["findings"] if f["rule"] == rule]

    def test_nuclei_findings_carry_cve_cvss_evidence_and_next_step(self):
        res = self.run_rules()
        n = self.by_rule(res, "ASM-NUCLEI")
        self.assertEqual(len(n), 1)
        self.assertEqual((n[0]["severity"], n[0]["cve"], n[0]["cvss"]), ("Critical", "CVE-2021-41773", 9.8))
        self.assertIn("cgi-bin", n[0]["evidence"])
        self.assertIn("CVE-2021-41773", n[0]["next_step"])
        self.assertEqual(res["skipped_info"], 1)

    def test_info_results_can_be_included_by_policy(self):
        pol = findings.policy()
        pol["nuclei"]["include_info"] = True
        self.assertEqual(len(self.by_rule(self.run_rules(pol=pol), "ASM-NUCLEI")), 2)

    def test_risky_ports_and_ssh(self):
        res = self.run_rules()
        titles = {f["title"]: f for f in self.by_rule(res, "ASM-PORT")}
        self.assertIn("RDP exposed on api.example.com", titles)
        self.assertEqual(titles["RDP exposed on api.example.com"]["severity"], "High")
        ssh = [f for f in titles.values() if f["title"].startswith("SSH")][0]
        self.assertEqual(ssh["severity"], "Medium")  # the same host serves a website
        self.assertNotIn("SMB exposed on 198.51.100.5", titles)  # out of scope: recorded, never judged
        self.assertFalse(any("198.51.100.5" in f["title"] for f in res["findings"]))

    def test_tls_rules(self):
        res = self.run_rules(days=5)
        near = [f for f in self.by_rule(res, "ASM-TLS") if "expiring" in f["title"]]
        self.assertEqual((len(near), near[0]["severity"], near[0]["asset_type"]), (1, "Low", "certificate"))
        self.assertIn("in 4 days", near[0]["evidence"])
        later = self.run_rules(days=20)
        self.assertTrue(any("expired" in f["title"] and f["severity"] == "Medium" for f in self.by_rule(later, "ASM-TLS")))
        self.assertTrue(any("self-signed" in f["title"] for f in self.by_rule(res, "ASM-TLS")))

    def test_takeover_looking_cname_is_a_name_match_and_says_so(self):
        t = self.by_rule(self.run_rules(), "ASM-TAKEOVER")
        self.assertEqual(len(t), 1)
        self.assertEqual((t[0]["severity"], t[0]["asset"]), ("High", "shop.example.com"))
        self.assertIn("name match", t[0]["evidence"])
        self.assertIn("Shopify", t[0]["title"])

    def test_a_healthy_provider_cname_is_not_flagged(self):
        store.import_text("dnsx", jl({"host": "ok.example.com", "a": ["203.0.113.50"], "cname": ["x.github.io"], "status_code": "NOERROR"}), engine=self.e, now=at())
        self.assertEqual(len(self.by_rule(self.run_rules(), "ASM-TAKEOVER")), 1)

    def test_management_interface(self):
        m = self.by_rule(self.run_rules(), "ASM-MGMT")
        self.assertEqual([f["asset"] for f in m], ["api.example.com"])
        self.assertIn("grafana", m[0]["evidence"])

    def test_outdated_technology_only_where_a_version_is_reported(self):
        t = self.by_rule(self.run_rules(), "ASM-TECH")
        titles = sorted(f["title"] for f in t)
        self.assertEqual(len(t), 2)
        self.assertTrue(any(x.startswith("nginx 1.18.0") for x in titles))
        self.assertTrue(any(x.startswith("php 7.4.3") for x in titles))
        store.import_text("httpx", jl({"url": "https://nov.example.com", "input": "nov.example.com", "tech": ["Nginx", "PHP"], "port": "443", "scheme": "https"}), engine=self.e, now=at())
        self.assertEqual(len(self.by_rule(self.run_rules(), "ASM-TECH")), 2)

    def test_shadow_assets_need_an_inventory_and_say_so_otherwise(self):
        res = self.run_rules(known=set())
        self.assertEqual(self.by_rule(res, "ASM-SHADOW"), [])
        self.assertTrue(any("no asset inventory" in g.lower() for g in res["gaps"]))
        res = self.run_rules(known={"www.example.com", "203.0.113.10"})
        shadow = {f["asset"] for f in self.by_rule(res, "ASM-SHADOW")}
        self.assertNotIn("www.example.com", shadow)
        self.assertIn("api.example.com", shadow)
        self.assertNotIn("203.0.113.10", shadow)

    def test_missing_tools_are_listed_as_gaps_not_as_a_clean_result(self):
        tmp, e = new_engine()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(e.dispose)
        store.import_text("subfinder", SUBFINDER, engine=e, now=at())
        res = findings.evaluate(store.all_assets(e), {"x"}, now=at())
        self.assertEqual(self.by_rule(res, "ASM-PORT"), [])
        self.assertEqual(len([g for g in res["gaps"] if g.startswith("No ")]), 3)  # httpx, naabu and nuclei
        self.assertTrue(any("naabu" in g for g in res["gaps"]))

    def test_gone_and_out_of_scope_assets_raise_nothing(self):
        store.import_text("naabu", jl({"ip": "203.0.113.10", "port": 23}), engine=self.e, now=at(1))
        self.assertTrue(any("Telnet" in f["title"] for f in self.run_rules()["findings"]))
        store.import_text("naabu", jl({"ip": "203.0.113.10", "port": 443}), engine=self.e, now=at(2), complete=True)
        assets = {a["key"]: a for a in store.all_assets(self.e)}
        self.assertEqual(assets["service:203.0.113.10:23/tcp"]["status"], "gone")
        self.assertFalse(any("Telnet" in f["title"] for f in self.run_rules()["findings"]))

    def test_per_rule_cap_keeps_the_highest_severity(self):
        pol = findings.policy()
        pol["max_findings_per_rule"] = 1
        res = self.run_rules(pol=pol)
        self.assertEqual(len(self.by_rule(res, "ASM-PORT")), 1)
        self.assertEqual(self.by_rule(res, "ASM-PORT")[0]["severity"], "High")
        self.assertTrue(any(c.startswith("ASM-PORT") for c in res["capped"]))

    def test_queue_items_carry_the_data_age_and_validate(self):
        from remediation.ingest import api_findings
        items = findings.to_queue_items(self.run_rules(days=3)["findings"])
        good, bad = api_findings.normalise_batch(items)
        self.assertEqual(bad, [])
        self.assertEqual(len(good), len(items))
        nuclei = [g for g in good if g["rule_id"] == "ASM-NUCLEI"][0]
        self.assertEqual((nuclei["cve"], nuclei["scan_type"], nuclei["tool"]), ("CVE-2021-41773", "dast", "quanta-asm"))
        self.assertIn("Last observed 2026-10-01 (3 days ago)", nuclei["description"])
        self.assertIn("Quanta did not scan", nuclei["description"])
        self.assertEqual({g["scan_type"] for g in good if g["rule_id"] == "ASM-TLS"}, {"cert-mgmt"})

    def test_known_assets_ignore_asm_own_findings(self):
        k = findings.known_assets([{"source": "asm", "asset": {"name": "x.example.com"}}, {"source": "tenable", "asset": {"name": "WEB-1", "ip": "10.0.0.1"}}], {"Owned": {"ip": "10.0.0.2"}})
        self.assertEqual(k, {"web-1", "10.0.0.1", "owned", "10.0.0.2"})


class StaleDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.e = new_engine()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.e.dispose)

    def test_no_cadence_never_stale_but_age_is_shown(self):
        store.import_text("subfinder", SUBFINDER, engine=self.e, now=at())
        a = store.data_age(self.e, at(10))
        self.assertFalse(a["stale"])
        self.assertEqual(a["age_hours"], 240.0)
        self.assertIn("No expected import cadence", a["message"])

    def test_stale_when_past_the_cadence_and_never_implied_clean(self):
        store.set_cadence_hours(24, self.e)
        store.import_text("subfinder", SUBFINDER, engine=self.e, now=at())
        self.assertFalse(store.data_age(self.e, at(hours=23))["stale"])
        a = store.data_age(self.e, at(2))
        self.assertTrue(a["stale"])
        self.assertIn("out of date, not as clean", a["message"])

    def test_cadence_set_with_nothing_imported_is_stale(self):
        store.set_cadence_hours(24, self.e)
        a = store.data_age(self.e, at())
        self.assertTrue(a["stale"] and a["never_imported"])

    def test_one_alert_per_stale_episode_then_again_after_a_new_import(self):
        from remediation.hunting import store as hunt_store
        store.set_cadence_hours(24, self.e)
        store.import_text("subfinder", SUBFINDER, engine=self.e, now=at())
        self.assertIsNone(store.check_stale(self.e, at(hours=5)))
        first = store.check_stale(self.e, at(3))
        self.assertIsNotNone(first)
        self.assertEqual(first["title"], "Stale attack-surface data")
        self.assertIsNone(store.check_stale(self.e, at(4)))
        store.import_text("subfinder", SUBFINDER, engine=self.e, now=at(5))
        self.assertIsNotNone(store.check_stale(self.e, at(9)))
        self.assertEqual(len([a for a in hunt_store.list_alerts(self.e) if a["source"] == "asm"]), 2)

    def test_cadence_validation(self):
        with self.assertRaises(ValueError):
            store.set_cadence_hours(0.2, self.e)
        with self.assertRaises(ValueError):
            store.set_cadence_hours("soon", self.e)
        self.assertIsNone(store.set_cadence_hours(None, self.e))


if __name__ == "__main__":
    unittest.main()
