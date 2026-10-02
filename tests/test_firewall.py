"""
Tests for firewall rules management: parsing exports, analysis, exposure, recertification and change requests.
"""
import datetime
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
from remediation.firewall import analysis, model, store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
TODAY = datetime.date(2026, 10, 15)

CSV = """Name,Source Zone,Destination Zone,Source Address,Destination Address,Service,Action,Log,Hit Count,Last Hit,Created,Owner,Comment
allow-web,untrust,dmz,any,10.1.1.10,tcp/443;tcp/80,allow,yes,5000,2026-10-10,2025-01-01,web-team,public site
allow-rdp-in,untrust,dmz,any,10.1.1.20,rdp,allow,no,0,,2024-01-01,,
deny-bad,trust,untrust,10.9.9.9,any,any,deny,yes,3,2026-10-01,2024-01-01,netops,
allow-bad-shadowed,trust,untrust,10.9.9.9,8.8.8.8,tcp/53,allow,yes,0,,2025-01-01,netops,
allow-all,trust,untrust,any,any,any,allow,yes,100,2026-10-14,2024-01-01,netops,outbound
legacy-app,trust,dmz,10.2.0.0/16,10.1.1.50,tcp/8080,allow,yes,,,2024-01-01,netops,
"""

PANOS = """<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules>
<entry name="web-in"><from><member>untrust</member></from><to><member>dmz</member></to><source><member>any</member></source><destination><member>10.1.1.10</member></destination>
<application><member>ssl</member></application><service><member>tcp/443</member></service><action>allow</action><log-end>yes</log-end><tag><member>web-team</member></tag></entry>
<entry name="legacy"><from><member>trust</member></from><to><member>dmz</member></to><source><member>10.0.0.0/8</member></source><destination><member>any</member></destination>
<service><member>application-default</member></service><application><member>ssh</member></application><action>deny</action><disabled>yes</disabled></entry>
</rules></security></rulebase></entry></vsys></entry></devices></config>"""

FORTI = """config firewall policy
    edit 1
        set name "wan-to-web"
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "web-server"
        set action accept
        set schedule "always"
        set service "HTTPS" "HTTP"
        set logtraffic all
        set comments "public web"
    next
    edit 2
        set name "block-rest"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "ALL"
        set status disable
    next
end
"""


def rule(position, **kw):
    base = {"device": "fw1", "key": f"r{position}", "position": position, "name": f"rule-{position}", "action": "allow", "enabled": True, "log": True, "src_zones": ["any"], "dst_zones": ["any"],
            "sources": ["10.0.0.0/24"], "destinations": ["10.1.0.5/32"], "services": ["tcp/443"], "hits": None, "last_hit": None, "created": None, "modified": None, "owner": "team", "comment": None,
            "expires": None}
    base.update(kw)
    return base


def ids(findings, key=None):
    return sorted({f["id"] for f in findings if key is None or f["rule_key"] == key})


class ModelTests(unittest.TestCase):
    def test_normalisers(self):
        self.assertEqual([model.norm_service(x) for x in ("HTTPS", "tcp/443", "443", "udp:53", "TCP-1000-2000", "ALL", "weird-app")], ["tcp/443", "tcp/443", "tcp/443", "udp/53", "tcp/1000-2000", "any", "weird-app"])
        self.assertEqual([model.norm_address(x) for x in ("ANY", "0.0.0.0/0", "10.1.1.7", "10.0.0.0/8", "web-server", "2001:db8::1")], ["any", "any", "10.1.1.7/32", "10.0.0.0/8", "web-server", "2001:db8::1/128"])

    def test_generic_csv_with_common_headers(self):
        rs = model.from_csv(CSV, "fw1")
        self.assertEqual(len(rs), 6)
        web = rs[0]
        self.assertEqual((web["name"], web["action"], web["services"], web["hits"], web["last_hit"], web["owner"], web["log"]), ("allow-web", "allow", ["tcp/443", "tcp/80"], 5000, "2026-10-10", "web-team", True))
        self.assertEqual(rs[1]["services"], ["tcp/3389"])
        self.assertIsNone(rs[1]["owner"])
        self.assertEqual((rs[5]["hits"], rs[0 + 3]["action"]), (None, "allow"))
        self.assertEqual(rs[2]["action"], "deny")

    def test_csv_errors(self):
        for bad in ("", "Name,Source\na,b\n", "Name,Action\n"):
            with self.assertRaises(model.RuleFormatError):
                model.from_csv(bad, "fw1")
        with self.assertRaises(model.RuleFormatError):
            model.from_csv("Name,Action\nx,maybe\n", "fw1")

    def test_json(self):
        rs = model.from_json(json.dumps({"rules": [{"name": "a", "action": "permit", "sources": ["10.0.0.0/8"], "destinations": "any", "services": "ssh"}]}), "fw1")
        self.assertEqual((rs[0]["action"], rs[0]["services"], rs[0]["destinations"]), ("allow", ["tcp/22"], ["any"]))
        for bad in ("nope", "[]", '{"rules": []}'):
            with self.assertRaises(model.RuleFormatError):
                model.from_json(bad, "fw1")

    def test_panos_xml(self):
        rs = model.from_panos_xml(PANOS, "pa1")
        self.assertEqual([r["name"] for r in rs], ["web-in", "legacy"])
        self.assertEqual((rs[0]["src_zones"], rs[0]["sources"], rs[0]["owner"], rs[0]["log"]), (["untrust"], ["any"], "web-team", True))
        self.assertEqual((rs[1]["enabled"], rs[1]["action"], rs[1]["services"]), (False, "deny", ["tcp/22"]))  # application ssh is read as its well-known port
        with self.assertRaises(model.RuleFormatError):
            model.from_panos_xml("<a/>", "pa1")
        with self.assertRaises(model.RuleFormatError):
            model.from_panos_xml("not xml", "pa1")

    def test_fortigate_text(self):
        rs = model.from_fortigate(FORTI, "fg1")
        self.assertEqual([r["name"] for r in rs], ["wan-to-web", "block-rest"])
        self.assertEqual((rs[0]["src_zones"], rs[0]["sources"], rs[0]["services"], rs[0]["log"], rs[0]["action"]), (["wan1"], ["any"], ["tcp/443", "tcp/80"], True, "allow"))
        self.assertEqual((rs[1]["enabled"], rs[1]["action"], rs[1]["services"]), (False, "deny", ["any"]))
        with self.assertRaises(model.RuleFormatError):
            model.from_fortigate("nothing here", "fg1")

    def test_format_detection(self):
        self.assertEqual(model.detect_and_parse(PANOS, "d")[1], "panos")
        self.assertEqual(model.detect_and_parse(FORTI, "d")[1], "fortigate")
        self.assertEqual(model.detect_and_parse('[{"action":"allow"}]', "d")[1], "json")
        self.assertEqual(model.detect_and_parse(CSV, "d")[1], "csv")
        with self.assertRaises(model.RuleFormatError):
            model.detect_and_parse("x", "d", "yaml")


class ContainmentTests(unittest.TestCase):
    def test_addresses(self):
        self.assertTrue(analysis.addr_covers(["any"], ["10.1.1.1/32"]))
        self.assertTrue(analysis.addr_covers(["10.0.0.0/8"], ["10.1.2.3/32", "10.4.0.0/16"]))
        self.assertFalse(analysis.addr_covers(["10.0.0.0/8"], ["192.168.0.1/32"]))
        self.assertFalse(analysis.addr_covers(["10.0.0.0/8"], ["any"]))
        self.assertTrue(analysis.addr_covers(["web-servers"], ["web-servers"]))  # an object compared by name
        self.assertFalse(analysis.addr_covers(["web-servers"], ["app-servers"]))

    def test_services(self):
        self.assertTrue(analysis.service_covers(["tcp/1000-2000"], ["tcp/1500", "tcp/1000-1100"]))
        self.assertFalse(analysis.service_covers(["tcp/1000-2000"], ["udp/1500"]))
        self.assertFalse(analysis.service_covers(["tcp/443"], ["any"]))
        self.assertTrue(analysis.service_covers(["any"], ["tcp/443"]))


class AnalysisTests(unittest.TestCase):
    def a(self, *rules):
        return analysis.analyse(list(rules), analysis.policy(), TODAY)

    def test_allow_everything(self):
        f = self.a(rule(1, sources=["any"], destinations=["any"], services=["any"], src_zones=["trust"], dst_zones=["untrust"]))
        self.assertIn("FW001", ids(f))
        self.assertEqual(f[0]["severity"], "Critical")

    def test_internet_exposure_of_risky_ports_needs_an_internet_facing_source(self):
        facing = self.a(rule(1, sources=["any"], src_zones=["untrust"], services=["tcp/3389", "tcp/443"]))
        self.assertIn("FW002", ids(facing))
        self.assertIn("3389 (RDP)", [f for f in facing if f["id"] == "FW002"][0]["detail"])
        internal = self.a(rule(1, sources=["any"], src_zones=["trust"], services=["tcp/3389"]))
        self.assertNotIn("FW002", ids(internal))  # any source from an inside zone is not the internet
        anyzone = self.a(rule(1, sources=["any"], src_zones=["any"], services=["tcp/22"]))
        self.assertIn("FW002", ids(anyzone))
        self.assertIn("FW003", self.a(rule(1, sources=["any"], src_zones=["wan1"], services=["any"])).__repr__() and ids(self.a(rule(1, sources=["any"], src_zones=["wan1"], services=["any"]))))

    def test_broad_service_or_destination_between_specific_peers(self):
        self.assertIn("FW004", ids(self.a(rule(1, services=["any"]))))
        self.assertIn("FW005", ids(self.a(rule(1, destinations=["any"]))))
        self.assertNotIn("FW004", ids(self.a(rule(1, sources=["any"], services=["any"], destinations=["any"]))))  # that is FW001

    def test_cleartext_logging_and_owner(self):
        f = self.a(rule(1, services=["tcp/21", "tcp/443"], log=False, owner=None))
        self.assertTrue({"FW006", "FW007", "FW012"} <= set(ids(f)))
        self.assertNotIn("FW007", ids(self.a(rule(1, action="deny", log=False))))  # only allow rules must log

    def test_unused_rules_need_evidence_and_age(self):
        self.assertIn("FW008", ids(self.a(rule(1, hits=0, created="2025-01-01"))))
        self.assertIn("FW008", ids(self.a(rule(1, hits=50, last_hit="2026-01-01", created="2025-01-01"))))
        self.assertNotIn("FW008", ids(self.a(rule(1, hits=0, created="2026-10-01"))))  # too new to judge
        self.assertNotIn("FW008", ids(self.a(rule(1, hits=None, last_hit=None, created="2024-01-01"))))  # the device did not say

    def test_disabled_and_expired(self):
        self.assertIn("FW009", ids(self.a(rule(1, enabled=False, modified="2026-01-01"))))
        self.assertNotIn("FW009", ids(self.a(rule(1, enabled=False, modified="2026-10-01"))))
        self.assertIn("FW013", ids(self.a(rule(1, expires="2026-09-01"))))
        self.assertNotIn("FW013", ids(self.a(rule(1, expires="2027-01-01"))))
        self.assertNotIn("FW013", ids(self.a(rule(1, expires="2026-09-01", enabled=False))))

    def test_shadowed_and_redundant(self):
        deny = rule(1, action="deny", sources=["10.0.0.0/24"], destinations=["any"], services=["any"])
        shadowed = rule(2, action="allow", sources=["10.0.0.5/32"], destinations=["8.8.8.8/32"], services=["tcp/53"])
        redundant = rule(3, action="deny", sources=["10.0.0.9/32"], destinations=["1.1.1.1/32"], services=["tcp/53"])
        f = self.a(deny, shadowed, redundant)
        self.assertEqual(ids(f, "r2"), ["FW010"] if "FW010" in ids(f, "r2") else ids(f, "r2"))
        self.assertIn("FW010", ids(f, "r2"))
        self.assertIn("FW011", ids(f, "r3"))
        self.assertNotIn("FW010", ids(f, "r1"))
        later_specific = self.a(rule(1, sources=["10.0.0.5/32"]), rule(2, sources=["10.0.0.0/24"]))
        self.assertEqual({f_["id"] for f_ in later_specific if f_["rule_key"] == "r2"} & {"FW010", "FW011"}, set())  # a broader rule after a narrower one is not shadowed
        disabled_first = self.a(rule(1, enabled=False, sources=["any"], destinations=["any"], services=["any"]), rule(2))
        self.assertTrue({"FW010", "FW011"}.isdisjoint(ids(disabled_first, "r2")))

    def test_each_device_is_its_own_order(self):
        f = self.a(rule(1, device="a", action="deny", sources=["any"], destinations=["any"], services=["any"]), rule(1, device="b", key="b1"))
        self.assertTrue({"FW010", "FW011"}.isdisjoint(ids(f, "b1")))

    def test_findings_are_ordered_worst_first_and_summarised(self):
        rs = [rule(1, sources=["any"], destinations=["any"], services=["any"]), rule(2, log=False)]
        f = analysis.analyse(rs, analysis.policy(), TODAY)
        self.assertEqual(f[0]["severity"], "Critical")
        s = analysis.summary(rs, f)
        self.assertEqual((s["rules"], s["devices"][0]["allow"]), (2, 2))
        self.assertGreaterEqual(s["devices"][0]["score"], 10)

    def test_the_csv_sample_produces_the_expected_findings(self):
        rs = model.from_csv(CSV, "fw1")
        f = analysis.analyse(rs, analysis.policy(), TODAY)
        self.assertIn("FW002", ids(f, "allow-rdp-in"))
        self.assertTrue({"FW007", "FW008", "FW012"} <= set(ids(f, "allow-rdp-in")))
        self.assertIn("FW010", ids(f, "allow-bad-shadowed"))  # the deny above it already decides that traffic
        self.assertIn("FW001", ids(f, "allow-all"))


class ExposureTests(unittest.TestCase):
    def test_ports_the_internet_can_reach(self):
        rs = [rule(1, sources=["any"], src_zones=["untrust"], services=["tcp/443", "tcp/3389"], hits=0, created="2025-01-01"), rule(2, sources=["any"], src_zones=["untrust"], services=["any"], destinations=["10.1.1.9/32"]),
              rule(3, sources=["any"], src_zones=["trust"], services=["tcp/22"]), rule(4, sources=["any"], src_zones=["untrust"], services=["tcp/8080"], enabled=False)]
        e = analysis.exposure(rs, pol=analysis.policy(), today=TODAY)
        ports = {p["port"]: p for p in e["ports"]}
        self.assertEqual(set(ports), {443, 3389})
        self.assertTrue(ports[3389]["risky"] and not ports[443]["risky"])
        self.assertEqual(e["ports"][0]["port"], 3389)  # risky first
        self.assertEqual((e["risky_exposed"], len(e["wide_open_rules"])), (1, 1))


class RequestCheckTests(unittest.TestCase):
    RULES = [rule(1, action="deny", sources=["10.66.0.0/16"], destinations=["any"], services=["any"], name="quarantine"),
             rule(2, action="allow", sources=["10.0.0.0/16"], destinations=["10.1.1.0/24"], services=["tcp/443"], name="app-https")]

    def chk(self, **kw):
        req = {"sources": ["10.0.5.5"], "destinations": ["10.1.1.9"], "services": ["tcp/9000"], "days": 14}
        req.update(kw)
        return analysis.check_request(req, self.RULES, analysis.policy())

    def test_already_allowed_blocked_or_new(self):
        a = self.chk(services=["tcp/443"])
        self.assertEqual((a["verdict"], a["decided_by"]["rule"], a["auto_approvable"]), ("already-allowed", "app-https", False))
        b = self.chk(sources=["10.66.1.1"])
        self.assertEqual((b["verdict"], b["decided_by"]["rule"]), ("blocked-by-rule", "quarantine"))
        c = self.chk()
        self.assertEqual((c["verdict"], c["decided_by"]), ("needs-new-rule", None))

    def test_a_zone_specific_rule_decides_only_when_the_request_names_the_zones(self):
        zoned = [rule(1, name="dmz-https", sources=["10.0.0.0/16"], destinations=["10.1.1.0/24"], services=["tcp/9000"], src_zones=["trust"], dst_zones=["dmz"])]
        req = {"sources": ["10.0.5.5"], "destinations": ["10.1.1.9"], "services": ["tcp/9000"], "days": 7}
        loose = analysis.check_request(req, zoned, analysis.policy())
        self.assertEqual((loose["verdict"], loose["auto_approvable"], loose["possible_rules"][0]["rule"]), ("needs-new-rule", False, "dmz-https"))
        self.assertIn("would match if the traffic crosses their zones", " ".join(loose["reasons"]))
        exact = analysis.check_request({**req, "src_zone": "trust", "dst_zone": "dmz"}, zoned, analysis.policy())
        self.assertEqual((exact["verdict"], exact["decided_by"]["rule"]), ("already-allowed", "dmz-https"))
        wrong = analysis.check_request({**req, "src_zone": "dmz", "dst_zone": "trust"}, zoned, analysis.policy())
        self.assertEqual(wrong["verdict"], "needs-new-rule")

    def test_risk_and_automatic_approval(self):
        low = self.chk()
        self.assertEqual((low["risk"], low["auto_approvable"]), ("low", True))
        self.assertEqual(self.chk(days=None)["risk"], "medium")
        self.assertEqual(self.chk(days=90)["risk"], "medium")
        self.assertFalse(self.chk(days=90)["auto_approvable"])
        for kw in ({"sources": ["any"]}, {"destinations": ["any"]}, {"services": ["any"]}, {"services": ["tcp/3389"]}, {"services": ["tcp/1-60000"]}):
            r = self.chk(**kw)
            self.assertEqual((r["risk"], r["auto_approvable"]), ("high", False), kw)
        many = self.chk(sources=[f"10.0.5.{i}" for i in range(1, 9)])
        self.assertEqual((many["risk"], many["auto_approvable"]), ("medium", False))

    def test_topology_context_is_attached_for_named_destinations(self):
        topo = {"assets": [{"match": {"name": "web-1"}, "path_to_internet": [{"hop_type": "firewall", "name": "edge", "default_action": "deny"}]}]}
        r = analysis.check_request({"sources": ["10.0.5.5"], "destinations": ["web-1"], "services": ["tcp/443"], "days": 7}, self.RULES, analysis.policy(), topo)
        self.assertEqual(r["path"][0]["asset"], "web-1")
        self.assertIn("verdict", r["path"][0])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def imp(self, text=CSV, device="fw1", day=1):
        return store.import_rules(device, text, None, "a", self.e, now=datetime.datetime(2026, 1, day, tzinfo=datetime.timezone.utc))

    def test_import_replaces_a_device_and_counts_changes(self):
        r = self.imp()
        self.assertEqual((r["format"], r["rules"], r["added"], r["removed"]), ("csv", 6, 6, 0))
        r2 = self.imp(CSV.replace("legacy-app", "new-rule"))
        self.assertEqual((r2["added"], r2["removed"]), (1, 1))
        self.assertEqual(len(store.rules("fw1", self.e)), 6)
        self.imp(PANOS, "pa1")
        self.assertEqual(store.devices(self.e), ["fw1", "pa1"])
        self.assertEqual(store.delete_device("pa1", self.e), 2)
        for bad in ("", "x" * 3):
            with self.assertRaises(model.RuleFormatError):
                store.import_rules("fw1", bad, None, "a", self.e)
        with self.assertRaises(model.RuleFormatError):
            store.import_rules("  ", CSV, None, "a", self.e)

    def test_duplicate_names_are_kept_apart(self):
        rs = [{"name": "dup", "action": "allow"}, {"name": "dup", "action": "deny"}]
        store.import_rules("fw1", json.dumps(rs), "json", "a", self.e)
        self.assertEqual(sorted(r["key"] for r in store.rules("fw1", self.e)), ["dup", "dup#2"])

    def test_certification_survives_a_reimport_only_while_the_rule_is_unchanged(self):
        self.imp(day=1)
        store.certify("fw1", "allow-web", "keep", "", "owner@t", self.e, now=datetime.datetime(2026, 2, 1, tzinfo=datetime.timezone.utc))
        self.imp(day=5)
        web = next(r for r in store.rules("fw1", self.e) if r["key"] == "allow-web")
        self.assertEqual((web["certified_by"], web["decision"], web["first_seen"]), ("owner@t", "keep", "2026-01-01"))
        self.imp(CSV.replace("tcp/443;tcp/80", "tcp/443;tcp/80;tcp/8443"), day=9)
        web = next(r for r in store.rules("fw1", self.e) if r["key"] == "allow-web")
        self.assertEqual((web["certified_by"], web["first_seen"]), (None, "2026-01-09"))  # changed, so it is a new rule to certify

    def test_certify_validation(self):
        self.imp()
        for args in (("fw1", "allow-web", "approve", ""), ("fw1", "allow-web", "remove", ""), ("fw1", "allow-web", "modify", "  ")):
            with self.assertRaises(ValueError):
                store.certify(*args, "a", self.e)
        with self.assertRaises(KeyError):
            store.certify("fw1", "nope", "keep", "", "a", self.e)

    def test_recertification_states(self):
        self.imp(day=1)
        store.certify("fw1", "allow-web", "keep", "", "o", self.e, now=datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc))
        store.certify("fw1", "allow-rdp-in", "remove", "Not needed", "o", self.e)
        store.certify("fw1", "allow-all", "modify", "Narrow it", "o", self.e)
        st = store.recert_status(store.rules("fw1", self.e), analysis.policy(), datetime.date(2027, 3, 1))
        states = {r["rule"]: r["state"] for r in st["rules"]}
        self.assertEqual(states["allow-web"], "current")
        self.assertEqual(states["allow-rdp-in"], "removal-requested")
        self.assertEqual(states["allow-all"], "change-requested")
        self.assertEqual(states["allow-bad-shadowed"], "overdue")  # first seen 2026-01-01, due 2027-01-01, grace over by 2027-03-01
        self.assertNotIn("deny-bad", states)  # only enabled allow rules are recertified
        soon = store.recert_status(store.rules("fw1", self.e), analysis.policy(), datetime.date(2026, 12, 20))
        self.assertEqual({r["rule"]: r["state"] for r in soon["rules"]}["allow-bad-shadowed"], "due-soon")

    def test_request_lifecycle_and_metrics(self):
        self.imp()
        rules = store.rules(None, self.e)
        t0 = datetime.datetime(2026, 10, 1, 9, tzinfo=datetime.timezone.utc)
        loose = store.submit_request("u@t", ["10.0.5.5"], ["10.1.1.9"], ["tcp/9000"], 7, "Report job", rules, engine=self.e, now=t0)
        self.assertFalse(loose["check"]["auto_approvable"])  # a zone-specific allow-all might apply, so a person looks first
        self.assertEqual(loose["check"]["possible_rules"][0]["rule"], "allow-all")
        r = store.submit_request("u@t", ["10.0.5.5"], ["10.1.1.9"], ["tcp/9000"], 7, "Report job", [], engine=self.e, now=t0)
        self.assertEqual((r["status"], r["check"]["verdict"], r["check"]["auto_approvable"]), ("submitted", "needs-new-rule", True))
        with self.assertRaises(ValueError):
            store.decide_request(r["id"], "implemented", "a", "", self.e)  # not approved yet
        with self.assertRaises(ValueError):
            store.decide_request(r["id"], "rejected", "a", " ", self.e)
        ap = store.decide_request(r["id"], "approved", "a@t", "ok", self.e, now=t0 + datetime.timedelta(hours=3))
        self.assertEqual(ap["decided_by"], "a@t")
        im = store.decide_request(r["id"], "implemented", "a@t", "", self.e, now=t0 + datetime.timedelta(hours=27))
        self.assertTrue(im["implemented_at"])
        m = store.request_metrics(store.list_requests(self.e))
        self.assertEqual((m["total"], m["median_hours_to_decision"], m["median_hours_to_implemented"], m["by_status"]["implemented"]), (2, 3.0, 27.0, 1))
        with self.assertRaises(ValueError):
            store.decide_request(r["id"], "approved", "a", "", self.e)
        for bad in (dict(sources=[], destinations=["x"], services=["y"], days=1, justification="why"), dict(sources=["a"], destinations=["x"], services=["y"], days=0, justification="why"),
                    dict(sources=["a"], destinations=["x"], services=["y"], days=1, justification=" ")):
            with self.assertRaises(ValueError):
                store.submit_request("u", bad["sources"], bad["destinations"], bad["services"], bad["days"], bad["justification"], rules, engine=self.e)

    def test_approving_a_request_a_deny_rule_blocks_needs_a_note(self):
        self.imp()
        store.import_rules("core", json.dumps([{"name": "quarantine", "action": "deny", "sources": ["10.9.9.0/24"], "destinations": "any", "services": "any"}]), "json", "a", self.e)
        r = store.submit_request("u@t", ["10.9.9.9"], ["8.8.4.4"], ["tcp/53"], 7, "dns", store.rules(None, self.e), engine=self.e)
        self.assertEqual(r["check"]["verdict"], "blocked-by-rule")
        with self.assertRaises(ValueError):
            store.decide_request(r["id"], "approved", "a", "", self.e)
        store.decide_request(r["id"], "approved", "a", "Order of rules will be changed", self.e)


class FirewallApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        auth_users.create_user("other@t.local", PW, "Other", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def test_who_can_do_what(self):
        for method, path in (("get", "/api/firewall/overview"), ("get", "/api/firewall/rules"), ("get", "/api/firewall/requests")):
            self.assertEqual(getattr(self.client, method)(path).status_code, 401, path)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/firewall/overview").status_code, 403)
        self.assertEqual(self.client.post("/api/firewall/import?device=fw1", content=CSV).status_code, 403)
        self.assertEqual(self.client.get("/api/firewall/requests").status_code, 200)

    def test_import_overview_certify_and_delete(self):
        self.login("admin@t.local")
        r = self.client.post("/api/firewall/import?device=fw1", content=CSV)
        self.assertEqual((r.status_code, r.json()["rules"]), (200, 6), r.text)
        self.assertEqual(self.client.post("/api/firewall/import?device=fw1&format=json", content="nope").status_code, 400)
        ov = self.client.get("/api/firewall/overview").json()
        self.assertGreater(ov["summary"]["by_severity"]["Critical"], 0)
        self.assertEqual(ov["devices"], ["fw1"])
        self.assertTrue(ov["exposure"]["risky_exposed"] >= 1)
        self.assertEqual(self.client.post("/api/firewall/certify", json={"device": "fw1", "key": "allow-web", "decision": "keep"}).status_code, 200)
        self.assertEqual(self.client.post("/api/firewall/certify", json={"device": "fw1", "key": "allow-web", "decision": "remove"}).status_code, 400)
        self.assertEqual(self.client.post("/api/firewall/certify", json={"device": "fw1", "key": "nope", "decision": "keep"}).status_code, 404)
        self.assertEqual(len(self.client.get("/api/firewall/rules?device=fw1").json()["rules"]), 6)
        self.assertEqual(self.client.delete("/api/firewall/devices/fw1").status_code, 200)
        self.assertEqual(self.client.delete("/api/firewall/devices/fw1").status_code, 404)

    def test_a_user_asks_for_access_and_sees_only_their_own_requests(self):
        self.login("admin@t.local")
        self.client.post("/api/firewall/import?device=fw1", content=CSV)
        self.login("user@t.local")
        body = {"sources": ["10.0.5.5"], "destinations": ["10.1.1.9"], "services": ["tcp/9000"], "days": 7, "justification": "Nightly report job"}
        r = self.client.post("/api/firewall/requests", json=body)
        self.assertEqual((r.status_code, r.json()["check"]["verdict"], r.json()["check"]["risk"]), (200, "needs-new-rule", "low"), r.text)
        self.assertEqual(self.client.post("/api/firewall/requests", json={**body, "justification": ""}).status_code, 400)
        self.assertEqual(len(self.client.get("/api/firewall/requests").json()["requests"]), 1)
        self.login("other@t.local")
        self.assertEqual(self.client.get("/api/firewall/requests").json()["requests"], [])
        self.assertEqual(self.client.post("/api/firewall/requests/1/decide", json={"status": "approved"}).status_code, 403)
        self.login("admin@t.local")
        self.assertEqual(len(self.client.get("/api/firewall/requests").json()["requests"]), 1)
        d = self.client.post("/api/firewall/requests/1/decide", json={"status": "approved", "note": "ok"})
        self.assertEqual((d.status_code, d.json()["status"]), (200, "approved"))
        self.assertEqual(self.client.post("/api/firewall/requests/1/decide", json={"status": "bogus"}).status_code, 400)
        self.assertEqual(self.client.post("/api/firewall/requests/99/decide", json={"status": "approved"}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
