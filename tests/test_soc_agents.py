"""
Tests for the SOC agents: the SIEM search and reputation connectors, OCSF intake, threat-intelligence intake, hunt execution and verdicts,
the L1 alert investigation, detection engineering, and their API.
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
from remediation.connections import registry, store as conn_store, sync as conn_sync  # noqa: E402
from remediation.connectors import reputation_connector as rep, siem_search_connector as sec  # noqa: E402
from remediation.hunting import detection, generate, intel, ocsf, service, soc, store, verdict  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
NOW = datetime.datetime(2026, 10, 15, 12, 0, tzinfo=datetime.timezone.utc)
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}


def fnd(i, host="WEB-1", cve="CVE-2021-44228", kev=True, tech=(T1190,)):
    return {"id": f"FIND-{i}", "title": f"Vuln {cve}", "cve": cve, "severity": "Critical", "asset": {"name": host}, "attack_techniques": list(tech),
            "kev": {"listed": True} if kev else None, "epss": {"score": 0.9}}


class FakeResp:
    def __init__(self, data=None, status=200):
        self._d, self.status_code = data if data is not None else {}, status

    def json(self):
        return self._d

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"{self.status_code}")


class FakeSplunk:
    """Just enough of Splunk's search REST API."""
    def __init__(self, count=3, done_after=1, fail=False):
        self.headers, self.auth, self.verify, self.calls = {}, None, True, []
        self.count, self.done_after, self.fail, self.polls = count, done_after, fail, 0

    def post(self, url, data=None, timeout=None):
        self.calls.append(("POST", url, data))
        if url.endswith("/services/search/jobs"):
            return FakeResp({"sid": "S1"})
        return FakeResp({})

    def get(self, url, params=None, timeout=None):
        self.calls.append(("GET", url, params))
        if url.endswith("/services/server/info"):
            return FakeResp({"entry": [{"content": {"serverName": "splunk-1", "version": "9.1"}}]})
        if url.endswith("/results"):
            return FakeResp({"results": [{"host": "WEB-1", "_time": "t", "_secret": "x", "big": "y" * 400} for _ in range(params["count"])]})
        self.polls += 1
        state = "FAILED" if self.fail else "DONE"
        return FakeResp({"entry": [{"content": {"isDone": self.polls > self.done_after, "dispatchState": state if self.polls > self.done_after else "RUNNING", "resultCount": self.count}}]})


class SearchConnectorTests(unittest.TestCase):
    def test_only_read_only_searches_are_sent(self):
        sec.check_query('search host="A" Image="*cmd.exe"')
        sec.check_query('search host="A" | stats count by host')
        for bad in ('index=main', 'search a | delete', 'search a | outputlookup x', 'search a | script x', 'search a |  Run foo', "search `macro`", "search " + "a" * 7000):
            with self.assertRaises(sec.SearchRefused, msg=bad):
                sec.check_query(bad)

    def test_search_flow_counts_clips_and_caps_rows(self):
        fake = FakeSplunk(count=500)
        c = sec.SplunkSearchConnector("https://s:8089/", token="tok", session=fake, sleep=lambda s: None)
        self.assertEqual(fake.headers["Authorization"], "Bearer tok")
        r = c.search('search host="A"', max_rows=1000)
        self.assertEqual((r["count"], len(r["rows"]), r["truncated"]), (500, 100, True))  # hard cap
        self.assertNotIn("_secret", r["rows"][0])
        self.assertLessEqual(len(r["rows"][0]["big"]), 300)
        post = next(x for x in fake.calls if x[0] == "POST")
        self.assertEqual(post[2]["earliest_time"], "-24h")

    def test_zero_results_makes_no_results_call_and_failure_and_deadline_are_errors(self):
        fake = FakeSplunk(count=0)
        r = sec.SplunkSearchConnector("https://s", token="t", session=fake, sleep=lambda s: None).search("search a")
        self.assertEqual((r["count"], r["rows"]), (0, []))
        self.assertFalse(any(x[1].endswith("/results") for x in fake.calls))
        with self.assertRaises(sec.SiemSearchError):
            sec.SplunkSearchConnector("https://s", token="t", session=FakeSplunk(fail=True), sleep=lambda s: None).search("search a")
        ticks = iter(range(0, 1000, 50))
        slow = FakeSplunk(done_after=10**6)
        with self.assertRaises(sec.SiemSearchError):
            sec.SplunkSearchConnector("https://s", token="t", session=slow, sleep=lambda s: None, clock=lambda: next(ticks)).search("search a", deadline=60)
        self.assertTrue(any("control" in x[1] for x in slow.calls))  # the slow search was cancelled

    def test_credentials_and_test_connection(self):
        with self.assertRaises(ValueError):
            sec.SplunkSearchConnector("https://s")
        fake = FakeSplunk()
        c = sec.SplunkSearchConnector("https://s", username="u", password="p", verify_tls=False, session=fake)
        self.assertEqual((fake.auth, fake.verify), (("u", "p"), False))
        self.assertEqual(c.test_connection(), {"server": "splunk-1", "version": "9.1"})


class FakeVT:
    def __init__(self, status=200, stats=None):
        self.headers, self.status, self.stats, self.urls = {}, status, stats if stats is not None else {"malicious": 12, "suspicious": 1, "harmless": 60, "undetected": 10}, []

    def get(self, url, timeout=None):
        self.urls.append(url)
        return FakeResp({"data": {"attributes": {"last_analysis_stats": self.stats}}}, self.status)


class ReputationTests(unittest.TestCase):
    def test_only_public_indicators_are_classified(self):
        self.assertEqual(rep.classify("8.8.8.8"), ("ip", "8.8.8.8"))
        for private in ("10.1.1.1", "192.168.0.5", "127.0.0.1", "169.254.1.1", "0.0.0.0", ""):
            self.assertEqual(rep.classify(private), (None, None), private)
        self.assertEqual(rep.classify("EVIL.Example.COM"), ("domain", "evil.example.com"))
        self.assertEqual(rep.classify("A" * 64)[0], "hash")
        self.assertEqual(rep.classify("http://x.example/a?b=1")[0], "url")
        self.assertEqual(rep.classify("not an indicator"), (None, None))

    def test_lookup_counts_unknown_rate_limit_and_key_errors(self):
        fake = FakeVT()
        c = rep.ReputationConnector("k", session=fake)
        self.assertEqual(fake.headers["x-apikey"], "k")
        r = c.lookup("8.8.8.8")
        self.assertEqual((r["result"], r["malicious"], r["total"]), ("seen", 12, 83))
        self.assertTrue(fake.urls[0].endswith("/ip_addresses/8.8.8.8"))
        c.lookup("http://x.example/")
        self.assertNotIn("=", fake.urls[1].rsplit("/", 1)[1])  # url id is unpadded base64
        self.assertEqual(c.lookup("10.0.0.1")["result"], "skipped")
        self.assertEqual(rep.ReputationConnector("k", session=FakeVT(status=404)).lookup("8.8.4.4")["result"], "unknown")
        with self.assertRaises(rep.ReputationError):
            rep.ReputationConnector("k", session=FakeVT(status=429)).lookup("8.8.4.4")
        with self.assertRaises(rep.ReputationError):
            rep.ReputationConnector("k", session=FakeVT(status=401)).lookup("8.8.4.4")
        with self.assertRaises(ValueError):
            rep.ReputationConnector("")


class OcsfTests(unittest.TestCase):
    EVENT = {"class_uid": 2004, "severity_id": 5, "time": 1790000000000, "finding_info": {"uid": "f-1", "title": "Shell from w3wp", "desc": "beacon to 185.220.101.9 and evil.example.com",
                                                                                        "analytic": {"name": "Web shell spawn"}, "attacks": [{"technique": {"uid": "t1190"}}]},
             "device": {"hostname": "WEB-1", "ip": "10.0.0.5"}, "user": {"name": "svc-web"}, "resources": [{"name": "WEB-1"}],
             "evidences": [{"src_endpoint": {"ip": "45.33.32.7"}, "file": {"hashes": [{"value": "A" * 64}]}}]}

    def test_maps_the_fields_quanta_uses(self):
        a = ocsf.map_detection_finding(self.EVENT)
        self.assertEqual((a["external_id"], a["severity"], a["rule_name"], a["technique"], a["asset"]), ("f-1", "Critical", "Web shell spawn", "T1190", "WEB-1"))
        self.assertTrue(a["occurred_at"].startswith("2026-"))
        e = a["entities"]
        self.assertEqual((e["host"], e["user"]), ("WEB-1", "svc-web"))
        self.assertIn("45.33.32.7", e["ips"])
        self.assertIn("185.220.101.9", e["ips"])
        self.assertIn("evil.example.com", e["domains"])
        self.assertIn("a" * 64, e["hashes"])

    def test_severity_mapping_and_errors(self):
        for sid, name in ((1, "Informational"), (2, "Low"), (3, "Medium"), (4, "High"), (6, "Critical")):
            self.assertEqual(ocsf.map_detection_finding({"finding_info": {"uid": "x", "title": "t"}, "severity_id": sid})["severity"], name)
        self.assertEqual(ocsf.map_detection_finding({"finding_info": {"uid": "x", "title": "t"}, "severity_id": 0})["severity"], "Medium")
        for bad in ({}, {"finding_info": {"uid": "x"}}, "nope"):
            with self.assertRaises(ValueError):
                ocsf.map_detection_finding(bad)

    def test_alert_entities_are_stored_and_read_back(self):
        e = create_engine("sqlite:///:memory:")
        a, _ = store.receive_alert({**ocsf.map_detection_finding(self.EVENT), "source": "x"}, e)
        self.assertEqual(a["rule_name"], "Web shell spawn")
        self.assertEqual(a["entities"]["user"], "svc-web")
        plain, _ = store.receive_alert({"source": "x", "external_id": "2", "title": "Beacon to 185.220.101.9", "asset": "H"}, e)
        self.assertEqual((plain["entities"]["host"], plain["entities"]["ips"]), ("H", ["185.220.101.9"]))


STIX = {"type": "bundle", "objects": [
    {"type": "report", "name": "Edge exploitation campaign"}, {"type": "intrusion-set", "name": "APT29"},
    {"type": "vulnerability", "name": "CVE-2021-44228"}, {"type": "attack-pattern", "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]},
    {"type": "indicator", "pattern": "[ipv4-addr:value = '185.220.101.9'] OR [ipv4-addr:value = '10.1.1.1'] OR [domain-name:value = 'evil.example.com']"}]}
TEXT = "Advisory: actor APT41 is exploiting CVE-2021-44228 and CVE-2099-0001 (T1190, T1059.001). C2 at 45.33.32.4 and http://bad.example.net/x, sha256 " + "b" * 64


class IntelTests(unittest.TestCase):
    def test_text_extraction(self):
        ex = intel.extract(TEXT)
        self.assertEqual(ex["cves"], ["CVE-2021-44228", "CVE-2099-0001"])
        self.assertEqual(ex["techniques"], ["T1059.001", "T1190"])
        self.assertEqual((ex["actors"], ex["ips"], ex["hashes"]), (["APT41"], ["45.33.32.4"], ["b" * 64]))
        self.assertIn("http://bad.example.net/x", ex["urls"])
        self.assertTrue(ex["title"].startswith("Advisory"))

    def test_stix_extraction_drops_private_addresses(self):
        ex = intel.extract(json.dumps(STIX))
        self.assertEqual((ex["format"], ex["title"], ex["actors"], ex["cves"], ex["techniques"]), ("stix", "Edge exploitation campaign", ["APT29"], ["CVE-2021-44228"], ["T1190"]))
        self.assertEqual(ex["ips"], ["185.220.101.9"])
        self.assertIn("evil.example.com", ex["domains"])

    def test_relevance_scoring_and_priority(self):
        ex = intel.extract(TEXT)
        score, prio, reasons, m = intel.relevance(ex, [fnd(1)])
        self.assertEqual((score, prio), (40 + 10 + 25 + 15 + 10, "high"))
        self.assertEqual((m["cves"], m["hosts"], m["kev"]), (["CVE-2021-44228"], ["WEB-1"], ["CVE-2021-44228"]))
        s2, p2, r2, _ = intel.relevance(intel.extract("Nothing useful here"), [fnd(1)])
        self.assertEqual((s2, p2), (0, "low"))
        self.assertIn("Nothing in the report", r2[0])
        s3, p3, *_ = intel.relevance(ex, [fnd(1, cve="CVE-2020-0001", tech=())])
        self.assertEqual((s3, p3), (25, "low"))  # no CVE or technique match: only the library entry (15) and the indicators (10)
        s4, p4, *_ = intel.relevance(ex, [fnd(1, cve="CVE-2020-0001")])
        self.assertEqual((s4, p4), (50, "medium"))  # a technique match without a CVE match

    def test_proposed_hunt_has_library_queries_and_an_ioc_sweep(self):
        ex = intel.extract(TEXT)
        rel = intel.relevance(ex, [fnd(1)])
        h = intel.propose_hunt(ex, rel, rel[3]["hosts"])
        techs = {q["technique"] for q in h["queries"]}
        self.assertTrue({"T1190", "T1059", "IOC"} <= techs)
        sweep = next(q for q in h["queries"] if q["technique"] == "IOC")
        self.assertIn("45.33.32.4", sweep["query"])
        self.assertIn('host="WEB-1"', sweep["query"])
        self.assertEqual(h["source"], "intel")
        self.assertIn("APT41", h["hypothesis"])

    def test_same_content_is_stored_once(self):
        e = create_engine("sqlite:///:memory:")
        ex = intel.extract(TEXT)
        score, prio, reasons, _ = intel.relevance(ex, [])
        rid, created = service.save_intel(ex["title"], "feed", intel.content_hash(TEXT), ex, score, prio, reasons, "a", e)
        rid2, created2 = service.save_intel(ex["title"], "feed", intel.content_hash(TEXT), ex, score, prio, reasons, "a", e)
        self.assertEqual((rid, created, rid2, created2), (rid, True, rid, False))
        self.assertEqual(service.get_intel(rid, e)["extracted"]["cves"], ex["cves"])


class FakeSearch:
    def __init__(self, count=2, rows=None, boom=False):
        self.count, self.rows, self.boom, self.queries = count, rows if rows is not None else [{"host": "WEB-1"}, {"host": "WEB-2"}], boom, []

    def search(self, query, earliest="-24h", max_rows=25):
        self.queries.append((query, earliest))
        if self.boom:
            raise sec.SiemSearchError("timeout")
        return {"count": self.count, "rows": self.rows, "truncated": False, "sid": "S"}


class HuntRunAndVerdictTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        self.h = store.create_hunt(generate.propose([fnd(1), fnd(2, host="WEB-2", cve="CVE-2021-44228")])[0], "a", self.e)

    def test_running_a_lead_records_count_sample_and_activates_the_hunt(self):
        fs = FakeSearch()
        q = service.run_hunt_query(self.h["id"], 0, fs, "-7d", engine=self.e)
        self.assertEqual((q["result"], q["count"], q["window"]), ("hits", 2, "-7d"))
        got = store.get_hunt(self.h["id"], self.e)
        self.assertEqual((got["status"], got["queries"][0]["sample"][0]["host"]), ("active", "WEB-1"))
        self.assertEqual(fs.queries[0][1], "-7d")
        self.assertEqual(service.run_hunt_query(self.h["id"], 0, FakeSearch(count=0, rows=[]), engine=self.e)["result"], "no-hits")

    def test_a_failed_search_is_recorded_and_raised(self):
        with self.assertRaises(sec.SiemSearchError):
            service.run_hunt_query(self.h["id"], 0, FakeSearch(boom=True), engine=self.e)
        q = store.get_hunt(self.h["id"], self.e)["queries"][0]
        self.assertEqual((q["result"], q["error"]), ("error", "timeout"))
        with self.assertRaises(IndexError):
            service.run_hunt_query(self.h["id"], 99, FakeSearch(), engine=self.e)
        with self.assertRaises(KeyError):
            service.run_hunt_query(999, 0, FakeSearch(), engine=self.e)

    def test_lead_and_overall_verdicts(self):
        lv = verdict.lead_verdict
        self.assertEqual([lv({"result": r, "assessment": a}) for r, a in ((None, None), ("error", None), ("no-hits", None), ("hits", "benign"), ("hits", None), ("hits", "suspicious"), ("hits", "malicious"))],
                         ["not-run", "not-run", "no-hits", "likely-fp", "possible-tp", "possible-tp", "confirmed-tp"])
        ov = lambda qs: verdict.hunt_verdict({"queries": qs})["overall"]  # noqa: E731
        hit = lambda a=None, host="H": {"result": "hits", "assessment": a, "sample": [{"host": host}]}  # noqa: E731
        self.assertEqual(ov([]), "incomplete")
        self.assertEqual(ov([{"result": None}]), "incomplete")
        self.assertEqual(ov([{"result": "no-hits"}, hit("benign")]), "no-findings")
        self.assertEqual(ov([hit("suspicious", "A"), {"result": "no-hits"}]), "low-confidence")
        self.assertEqual(ov([hit(None, "A"), hit(None, "B")]), "multi-hit-correlated")
        self.assertEqual(ov([hit("suspicious", "A"), hit("suspicious", "A")]), "multi-hit-correlated")
        self.assertEqual(ov([hit("benign", "A"), hit("malicious", "B")]), "confirmed-compromise")
        v = verdict.hunt_verdict({"queries": [hit("suspicious", "A"), hit("suspicious", "A")]})
        self.assertEqual(v["correlated_entities"], ["host:a"])

    def test_lead_assessment_is_validated_and_reports_escape_html(self):
        with self.assertRaises(ValueError):
            store.update_hunt(self.h["id"], {"queries": [{"result": "hits", "assessment": "scary"}]}, self.e)
        h = store.get_hunt(self.h["id"], self.e)
        h["title"] = "<script>alert(1)</script>"
        h["notes"] = "saw <b>x</b>"
        page = verdict.to_html(h)
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)
        md = verdict.to_markdown(h)
        self.assertIn("Hunt verdict: incomplete", md)
        self.assertIn(h["queries"][0]["query"], md)


def mk_alert(e, i, rule="Rule A", host="WEB-1", sev="High", disp=None, tech="T1190", closed_days_ago=2, detail="", entities=None):
    a, _ = store.receive_alert({"source": "siem", "external_id": str(i), "title": f"Alert {i} shell", "severity": sev, "asset": host, "technique": tech,
                                "rule_name": rule, "detail": detail, "entities": entities}, e)
    if disp:
        store.update_alert(a["id"], {"status": "closed", "disposition": disp}, e)
        t = db_module.soc_alerts
        stamp = (NOW - datetime.timedelta(days=closed_days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
        recv = (NOW - datetime.timedelta(days=closed_days_ago, hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with e.begin() as c:
            c.execute(t.update().where(t.c.id == a["id"]).values(closed_at=stamp, received_at=recv))
    return store.get_alert(a["id"], e)


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        self.cfg = soc.config()

    def run_inv(self, alert, findings=(), lookup=None, siem_run=None):
        return soc.investigate(alert, store.list_alerts(self.e), list(findings), {}, lookup=lookup, siem_run=siem_run, cfg=self.cfg, now=NOW)

    def test_classification(self):
        self.assertEqual(soc.classify({"technique": "T1059.001"}), "endpoint")
        self.assertEqual(soc.classify({"technique": "T1190"}), "network")
        self.assertEqual(soc.classify({"title": "Suspicious login from new country"}), "identity")
        self.assertEqual(soc.classify({"title": "xyz"}), "other")

    def test_flagged_indicator_plus_exposed_host_is_a_likely_true_positive(self):
        a = mk_alert(self.e, 1, detail="beacon to 185.220.101.9")
        inv = self.run_inv(a, [fnd(1)], lookup=lambda v: {"result": "seen", "malicious": 15, "total": 80})
        self.assertEqual(inv["verdict"], "likely-true-positive")
        self.assertEqual(inv["confidence"], "high")
        self.assertTrue(inv["signals"]["ioc_malicious"] and inv["signals"]["kev_match"])
        self.assertTrue(any("185.220.101.9" in r for r in inv["reasons"]))

    def test_threshold_is_per_category(self):
        a = mk_alert(self.e, 1, tech="T1059", detail="x 185.220.101.9")  # endpoint needs 20 engines
        inv = self.run_inv(a, lookup=lambda v: {"result": "seen", "malicious": 15, "total": 80})
        self.assertFalse(inv["signals"]["ioc_malicious"])
        self.assertEqual((inv["threshold"], inv["verdict"]), (20, "escalate-l2"))

    def test_a_noisy_rule_with_clean_indicators_is_a_likely_false_positive(self):
        for i in range(10):
            mk_alert(self.e, 100 + i, disp="false-positive")
        a = mk_alert(self.e, 1, detail="to 8.8.8.8")
        inv = self.run_inv(a, lookup=lambda v: {"result": "seen", "malicious": 0, "total": 80})
        self.assertEqual(inv["verdict"], "likely-false-positive")
        self.assertTrue(inv["signals"]["rule_noise_history"] and inv["signals"]["clean_indicators"])

    def test_critical_is_never_called_a_false_positive_and_thin_evidence_escalates(self):
        for i in range(10):
            mk_alert(self.e, 100 + i, disp="false-positive")
        crit = mk_alert(self.e, 1, sev="Critical")
        self.assertEqual(self.run_inv(crit)["verdict"], "escalate-l2")
        quiet = mk_alert(self.e, 2, rule="Never seen", sev="Medium")
        inv = self.run_inv(quiet)
        self.assertEqual((inv["verdict"], inv["confidence"]), ("escalate-l2", "low"))
        self.assertIn("goes to a person", inv["reasons"][0])

    def test_recurrence_and_prior_benign_history(self):
        mk_alert(self.e, 50, rule="Rule B", host="DB-1", disp="true-positive", closed_days_ago=1)
        inv = self.run_inv(mk_alert(self.e, 51, rule="Rule B", host="DB-1", sev="Critical"))
        self.assertTrue(inv["signals"]["recurrence"])
        self.assertEqual(inv["verdict"], "likely-true-positive")  # recurrence 2 + critical 1 = 3
        mk_alert(self.e, 60, rule="Rule C", host="H", disp="benign")
        self.assertTrue(self.run_inv(mk_alert(self.e, 61, rule="Rule C", host="H"))["signals"]["prior_benign_same_host"])

    def test_lookup_failure_and_missing_connection_are_said_not_guessed(self):
        a = mk_alert(self.e, 1, detail="x 185.220.101.9")
        def boom(v):
            raise rep.ReputationError("rate limited")
        inv = self.run_inv(a, lookup=boom)
        self.assertIn("unavailable", inv["lookup_note"])
        self.assertFalse(inv["signals"]["ioc_malicious"] or inv["signals"]["clean_indicators"])
        self.assertIn("No reputation connection", self.run_inv(a)["lookup_note"])

    def test_siem_evidence_corroborates_and_failures_are_reported(self):
        a = mk_alert(self.e, 1)
        ok = self.run_inv(a, siem_run=lambda q, earliest: {"count": 4, "rows": [{"host": "WEB-1"}]})
        self.assertTrue(ok["signals"]["siem_corroboration"])
        self.assertTrue(ok["siem_evidence"] and 'host="WEB-1"' in ok["siem_evidence"][0]["query"])
        def fail(q, earliest):
            raise RuntimeError("down")
        bad = self.run_inv(a, siem_run=fail)
        self.assertFalse(bad["signals"]["siem_corroboration"])
        self.assertEqual(bad["siem_evidence"][0]["error"], "down")

    def test_report_names_the_verdict_and_says_a_person_validates(self):
        a = mk_alert(self.e, 1, detail="x 185.220.101.9")
        inv = self.run_inv(a, [fnd(1)], lookup=lambda v: {"result": "seen", "malicious": 15, "total": 80})
        md = soc.render_markdown(a, inv)
        self.assertIn("Recommended verdict: likely-true-positive", md)
        self.assertIn("A person validates this", md)
        self.assertIn("| 185.220.101.9 | ip | seen | 15 of 80 |", md)
        iid = service.save_investigation(inv, md, "a", self.e)
        self.assertEqual(service.latest_investigation(a["id"], self.e)["id"], iid)


SIGMA = """title: Suspicious shell from web server
id: 11111111-1111-1111-1111-111111111111
logsource: {product: windows, category: process_creation}
tags: [attack.execution, attack.t1059.001, attack.t1190]
detection:
  selection:
    ParentImage|endswith: '\\w3wp.exe'
  condition: selection
---
title: Second rule
detection:
  sel: {a: 1}
  condition: sel
"""


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        self.pol = detection.policy()

    def alerts(self, rule, tp=0, benign=0, fp=0, hosts=("H1",)):
        n = 0
        for disp, count in (("true-positive", tp), ("benign", benign), ("false-positive", fp)):
            for _ in range(count):
                n += 1
                mk_alert(self.e, f"{rule}-{n}", rule=rule, host=hosts[n % len(hosts)], disp=disp)

    def test_sigma_parsing(self):
        rules = detection.parse_sigma(SIGMA)
        self.assertEqual([r["name"] for r in rules], ["Suspicious shell from web server", "Second rule"])
        self.assertEqual(rules[0]["techniques"], ["T1059.001", "T1190"])
        self.assertEqual(rules[0]["platform"], "sigma:windows/process_creation")
        for bad in ("- just a list", "title: x", "a: [unclosed"):
            with self.assertRaises(ValueError):
                detection.parse_sigma(bad)

    def test_health_tiers(self):
        m = lambda decided, tp, benign, fp: {"decided": decided, "tp": tp, "benign": benign, "fp": fp,  # noqa: E731
                                              "tp_rate": tp / decided if decided else 0, "noise_rate": (benign + fp) / decided if decided else 0}
        t = lambda *a: detection.tier(m(*a), self.pol)  # noqa: E731
        self.assertEqual(t(4, 4, 0, 0), "low_volume")
        self.assertEqual(t(10, 9, 0, 1), "high_fidelity")
        self.assertEqual(t(10, 0, 9, 1), "low_value")
        self.assertEqual(t(40, 2, 0, 38), "critical_noise")
        self.assertEqual(t(10, 2, 0, 8), "noisy")
        self.assertEqual(t(10, 6, 0, 4), "healthy")
        self.assertEqual(t(10, 0, 2, 8), "noisy")  # mostly false positive, not mostly benign

    def test_recommendations(self):
        self.assertEqual(detection.recommendation("healthy", {"tp": 3}, self.pol), "maintain")
        self.assertEqual(detection.recommendation("noisy", {"tp": 3}, self.pol), "tune")
        self.assertEqual(detection.recommendation("low_value", {"tp": 0}, self.pol), "disable")
        self.assertEqual(detection.recommendation("critical_noise", {"tp": 0}, self.pol), "disable")
        self.assertEqual(detection.recommendation("critical_noise", {"tp": 2}, self.pol), "tune")

    def test_assessment_orders_by_urgency_and_finds_the_noisy_host(self):
        self.alerts("Noisy rule", tp=2, fp=8, hosts=("NOISY-1", "NOISY-1", "NOISY-1", "OTHER"))
        self.alerts("Good rule", tp=9, fp=1)
        self.alerts("Tiny rule", tp=1)
        rules = [detection.upsert_rule(r["name"], r["platform"], r["logic"], r["techniques"], "sigma", True, self.e) for r in detection.parse_sigma(SIGMA)]
        detection.upsert_rule("Noisy rule", "sigma:windows/process_creation", SIGMA.split("---")[0].replace("Suspicious shell from web server", "Noisy rule"), ["T1190"], "sigma", True, self.e)
        a = detection.assess(store.list_alerts(self.e), detection.list_rules(self.e), [fnd(1), fnd(2, tech=({"technique_id": "T1068", "technique_name": "Priv esc", "tactic": "x"},))], self.pol, NOW)
        by = {r["rule"]: r for r in a["rules"]}
        self.assertEqual(by["Noisy rule"]["metrics"]["tier"], "noisy")
        self.assertEqual(by["Good rule"]["metrics"]["tier"], "high_fidelity")
        self.assertEqual(by["Tiny rule"]["metrics"]["tier"], "low_volume")
        self.assertEqual(a["rules"][0]["rule"], "Noisy rule")  # most urgent first
        tu = by["Noisy rule"]["tuning"]
        self.assertEqual(tu["exclude_hosts"], ["NOISY-1"])
        self.assertIn("filter_known_benign", tu["after"])
        self.assertNotIn("filter_known_benign", tu["before"])
        self.assertIn("not filter_known_benign", tu["after"])
        self.assertGreater(tu["estimated_noise_reduction"], 0.5)
        self.assertEqual(a["tier_counts"]["noisy"], 1)
        self.assertEqual(len(rules), 2)

    def test_no_exclusion_is_suggested_without_a_dominant_host(self):
        self.alerts("Spread rule", tp=2, fp=8, hosts=("A", "B", "C", "D", "E", "F", "G", "H"))
        a = detection.assess(store.list_alerts(self.e), [], [], self.pol, NOW)
        self.assertIsNone(a["rules"][0]["tuning"])

    def test_old_alerts_fall_outside_the_window(self):
        for i in range(6):
            mk_alert(self.e, f"old-{i}", rule="Old rule", disp="false-positive", closed_days_ago=200)
        a = detection.assess(store.list_alerts(self.e), [], [], self.pol, NOW)
        self.assertEqual(a["rules"], [])

    def test_coverage_gaps_against_the_estate(self):
        detection.upsert_rule("Covers 1190", techniques=["T1190.001"], engine=self.e)
        detection.upsert_rule("Disabled covers 1068", techniques=["T1068"], enabled=False, engine=self.e)
        findings = [fnd(1), fnd(2, tech=({"technique_id": "T1068", "technique_name": "Priv esc", "tactic": "x"}, {"technique_id": "T9999", "technique_name": "Odd", "tactic": "x"}))]
        c = detection.coverage(detection.list_rules(self.e), findings)
        self.assertEqual((c["estate_techniques"], c["estate_covered"], c["pct"]), (3, 1, 33))
        self.assertEqual({g["technique_id"]: g["hunt_queries"] for g in c["gaps"]}, {"T1068": True, "T9999": False})

    def test_snapshots_history_and_reports(self):
        self.alerts("Noisy rule", tp=2, fp=8, hosts=("NOISY-1",))
        a = detection.assess(store.list_alerts(self.e), [], [], self.pol, NOW)
        detection.save_assessment(a, "me", self.e)
        detection.save_assessment(a, "me", self.e)
        self.assertEqual(len(detection.list_assessments(self.e)), 2)
        self.assertEqual(detection.latest_assessment(self.e)["totals"]["rules"], 1)
        md = detection.rule_report_md(a["rules"][0])
        self.assertIn("Recommendation: Tune", md)
        self.assertIn("Quanta has not changed any rule", md)
        self.assertIn("Noisy rule", detection.summary_md(a))
        self.assertNotIn("<script>", detection.to_html("# <script>x</script>", "t"))

    def test_rule_validation_and_toggle(self):
        with self.assertRaises(ValueError):
            detection.upsert_rule("  ", engine=self.e)
        r = detection.upsert_rule("R", techniques=["t1190", "nonsense"], engine=self.e)
        self.assertEqual(r["techniques"], ["T1190"])
        self.assertFalse(detection.set_enabled(r["id"], False, self.e)["enabled"])
        self.assertTrue(detection.delete_rule(r["id"], self.e))
        with self.assertRaises(KeyError):
            detection.set_enabled(999, True, self.e)


class RegistryTests(unittest.TestCase):
    def test_tool_connections_validate_and_are_not_synced(self):
        with patch("remediation.connectors.url_safety.assert_safe_target"):
            cfg, sec_ = registry.split_values("splunk-search", {"base_url": "https://s:8089", "token": "t"})
            self.assertEqual((cfg["base_url"], sec_["token"]), ("https://s:8089", "t"))
            with self.assertRaises(ValueError):
                registry.split_values("splunk-search", {"base_url": "https://s:8089"})
        self.assertEqual(registry.split_values("reputation", {"api_key": "k"})[1], {"api_key": "k"})
        kinds = {t["type"]: t["kind"] for t in registry.public_catalog()}
        self.assertEqual((kinds["splunk-search"], kinds["reputation"]), ("tool", "tool"))

    def test_running_a_tool_connection_does_not_pull_anything(self):
        e = create_engine("sqlite:///:memory:")
        with patch("remediation.connectors.url_safety.assert_safe_target"), patch.dict("os.environ", {"QUANTA_ENCRYPTION_KEY": __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet.generate_key().decode()}):
            c = conn_store.create("hunt siem", "reputation", {"api_key": "k"}, "a", engine=e)
            r = conn_sync.run(c["id"], "a", engine=e)
        self.assertTrue(r["ok"])
        self.assertIn("on demand", r["message"])


class SocApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fake = [fnd(1, "WEB-1")]
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=self.fake)]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")
        self.key = self.client.post("/api/api-keys", json={"name": "siem", "scopes": ["soc:write"]}).json()["key"]
        self.other = self.client.post("/api/api-keys", json={"name": "ci", "scopes": ["ingest:write"]}).json()["key"]
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

    def h(self, key=None):
        return {"Authorization": f"Bearer {key or self.key}"}

    def test_admin_only(self):
        paths = ["/api/hunting/intel", "/api/detections/overview", "/api/detections/rules", "/api/detections/report", "/api/hunting/hunts/1/report"]
        for p in paths:
            self.assertEqual(self.client.get(p).status_code, 401, p)
        self.login("user@t.local")
        for p in paths:
            self.assertEqual(self.client.get(p).status_code, 403, p)

    def test_intel_to_hunt_to_verdict_and_report(self):
        self.login("admin@t.local")
        r = self.client.post("/api/hunting/intel", json={"content": TEXT})
        self.assertEqual(r.status_code, 200, r.text)
        rep_ = r.json()
        self.assertEqual((rep_["priority"], rep_["created"], rep_["matches"]["hosts"]), ("high", True, ["WEB-1"]))
        self.assertFalse(self.client.post("/api/hunting/intel", json={"content": TEXT}).json()["created"])
        self.assertEqual(self.client.post("/api/hunting/intel", json={"content": "   "}).status_code, 400)
        h = self.client.post(f"/api/hunting/intel/{rep_['id']}/hunt")
        self.assertEqual(h.status_code, 200, h.text)
        hunt = h.json()
        self.assertEqual((hunt["source"], hunt["verdict"]["overall"]), ("intel", "incomplete"))
        self.assertEqual(self.client.post(f"/api/hunting/intel/{rep_['id']}/hunt").status_code, 400)
        upd = self.client.put(f"/api/hunting/hunts/{hunt['id']}", json={"queries": [{**hunt["queries"][0], "result": "hits", "assessment": "malicious", "sample": [{"host": "WEB-1"}]}] + hunt["queries"][1:]})
        self.assertEqual(upd.json()["verdict"]["overall"], "confirmed-compromise")
        md = self.client.get(f"/api/hunting/hunts/{hunt['id']}/report")
        self.assertIn("text/markdown", md.headers["content-type"])
        self.assertIn("confirmed-compromise", md.text)
        page = self.client.get(f"/api/hunting/hunts/{hunt['id']}/report?format=html")
        self.assertIn("attachment", page.headers["content-disposition"])

    def test_threat_intel_push_needs_the_scope(self):
        self.assertEqual(self.client.post("/api/ingest/threat-intel", json={"content": TEXT}).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/threat-intel", json={"content": TEXT}, headers=self.h(self.other)).status_code, 401)
        r = self.client.post("/api/ingest/threat-intel", json={"content": TEXT}, headers=self.h())
        self.assertEqual((r.status_code, r.json()["created"], r.json()["priority"]), (200, True, "high"))

    def test_run_a_lead_previews_then_runs_with_confirmation(self):
        self.login("admin@t.local")
        hunt = self.client.post("/api/hunting/hunts", json={"title": "t", "hypothesis": "h", "queries": [{"technique": "T1190", "name": "n", "query": 'search host="WEB-1"', "language": "splunk-spl", "result": None}]}).json()
        url = f"/api/hunting/hunts/{hunt['id']}/queries/0/run"
        self.assertEqual(self.client.post(url, json={}).status_code, 400)  # no connection configured
        fake = FakeSearch(count=3)
        with patch.object(service, "connector", return_value=(fake, {"name": "prod splunk"})):
            pre = self.client.post(url, json={})
            self.assertTrue(pre.json()["preview_only"])
            self.assertEqual(fake.queries, [])  # nothing was sent
            self.assertEqual(self.client.post(url, json={"earliest": "yesterday"}).status_code, 400)
            ran = self.client.post(url, json={"confirm": True, "earliest": "-7d"})
            self.assertEqual(ran.status_code, 200, ran.text)
            self.assertEqual((ran.json()["query"]["count"], ran.json()["hunt"]["status"]), (3, "active"))
            self.assertEqual(fake.queries[0][1], "-7d")
            self.assertEqual(self.client.post(f"/api/hunting/hunts/{hunt['id']}/queries/5/run", json={"confirm": True}).status_code, 404)
        with patch.object(service, "connector", return_value=(FakeSearch(boom=True), {"name": "prod splunk"})):
            self.assertEqual(self.client.post(url, json={"confirm": True}).status_code, 502)

    def test_ocsf_intake_and_alert_fields(self):
        r = self.client.post("/api/ingest/alerts/ocsf", json=[OcsfTests.EVENT, {"finding_info": {}}], headers=self.h())
        self.assertEqual((r.status_code, r.json()["created"], r.json()["rejected"]), (200, 1, 1), r.text)
        self.assertEqual(self.client.post("/api/ingest/alerts/ocsf", json={"events": [OcsfTests.EVENT]}, headers=self.h()).json()["already_known"], 1)
        self.assertEqual(self.client.post("/api/ingest/alerts/ocsf", json=[OcsfTests.EVENT], headers=self.h(self.other)).status_code, 401)
        plain = self.client.post("/api/ingest/alerts", json={"alerts": [{"external_id": "p1", "title": "x", "rule_name": "Rule Z", "entities": {"user": "bob"}}]}, headers=self.h())
        self.assertEqual(plain.json()["created"], 1)
        self.login("admin@t.local")
        rows = self.client.get("/api/soc/alerts").json()["alerts"]
        self.assertEqual({r_["rule_name"] for r_ in rows}, {"Web shell spawn", "Rule Z"})

    def test_investigation_local_preview_and_confirmed(self):
        with patch.object(soc, "config", return_value={**soc.config(), "auto_investigate": {"enabled": False}}):  # this test is about the manual path
            self.client.post("/api/ingest/alerts", json={"alerts": [{"external_id": "a1", "title": "Shell from w3wp", "severity": "High", "asset": "WEB-1", "technique": "T1190",
                                                                    "detail": "beacon 185.220.101.9"}]}, headers=self.h())
        self.login("admin@t.local")
        aid = self.client.get("/api/soc/alerts").json()["alerts"][0]["id"]
        self.assertEqual(self.client.get(f"/api/soc/alerts/{aid}/investigation").status_code, 404)
        local = self.client.post(f"/api/soc/alerts/{aid}/investigate", json={})
        self.assertEqual(local.status_code, 200, local.text)
        self.assertEqual(local.json()["investigation"]["verdict"], "escalate-l2")  # exposed host + unchecked indicator: not enough alone
        self.assertEqual(self.client.post(f"/api/soc/alerts/{aid}/investigate", json={"reputation": True}).status_code, 400)  # nothing configured
        lookups = []

        class FakeRep:
            def lookup(self, v):
                lookups.append(v)
                return {"result": "seen", "malicious": 30, "total": 80}

        def fake_connector(conn_type, cid=None, engine=None):
            return (FakeRep(), {"name": "vt"}) if conn_type == "reputation" else (FakeSearch(), {"name": "splunk"})

        with patch.object(service, "connector", side_effect=fake_connector):
            pre = self.client.post(f"/api/soc/alerts/{aid}/investigate", json={"reputation": True, "siem": True})
            self.assertEqual(pre.json()["indicators_that_would_be_sent"], ["185.220.101.9"])
            self.assertEqual(lookups, [])  # nothing left the building without confirm
            done = self.client.post(f"/api/soc/alerts/{aid}/investigate", json={"reputation": True, "siem": True, "confirm": True})
            self.assertEqual(done.status_code, 200, done.text)
        inv = done.json()["investigation"]
        self.assertEqual((inv["verdict"], lookups), ("likely-true-positive", ["185.220.101.9"]))
        self.assertIn("Recommended verdict", done.json()["report_md"])
        self.assertEqual(self.client.get(f"/api/soc/alerts/{aid}/investigation").json()["verdict"], "likely-true-positive")
        self.assertEqual(self.client.get("/api/soc/alerts/999/investigation").status_code, 404)
        self.assertEqual(self.client.post("/api/soc/alerts/999/investigate", json={}).status_code, 404)
        # applying a verdict stays a separate, human step
        # an escalate-L2 verdict on a High alert opens a case automatically, which marks the alert investigating; it is never closed by the investigation
        self.assertEqual(self.client.get(f"/api/soc/alerts/{aid}").json()["status"], "investigating")
        self.assertEqual(local.json()["case_id"], self.client.get("/api/soc/cases").json()["cases"][0]["id"])

    def test_detection_engineering_flow(self):
        self.login("admin@t.local")
        imp = self.client.post("/api/detections/rules/import", content=SIGMA)
        self.assertEqual((imp.status_code, imp.json()["imported"]), (200, 2), imp.text)
        self.assertEqual(self.client.post("/api/detections/rules/import", content="title: x").status_code, 400)
        for i in range(8):
            a = self.client.post("/api/ingest/alerts", json={"alerts": [{"external_id": f"d{i}", "title": "x", "rule_name": "Suspicious shell from web server", "asset": "NOISY-1"}]}, headers=self.h())
            self.assertEqual(a.status_code, 200)
        rows = self.client.get("/api/soc/alerts").json()["alerts"]
        for i, r in enumerate(rows):
            self.client.put(f"/api/soc/alerts/{r['id']}", json={"status": "closed", "disposition": "true-positive" if i < 2 else "false-positive"})
        ov = self.client.get("/api/detections/overview").json()
        rule = next(r for r in ov["rules"] if r["rule"] == "Suspicious shell from web server")
        self.assertEqual((rule["metrics"]["tier"], rule["metrics"]["recommendation"], rule["tuning"]["exclude_hosts"]), ("noisy", "tune", ["NOISY-1"]))
        self.assertEqual(ov["coverage"]["estate_techniques"], 1)
        saved = self.client.post("/api/detections/assess").json()
        self.assertEqual(len(saved["history"]), 1)
        md = self.client.get("/api/detections/report?rule=Suspicious%20shell%20from%20web%20server")
        self.assertIn("Recommendation: Tune", md.text)
        self.assertEqual(self.client.get("/api/detections/report?rule=nope").status_code, 404)
        self.assertIn("Detection engineering summary", self.client.get("/api/detections/report").text)
        rid = rule["rule_id"]
        self.assertFalse(self.client.put(f"/api/detections/rules/{rid}", json={"enabled": False}).json()["enabled"])
        self.assertEqual(self.client.delete(f"/api/detections/rules/{rid}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/detections/rules/{rid}").status_code, 404)
        add = self.client.post("/api/detections/rules", json={"name": "Manual rule", "techniques": ["T1068"]})
        self.assertEqual((add.status_code, add.json()["techniques"]), (200, ["T1068"]))
        self.assertEqual(self.client.post("/api/detections/rules", json={"name": " "}).status_code, 400)

    def test_weekly_snapshot_runs_only_when_due_and_only_with_alerts(self):
        dashboard_app_module._run_detection_assessment_if_due()
        self.assertEqual(detection.list_assessments(self.engine), [])
        store.receive_alert({"source": "x", "external_id": "1", "title": "t", "rule_name": "R"}, self.engine)
        dashboard_app_module._run_detection_assessment_if_due()
        dashboard_app_module._run_detection_assessment_if_due()
        self.assertEqual(len(detection.list_assessments(self.engine)), 1)


if __name__ == "__main__":
    unittest.main()
