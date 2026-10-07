"""
The threat-intelligence report watcher: RSS / Atom / JSON feed reading, the TAXII 2.1 poller, dedupe, SSRF refusal, relevance to hunt creation (with the reason recorded),
no automatic run on a SIEM, error handling per source, the scheduler tick, and the time-to-report clock starting at report arrival. Every outside call is a fake.
"""
import datetime
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import requests
from sqlalchemy import create_engine

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation.connectors import report_feed_connector as rfc, taxii_connector as tx  # noqa: E402
from remediation.connectors import url_safety  # noqa: E402
from remediation.hunting import hunt_report, intel, intelwatch, service, store as hunt_store  # noqa: E402

T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
FINDING = {"id": "FIND-1", "title": "Log4Shell", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": "WEB-1"}, "attack_techniques": [T1190], "kev": {"listed": True}, "epss": {"score": 0.9}}
RELEVANT = "Actors exploit CVE-2021-44228 (T1190) against public web servers and beacon to 8.8.4.4."
IRRELEVANT = "A quarterly overview of phishing trends in the retail sector, with no CVE or indicator in it."

RSS = f"""<?xml version="1.0"?><rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Vendor blog</title>
<item><title>Log4Shell exploitation surge</title><link>https://blog.example.com/log4shell</link><guid>post-1</guid><pubDate>Tue, 06 Oct 2026 08:00:00 GMT</pubDate>
<description>&lt;p&gt;{RELEVANT}&lt;/p&gt;</description></item>
<item><title>Retail phishing</title><link>https://blog.example.com/phish</link><guid>post-2</guid><pubDate>Mon, 05 Oct 2026 08:00:00 GMT</pubDate>
<content:encoded><![CDATA[<div>{IRRELEVANT}</div>]]></content:encoded></item></channel></rss>"""
ATOM = f"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>CISA</title>
<entry><title>Advisory AA26-1</title><id>urn:uuid:1</id><link rel="alternate" href="https://cisa.example.gov/aa26-1"/><published>2026-10-06T07:00:00Z</published><content type="html">&lt;b&gt;{RELEVANT}&lt;/b&gt;</content></entry></feed>"""
JSONFEED = json.dumps({"version": "https://jsonfeed.org/version/1.1", "items": [{"id": "j1", "url": "https://x.example.com/j1", "title": "JSON report", "content_text": RELEVANT, "date_published": "2026-10-06T06:00:00+00:00"}]})
JSON_LIST = json.dumps([{"title": "Plain list report", "summary": IRRELEVANT, "link": "https://x.example.com/p1", "published": "2026-10-04T01:00:00Z"}])


class Resp:
    def __init__(self, body=b"", status=200, headers=None, data=None):
        self.body = body.encode() if isinstance(body, str) else body
        self.status_code, self.headers, self._data = status, headers or {}, data
        self.closed = False

    def json(self):
        return self._data if self._data is not None else json.loads(self.body)

    def iter_content(self, n):
        for i in range(0, len(self.body), n):
            yield self.body[i:i + n]

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code), response=self)

    def close(self):
        self.closed = True


class Session:
    def __init__(self, responses):
        self.responses, self.calls, self.headers, self.auth, self.verify = list(responses), [], {}, None, True

    def _next(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, **kw})
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r

    def get(self, url, **kw):
        return self._next("GET", url, **kw)

    def request(self, method, url, **kw):
        return self._next(method, url, **kw)


def public_dns():
    """No DNS in tests: literal loopback / metadata addresses still go through the real guard; any other name is treated as public."""
    real = url_safety.assert_safe_target

    def guard(target):
        if any(x in target for x in ("127.0.0.1", "169.254.169.254", "localhost", "metadata.google.internal")):
            return real(target)
    return patch.object(url_safety, "assert_safe_target", side_effect=guard)


class FeedParsingTests(unittest.TestCase):
    def setUp(self):
        p = public_dns()
        p.start()
        self.addCleanup(p.stop)

    def feed(self, body, **kw):
        s = Session([Resp(body, headers=kw.pop("headers", {"ETag": '"v1"', "Last-Modified": "Tue, 06 Oct 2026 09:00:00 GMT"}))])
        return rfc.ReportFeedConnector("https://blog.example.com/feed", session=s, **kw), s

    def test_rss_items_are_normalised_with_markup_stripped_and_newest_first(self):
        c, s = self.feed(RSS)
        r = c.fetch()
        self.assertEqual((r["status"], r["format"], r["etag"]), ("ok", "rss", '"v1"'))
        a, b = r["items"]
        self.assertEqual((a["title"], a["external_id"], a["published_at"], a["url"]), ("Log4Shell exploitation surge", "post-1", "2026-10-06T08:00:00Z", "https://blog.example.com/log4shell"))
        self.assertNotIn("<p>", a["content"])
        self.assertIn("CVE-2021-44228", a["content"])
        self.assertIn("phishing", b["content"])                  # content:encoded is read and stripped
        self.assertEqual(s.calls[0]["headers"]["User-Agent"].split("/")[0], "Quanta-report-watcher")

    def test_atom(self):
        r = self.feed(ATOM)[0].fetch()
        e = r["items"][0]
        self.assertEqual((r["format"], e["external_id"], e["url"], e["published_at"]), ("atom", "urn:uuid:1", "https://cisa.example.gov/aa26-1", "2026-10-06T07:00:00Z"))
        self.assertIn("CVE-2021-44228", e["content"])
        self.assertNotIn("<b>", e["content"])

    def test_json_feed_and_plain_json_list(self):
        r = self.feed(JSONFEED)[0].fetch()
        self.assertEqual((r["format"], r["items"][0]["external_id"], r["items"][0]["published_at"]), ("jsonfeed", "j1", "2026-10-06T06:00:00Z"))
        r = self.feed(JSON_LIST)[0].fetch()
        e = r["items"][0]
        self.assertEqual((r["format"], e["title"], e["external_id"] != ""), ("json", "Plain list report", True))

    def test_conditional_get_sends_validators_and_a_304_costs_nothing(self):
        s = Session([Resp(b"", status=304)])
        c = rfc.ReportFeedConnector("https://blog.example.com/feed", session=s)
        r = c.fetch(etag='"v1"', last_modified="Tue, 06 Oct 2026 09:00:00 GMT")
        self.assertEqual((r["status"], r["items"]), ("not-modified", []))
        self.assertEqual((s.calls[0]["headers"]["If-None-Match"], s.calls[0]["headers"]["If-Modified-Since"]), ('"v1"', "Tue, 06 Oct 2026 09:00:00 GMT"))

    def test_size_cap_doctype_and_garbage_are_refused(self):
        c, _ = self.feed("<rss>" + "x" * 5000 + "</rss>", max_bytes=1000)
        with self.assertRaisesRegex(rfc.FeedError, "larger than"):
            c.fetch()
        c, _ = self.feed("<rss>x</rss>", max_bytes=1000, headers={"Content-Length": "999999"})
        with self.assertRaisesRegex(rfc.FeedError, "over the"):
            c.fetch()
        bomb = '<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><rss><channel><item><title>&b;</title></item></channel></rss>'
        with self.assertRaisesRegex(rfc.FeedError, "DOCTYPE"):
            self.feed(bomb)[0].fetch()
        with self.assertRaises(rfc.FeedError):
            self.feed("<html><body>not a feed</body></html>")[0].fetch()
        with self.assertRaises(rfc.FeedError):
            self.feed("{not json")[0].fetch()

    def test_the_item_cap(self):
        many = json.dumps([{"title": f"r{i}", "id": str(i), "summary": "x", "published": f"2026-10-{(i % 28) + 1:02d}T00:00:00Z"} for i in range(80)])
        self.assertEqual(len(self.feed(many, max_items=10)[0].fetch()["items"]), 10)

    def test_ssrf_and_scheme_are_refused_at_construction(self):
        for bad in ("http://blog.example.com/feed", "https://127.0.0.1/feed", "https://169.254.169.254/latest/meta-data", "https://localhost/x", "ftp://x/y", ""):
            with self.assertRaises(ValueError, msg=bad):
                rfc.ReportFeedConnector(bad, session=Session([Resp(RSS)]))

    def test_an_http_error_propagates_for_the_caller_to_record(self):
        c = rfc.ReportFeedConnector("https://blog.example.com/feed", session=Session([Resp(b"", status=503)]))
        with self.assertRaises(requests.HTTPError):
            c.fetch()


def stix_report(i, refs=(), published="2026-10-06T05:00:00.000Z"):
    return {"type": "report", "id": f"report--{i}", "name": f"Intrusion set report {i}", "created": published, "modified": published, "published": published,
            "object_refs": list(refs), "external_references": [{"source_name": "x", "url": f"https://cti.example.com/r/{i}"}]}


IND = {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '8.8.4.4']", "pattern_type": "stix"}
ACTOR = {"type": "threat-actor", "id": "threat-actor--1", "name": "APT29"}
VULN = {"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2021-44228"}


class TaxiiTests(unittest.TestCase):
    def setUp(self):
        p = public_dns()
        p.start()
        self.addCleanup(p.stop)

    def taxii(self, responses, **kw):
        s = Session(responses)
        return tx.TaxiiConnector("https://cti.example.com/taxii2/api1/", session=s, **kw), s

    def test_discovery_and_collections(self):
        c, s = self.taxii([Resp(data={"title": "Acme CTI", "versions": ["application/taxii+json;version=2.1"]}), Resp(data={"collections": [{"id": "c1", "title": "Reports", "can_read": True}]})], token="tok-1")
        self.assertEqual(c.test_connection()["title"], "Acme CTI")
        self.assertEqual(c.collections(), [{"id": "c1", "title": "Reports", "can_read": True}])
        self.assertEqual((s.headers["Accept"], s.headers["Authorization"]), ("application/taxii+json;version=2.1", "Bearer tok-1"))
        self.assertTrue(all(call["method"] == "GET" for call in s.calls))

    def test_basic_auth(self):
        c, s = self.taxii([Resp(data={})], username="u", password="p")
        self.assertEqual(s.auth, ("u", "p"))

    def test_poll_paginates_builds_bundles_and_keeps_the_cursor(self):
        page1 = Resp(data={"more": True, "next": "n1", "objects": [stix_report(1, ["indicator--1", "threat-actor--1"]), IND, ACTOR]}, headers={"X-TAXII-Date-Added-Last": "2026-10-06T05:00:00.100Z"})
        page2 = Resp(data={"more": False, "objects": [stix_report(2, ["vulnerability--1"]), VULN]}, headers={"X-TAXII-Date-Added-Last": "2026-10-06T06:00:00.000Z"})
        c, s = self.taxii([page1, page2], token="t")
        r = c.poll("c1", added_after="2026-10-01T00:00:00Z")
        self.assertEqual((r["pages"], len(r["items"]), r["added_after"], r["objects_seen"]), (2, 2, "2026-10-06T06:00:00.000Z", 5))
        self.assertEqual(s.calls[0]["params"]["added_after"], "2026-10-01T00:00:00Z")
        self.assertEqual(s.calls[1]["params"]["next"], "n1")
        self.assertTrue(all(call["method"] == "GET" and "/collections/c1/objects/" in call["url"] for call in s.calls))
        first = r["items"][0]
        bundle = json.loads(first["content"])
        self.assertEqual({o["type"] for o in bundle["objects"]}, {"report", "indicator", "threat-actor"})
        self.assertEqual((first["published_at"], first["url"]), ("2026-10-06T05:00:00Z", "https://cti.example.com/r/1"))
        ex = intel.extract(first["content"])
        self.assertIn("8.8.4.4", ex["ips"])                       # the existing STIX extractor reads the poll's bundle
        self.assertIn("APT29", ex["actors"])

    def test_errors_are_short_and_credential_free(self):
        c, _ = self.taxii([Resp(status=401)], token="supersecrettoken")
        with self.assertRaises(tx.TaxiiError) as cm:
            c.collections()
        self.assertEqual(str(cm.exception), "authentication failed")
        c, _ = self.taxii([requests.ConnectionError("boom supersecrettoken")], token="supersecrettoken")
        with self.assertRaises(tx.TaxiiError) as cm:
            c.poll("c1")
        self.assertNotIn("supersecrettoken", str(cm.exception))

    def test_ssrf_is_refused(self):
        for bad in ("https://127.0.0.1/taxii2/", "https://169.254.169.254/", "ftp://x", ""):
            with self.assertRaises(ValueError):
                tx.TaxiiConnector(bad, session=Session([Resp(data={})]))


class FakeFeed:
    def __init__(self, items, status="ok", boom=None):
        self.items, self.status, self.boom, self.calls = items, status, boom, []

    def fetch(self, etag=None, last_modified=None):
        self.calls.append((etag, last_modified))
        if self.boom:
            raise self.boom
        return {"status": self.status, "format": "rss", "items": self.items, "etag": '"e2"', "last_modified": "LM2"}


def item(i, text=RELEVANT, published="2026-10-06T08:00:00Z"):
    return {"external_id": f"id-{i}", "title": f"Report {i}", "url": f"https://x/{i}", "published_at": published, "content": text}


class WatcherBase(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        self.feed = FakeFeed([])
        self.hunts, self.refreshed, self.searches = [], [], []
        self.floor = "high"

        def make_hunt(rec, actor):
            ex = rec["extracted"]
            score, prio, reasons, matches = intel.relevance(ex, [FINDING])
            proposal = intel.propose_hunt(ex, (score, prio, reasons, matches), matches["hosts"])
            proposal["source_ref"] = f"intel-{rec['id']}"
            h = hunt_store.create_hunt(proposal, actor, self.e)
            service.link_intel_hunt(rec["id"], h["id"], self.e)
            self.hunts.append(h)
            return h
        self.deps = intelwatch.Deps(findings=lambda: [FINDING], make_hunt=make_hunt, refresh_engine=lambda f: self.refreshed.append(len(f)), hunt_floor=lambda: self.floor,
                                    build_feed=lambda s: self.feed, build_taxii=lambda s: self.taxii, engine=self.e)
        self.src = service.add_source("Vendor", "feed", "https://blog.example.com/feed", "admin", engine=self.e)


class IngestRules(WatcherBase):
    def test_a_relevant_report_creates_the_hunt_and_records_why(self):
        self.feed.items = [item(1)]
        out = intelwatch.poll_source(self.src, self.deps)
        self.assertEqual((out["status"], out["new"], out["hunts_created"]), ("ok", 1, 1))
        rec = service.list_intel(self.e)[0]
        self.assertEqual((rec["priority"], rec["source"], rec["source_id"], rec["published_at"], rec["hunt_id"]), ("high", "watcher:Vendor", self.src["id"], "2026-10-06T08:00:00Z", self.hunts[0]["id"]))
        why = rec["trigger"]
        self.assertEqual((why["decision"], why["threshold"], why["source"]), ("created", "high", "Vendor"))
        self.assertIn("a hunt was created", why["text"])
        self.assertTrue(why["reasons"])
        self.assertEqual(why["matched_hosts"], ["WEB-1"])
        self.assertEqual(self.refreshed, [1])                      # the hunt engine was refreshed so the report is also a suggestion

    def test_the_hunt_engine_suggestion_exists_for_the_report(self):
        from remediation.hunting.engine import service as engine_service
        self.feed.items = [item(1)]
        self.deps.refresh_engine = lambda findings: engine_service.refresh(findings, self.e)
        intelwatch.poll_source(self.src, self.deps)
        rows = engine_service.listing(self.e, include_suppressed=True)["suggestions"]
        self.assertTrue(any(any(ev["kind"] == "intel" for ev in r["why_now"]) for r in rows))

    def test_below_the_threshold_the_report_is_stored_and_no_hunt_is_made(self):
        self.feed.items = [item(2, IRRELEVANT)]
        out = intelwatch.poll_source(self.src, self.deps)
        self.assertEqual((out["new"], out["hunts_created"], self.hunts, self.refreshed), (1, 0, [], []))
        rec = service.list_intel(self.e)[0]
        self.assertEqual((rec["hunt_id"], rec["trigger"]["decision"]), (None, "below-threshold"))
        self.assertIn("below the 'high' threshold", rec["trigger"]["text"])

    def test_no_configured_threshold_never_creates_a_hunt(self):
        self.floor = ""
        self.feed.items = [item(1)]
        intelwatch.poll_source(self.src, self.deps)
        self.assertEqual((self.hunts, service.list_intel(self.e)[0]["trigger"]["decision"]), ([], "no-threshold"))

    def test_nothing_is_run_on_a_siem_and_the_hunt_stays_proposed(self):
        self.feed.items = [item(1)]
        intelwatch.poll_source(self.src, self.deps)
        h = hunt_store.get_hunt(self.hunts[0]["id"], self.e)
        self.assertEqual(h["status"], "proposed")
        self.assertTrue(h["queries"] and all(q["result"] is None and not q.get("ran_at") for q in h["queries"]))
        for name in ("search_connector", "connector", "run_hunt_query"):
            self.assertFalse(hasattr(self.deps, name))               # the watcher has no way to reach a search connection

    def test_repeats_are_ignored_by_external_id_and_by_content(self):
        self.feed.items = [item(1)]
        intelwatch.poll_source(self.src, self.deps)
        again = intelwatch.poll_source(service.get_source(self.src["id"], self.e), self.deps)
        self.assertEqual((again["new"], again["seen"], len(service.list_intel(self.e)), len(self.hunts)), (0, 1, 1, 1))
        other = service.add_source("Mirror", "feed", "https://mirror.example.com/feed", "admin", engine=self.e)
        self.feed.items = [dict(item(1), external_id="different-id")]     # same report text through another source
        r = intelwatch.poll_source(other, self.deps)
        self.assertEqual((r["new"], len(service.list_intel(self.e)), len(self.hunts)), (0, 1, 1))

    def test_a_per_poll_cap_leaves_the_rest_for_the_next_poll(self):
        self.feed.items = [item(i, f"{IRRELEVANT} number {i}") for i in range(10)]
        out = intelwatch.poll_source(self.src, self.deps, cfg={**intelwatch.config(), "max_new_reports_per_poll": 3})
        self.assertEqual(out["new"], 3)

    def test_a_stix_item_is_scored_from_its_bundle(self):
        bundle = json.dumps({"type": "bundle", "id": "bundle--1", "objects": [stix_report(1, ["vulnerability--1", "threat-actor--1"]), VULN, ACTOR]})
        self.feed.items = [{"external_id": "r1@x", "title": "Intrusion set report 1", "url": "", "published_at": "2026-10-06T05:00:00Z", "content": bundle}]
        intelwatch.poll_source(self.src, self.deps)
        rec = service.list_intel(self.e)[0]
        self.assertIn("CVE-2021-44228", rec["extracted"]["cves"])
        self.assertEqual(rec["extracted"]["format"], "stix")

    def test_a_failing_source_is_recorded_and_does_not_stop_the_others(self):
        self.feed.boom = requests.ConnectionError("down")
        bad = intelwatch.poll_source(self.src, self.deps)
        self.assertEqual(bad["status"], "error")
        s = service.get_source(self.src["id"], self.e)
        self.assertEqual((s["last_status"], bool(s["last_error"])), ("error", True))
        self.assertNotIn("Traceback", s["last_error"])
        self.feed.boom = None
        self.feed.items = [item(1)]
        ok = intelwatch.poll_due(self.deps, force=True)
        self.assertEqual(ok["polled"][0]["status"], "ok")
        self.assertEqual(service.get_source(self.src["id"], self.e)["last_error"], None)

    def test_validators_are_kept_and_sent_on_the_next_poll(self):
        self.feed.items = [item(1)]
        intelwatch.poll_source(self.src, self.deps)
        s = service.get_source(self.src["id"], self.e)
        self.assertEqual((s["etag"], s["last_modified"], s["total_reports"], s["last_new"]), ('"e2"', "LM2", 1, 1))
        intelwatch.poll_source(s, self.deps)
        self.assertEqual(self.feed.calls[-1], ('"e2"', "LM2"))

    def test_taxii_source_uses_the_cursor(self):
        class FakeTaxii:
            calls = []

            def poll(self, collection, added_after, limit):
                FakeTaxii.calls.append((collection, added_after))
                return {"items": [item(5)], "added_after": "2026-10-06T09:00:00Z"}
        self.taxii = FakeTaxii()
        t = service.add_source("CTI", "taxii", None, "admin", connection_id=3, collection_id="c9", engine=self.e)
        intelwatch.poll_source(t, self.deps)
        t = service.get_source(t["id"], self.e)
        self.assertEqual(t["added_after"], "2026-10-06T09:00:00Z")
        intelwatch.poll_source(t, self.deps)
        self.assertEqual(FakeTaxii.calls, [("c9", None), ("c9", "2026-10-06T09:00:00Z")])


class Scheduling(WatcherBase):
    def test_nothing_happens_with_no_source_and_the_switch_stops_the_tick(self):
        e2 = create_engine("sqlite:///:memory:")
        deps = intelwatch.Deps(findings=lambda: [], make_hunt=None, build_feed=lambda s: self.fail("no source, no fetch"), engine=e2)
        self.assertEqual(intelwatch.poll_due(deps)["polled"], [])
        self.feed.items = [item(1)]
        with patch.dict(os.environ, {"QUANTA_INTEL_WATCH": "false"}):
            r = intelwatch.poll_due(self.deps)
        self.assertEqual((r["polled"], "off" in r["skipped"]), ([], True))
        self.assertEqual(service.list_intel(self.e), [])

    def test_interval_and_disabled_sources(self):
        now = datetime.datetime(2026, 10, 7, 12, 0, tzinfo=datetime.timezone.utc)
        self.feed.items = [item(1, IRRELEVANT)]
        self.assertEqual(len(intelwatch.poll_due(self.deps, now=now)["polled"]), 1)              # never polled: due
        self.assertEqual(intelwatch.poll_due(self.deps, now=now + datetime.timedelta(minutes=5))["polled"], [])   # inside the interval
        self.assertEqual(len(intelwatch.poll_due(self.deps, now=now + datetime.timedelta(minutes=61))["polled"]), 1)
        service.update_source(self.src["id"], {"enabled": 0}, self.e)
        self.assertEqual(intelwatch.poll_due(self.deps, now=now + datetime.timedelta(hours=9), force=True)["polled"], [])

    def test_config_defaults(self):
        c = intelwatch.config()
        self.assertEqual((c["interval_minutes"], c["max_items_per_poll"]), (60, 50))


class TimeToReport(WatcherBase):
    def test_the_clock_starts_at_the_reports_published_time(self):
        self.feed.items = [item(1, published="2026-10-06T00:00:00Z")]
        intelwatch.poll_source(self.src, self.deps)
        hunt = hunt_store.get_hunt(self.hunts[0]["id"], self.e)
        start, src = service.clock_start_for(hunt, self.e)
        self.assertEqual((start, src), ("2026-10-06T00:00:00Z", "report-published"))
        h = service.with_clock_start(hunt, self.e)
        now = datetime.datetime(2026, 10, 6, 6, 0, tzinfo=datetime.timezone.utc)
        t = hunt_report.timing(h, [{"status": "no-hit", "ran_at": "2026-10-06T05:00:00Z"}], {}, {}, now)
        self.assertEqual((t["clock_start_source"], t["clock_started_at"], t["time_to_report_hours"]), ("report-published", "2026-10-06T00:00:00Z", 5.0))

    def test_without_a_published_date_the_clock_starts_when_the_report_was_fetched(self):
        self.feed.items = [item(1, published=None)]
        intelwatch.poll_source(self.src, self.deps)
        rec = service.list_intel(self.e)[0]
        start, src = service.clock_start_for(hunt_store.get_hunt(self.hunts[0]["id"], self.e), self.e)
        self.assertEqual((src, start), ("report-fetched", rec["fetched_at"]))

    def test_a_hunt_that_did_not_come_from_a_report_keeps_its_own_clock(self):
        h = hunt_store.create_hunt({"title": "manual", "hypothesis": "x", "source": "manual", "queries": []}, "a", self.e)
        self.assertEqual(service.clock_start_for(h, self.e), (None, None))
        self.assertIs(service.with_clock_start(h, self.e), h)
        t = hunt_report.timing(h, [], {}, {}, datetime.datetime.now(datetime.timezone.utc))
        self.assertEqual(t["clock_start_source"], "hunt-created")

    def test_a_manually_pasted_report_uses_its_receipt_time(self):
        rid, _ = service.save_intel("t", "manual", "h1", {"title": "t"}, 10, "low", [], "a", self.e)
        self.assertTrue(service.get_intel(rid, self.e)["fetched_at"])
        self.assertIsNone(service.get_intel(rid, self.e)["published_at"])


if __name__ == "__main__":
    unittest.main()
