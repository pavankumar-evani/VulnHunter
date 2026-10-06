"""
Core tests for the hunt report: the trial-hit table arithmetic, status and verdict rules, the benign-activity allow-list and its effect on later runs, per-domain results,
detection recommendations, the time-box and time-to-report metrics, and the Markdown and HTML exports. No network, no SIEM.
"""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine  # noqa: E402

from remediation.hunting import hunt_report as hr, store as hunt_store  # noqa: E402
from remediation.investigation import store as inv_store  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, 12, 0, 0, tzinfo=datetime.timezone.utc)


def at(hours_ago):
    return (NOW - datetime.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def lead(name, technique="T1059", result=None, count=None, sample=None, assessment=None, domain=None, ran_hours_ago=None, window="-30d", **kw):
    q = {"technique": technique, "name": name, "domain": domain, "source": "SIEM", "language": "splunk-spl", "query": f"search host=WEB-1 {name}", "result": result, "notes": ""}
    if result:
        q.update({"count": count, "sample": sample or [], "ran_at": at(ran_hours_ago if ran_hours_ago is not None else 1), "window": window, "truncated": kw.get("truncated", False)})
    if assessment:
        q["assessment"] = assessment
    if result == "error":
        q["error"] = "timeout"
    return q


def hunt(queries, **kw):
    return {"id": kw.get("id", 1), "title": "Exploitation of CVE-2021-44228", "hypothesis": "CVE-2021-44228 is on the KEV list and open on 2 assets. Look for exploitation attempts and activity after one.",
            "source": "generated", "source_ref": "CVE-2021-44228", "status": kw.get("status", "active"), "outcome": kw.get("outcome"), "techniques": [{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}],
            "assets": ["WEB-1", "WEB-2"], "data_sources": ["process creation"], "queries": queries, "notes": "", "follow_ups": "", "detection_created": kw.get("detection_created", False),
            "created_at": kw.get("created_at", at(5)), "closed_at": kw.get("closed_at"), "updated_at": at(1)}


def rows(*hosts):
    return [{"host": h, "Image": "cmd.exe"} for h in hosts]


def build(h, allow=(), rules=(), boxes=None):
    return hr.build(h, list(rules), list(allow), boxes or {}, now=NOW)


def entry(i, q, field, value, note="Nightly vulnerability scanner"):
    return {"id": i, "lead_key": hr.lead_key(q), "hunt_id": 1, "field": field, "value": value, "note": note, "created_by": "a@t.local", "created_at": at(2)}


class TableMath(unittest.TestCase):
    def setUp(self):
        self.qs = [lead("Shells spawned by server or office processes", "T1059", "hits", 5, rows("WEB-1", "WEB-1", "WEB-2", "WEB-2", "WEB-2")),
                   lead("Server error bursts from one source", "T1190", "no-hits", 0),
                   lead("sudo or UAC bypass patterns", "T1548"),
                   lead("Suspicious request patterns against the affected hosts", "T1190", "error", None)]
        self.r = build(hunt(self.qs))

    def test_counts_add_up(self):
        c = self.r["counts"]
        self.assertEqual((c["trial_hits"], c["run"], c["no_hit"], c["needs_investigation"], c["not_run"]), (4, 2, 1, 1, 2))
        self.assertEqual(c["run"] + c["not_run"], c["trial_hits"])
        self.assertEqual(c["no_hit"] + c["needs_investigation"] + c["not_run"], c["trial_hits"])
        self.assertEqual((c["hits"], c["entities"]), (5, len(self.r["entities_observed"])))
        self.assertEqual(sum(d["trial_hits"] for d in self.r["per_domain"].values()), 4)

    def test_status_and_columns_per_trial_hit(self):
        by = {x["n"]: x for x in self.r["trial_hits"]}
        self.assertEqual([by[i]["status"] for i in (1, 2, 3, 4)], ["needs-investigation", "no-hit", "not-run", "not-run"])
        self.assertEqual((by[1]["hits"], by[1]["hits_after_allowlist"], by[1]["source_tool"]), (5, 5, "SIEM"))
        self.assertEqual(sorted(by[1]["entities"]), ["WEB-1", "WEB-2", "cmd.exe"])
        self.assertEqual(by[1]["lead"], {"hunt_id": 1, "index": 0, "path": "/hunting?hunt=1&lead=0"})
        self.assertEqual(by[4]["error"], "timeout")                     # an error is not-run, with the reason shown
        self.assertIsNone(by[3]["hits"])

    def test_domains(self):
        by = {x["n"]: x["domain"] for x in self.r["trial_hits"]}
        self.assertEqual(by[1], "endpoint")
        self.assertEqual(by[2], "network")                              # T1190 is a network-domain library entry
        self.assertEqual(hr.domain_of({"domain": "identity"}), "identity-email")
        self.assertEqual(hr.domain_of({"domain": "email"}), "identity-email")
        self.assertEqual(self.r["per_domain"]["network"]["no_hit"], 1)
        self.assertEqual(self.r["per_domain"]["endpoint"]["needs_investigation"], 1)

    def test_topic_gist_lookback_and_counts_of_planned(self):
        self.assertEqual(self.r["topic"], "Exploitation of CVE-2021-44228")
        self.assertTrue(self.r["gist"].startswith("CVE-2021-44228 is on the KEV list"))
        self.assertEqual((self.r["look_back"]["text"], self.r["look_back"]["days_max"]), ("-30d", 30))
        self.assertEqual(build(hunt([lead("x")]))["look_back"]["text"], "not run yet")


class Verdicts(unittest.TestCase):
    def v(self, *qs):
        return build(hunt(list(qs)))["verdict"]["label"]

    def test_no_match_needs_investigation_confirmed_and_not_run(self):
        self.assertEqual(self.v(lead("a", result="no-hits", count=0), lead("b", result="no-hits", count=0)), "no-ioc-match")
        self.assertEqual(self.v(lead("a", result="no-hits", count=0), lead("b", result="hits", count=2, sample=rows("W"))), "needs-investigation")
        self.assertEqual(self.v(lead("a", result="hits", count=2, sample=rows("W"), assessment="malicious")), "confirmed")
        self.assertEqual(self.v(lead("a"), lead("b")), "not-run")

    def test_an_unassessed_hit_is_never_benign_and_an_assessed_benign_one_is_a_recorded_decision(self):
        r = build(hunt([lead("a", result="hits", count=2, sample=rows("W"))]))
        self.assertEqual(r["trial_hits"][0]["status"], "needs-investigation")
        r = build(hunt([lead("a", result="hits", count=2, sample=rows("W"), assessment="benign")]))
        self.assertEqual((r["trial_hits"][0]["status"], r["trial_hits"][0]["judged_benign"], r["verdict"]["label"]), ("no-hit", True, "no-ioc-match"))
        r = build(hunt([lead("a", result="hits", count=2, sample=rows("W"), assessment="suspicious")]))
        self.assertEqual(r["verdict"]["label"], "needs-investigation")

    def test_partial_runs_are_not_presented_as_complete(self):
        r = build(hunt([lead("a", result="no-hits", count=0), lead("b")]))
        self.assertEqual(r["verdict"]["label"], "no-ioc-match")
        self.assertIn("covers only those that ran", r["verdict"]["rationale"])
        self.assertTrue(any("not run" in x["text"] for x in r["executive_summary"]))

    def test_the_same_entity_in_two_leads_is_called_out(self):
        r = build(hunt([lead("a", result="hits", count=1, sample=rows("WEB-1")), lead("b", "T1190", result="hits", count=1, sample=rows("WEB-1"))]))
        self.assertIn("WEB-1", r["verdict"]["correlated_entities"])

    def test_every_executive_statement_points_at_trial_hits(self):
        r = build(hunt([lead("a", result="hits", count=1, sample=rows("W"))]))
        for x in r["executive_summary"]:
            self.assertIn("trial_hits", x)


class AllowList(unittest.TestCase):
    def setUp(self):
        self.q = lead("Shells spawned by server or office processes", "T1059", "hits", 5, rows("SCAN-1", "SCAN-1", "scan-1", "WEB-2", "WEB-3"))

    def test_matching_rows_are_set_aside_and_counted_not_hidden(self):
        r = build(hunt([self.q]), allow=[entry(1, self.q, "host", "SCAN-1")])
        x = r["trial_hits"][0]
        self.assertEqual((x["hits"], x["allowlisted_rows"], x["hits_after_allowlist"], x["status"]), (5, 3, 2, "needs-investigation"))   # case-insensitive, exact
        self.assertEqual(sorted(e for e in x["entities"] if e.lower() != "cmd.exe"), ["WEB-2", "WEB-3"])
        self.assertEqual(r["allowlist"]["rows_set_aside"], 3)
        self.assertEqual([e["id"] for e in r["allowlist"]["applied_entries"]], [1])
        self.assertTrue(any("3 result row(s) were set aside" in e["text"] for e in r["executive_summary"]))
        self.assertEqual(r["counts"]["hits"], 2)

    def test_when_everything_is_allow_listed_the_lead_is_no_hit(self):
        q = lead("Shells spawned by server or office processes", "T1059", "hits", 2, rows("SCAN-1", "SCAN-1"))
        r = build(hunt([q]), allow=[entry(1, q, "host", "SCAN-1")])
        self.assertEqual((r["trial_hits"][0]["status"], r["verdict"]["label"]), ("no-hit", "no-ioc-match"))

    def test_a_truncated_sample_makes_the_count_partial_instead_of_guessing(self):
        q = lead("Shells spawned by server or office processes", "T1059", "hits", 500, rows("SCAN-1", "SCAN-1", "WEB-2"), truncated=True)
        x = build(hunt([q]), allow=[entry(1, q, "host", "SCAN-1")])["trial_hits"][0]
        self.assertEqual((x["hits_after_allowlist"], x["allowlist_partial"], x["status"]), (498, True, "needs-investigation"))

    def test_it_applies_to_a_later_run_of_the_same_lead_in_another_hunt_and_only_that_lead(self):
        e = entry(1, self.q, "host", "SCAN-1")
        later = lead("Shells spawned by server or office processes", "T1059", "hits", 3, rows("SCAN-1", "WEB-9", "WEB-9"))
        other = lead("sudo or UAC bypass patterns", "T1548", "hits", 3, rows("SCAN-1", "SCAN-1", "SCAN-1"))
        r = build(hunt([later, other], id=2), allow=[e])
        self.assertEqual((r["trial_hits"][0]["allowlisted_rows"], r["trial_hits"][0]["hits_after_allowlist"]), (1, 2))
        self.assertEqual((r["trial_hits"][1]["allowlisted_rows"], r["trial_hits"][1]["hits_after_allowlist"]), (0, 3))

    def test_it_matches_the_recorded_field_exactly_not_a_substring(self):
        kept, supp, used = hr.apply_allowlist(self.q, [entry(1, self.q, "host", "SCAN")])
        self.assertEqual((len(supp), len(kept), used), (0, 5, set()))
        kept, supp, used = hr.apply_allowlist(self.q, [entry(1, self.q, "user", "SCAN-1")])
        self.assertEqual(len(supp), 0)

    def test_the_entries_are_listed_with_who_when_and_why(self):
        r = build(hunt([self.q]), allow=[entry(1, self.q, "host", "SCAN-1", "Nightly vulnerability scanner")])
        e = r["allowlist"]["entries"][0]
        self.assertEqual((e["note"], e["created_by"]), ("Nightly vulnerability scanner", "a@t.local"))
        self.assertIn("Nightly vulnerability scanner", hr.to_markdown(r))


class Renderings(unittest.TestCase):
    def test_a_library_lead_gets_spl_sigma_and_kql(self):
        r = build(hunt([lead("Shells spawned by server or office processes", "T1059", "hits", 1, rows("W"))]))
        q = r["trial_hits"][0]["queries"]
        self.assertTrue(q["spl"].startswith("search"))
        self.assertIn("title:", q["sigma"])
        self.assertTrue(q["kql"].startswith("union *"))
        self.assertIsNone(q["note"])

    def test_a_custom_lead_says_why_there_is_no_sigma_or_kql(self):
        q = build(hunt([lead("My own search", "T1059")]))["trial_hits"][0]["queries"]
        self.assertTrue(q["spl"])
        self.assertIsNone(q["sigma"])
        self.assertIn("not a library detection", q["note"])

    def test_a_lead_that_already_carries_them_keeps_them(self):
        l = lead("My own search", "T1059")
        l.update({"sigma": "title: mine", "kql": "DeviceProcessEvents"})
        q = build(hunt([l]))["trial_hits"][0]["queries"]
        self.assertEqual((q["sigma"], q["kql"], q["note"]), ("title: mine", "DeviceProcessEvents", None))


class DetectionRecommendations(unittest.TestCase):
    def recs(self, h, rules=()):
        return {x["trial_hit"]: x for x in build(h, rules=rules)["detection_recommendations"] if x["trial_hit"]}

    def test_promote_when_assessed_and_uncovered(self):
        h = hunt([lead("Shells spawned by server or office processes", "T1059", "hits", 2, rows("W"), assessment="malicious"), lead("Server error bursts from one source", "T1190", "no-hits", 0),
                  lead("x", "T1059", "hits", 2, rows("W"))])
        r = self.recs(h)
        self.assertEqual((r[1]["recommendation"], r[1]["priority"]), ("promote", "high"))
        self.assertTrue(r[1]["usecase_key"].startswith("hunt-"))
        self.assertEqual(r[2]["recommendation"], "consider")
        self.assertEqual(r[3]["recommendation"], "assess-then-promote")

    def test_covered_techniques_are_reported_as_covered(self):
        h = hunt([lead("Shells spawned by server or office processes", "T1059", "hits", 2, rows("W"), assessment="malicious")])
        r = self.recs(h, rules=[{"name": "Shell from web", "techniques": ["T1059"], "enabled": True}])
        self.assertEqual(r[1]["recommendation"], "covered")
        r = self.recs(h, rules=[{"name": "Shell from web", "techniques": ["T1059"], "enabled": False}])
        self.assertEqual(r[1]["recommendation"], "promote")

    def test_not_run_leads_get_no_recommendation_and_an_existing_detection_is_noted(self):
        h = hunt([lead("a", "T1059")], detection_created=True)
        recs = build(h)["detection_recommendations"]
        self.assertEqual([x["recommendation"] for x in recs], ["done"])


class TimeBox(unittest.TestCase):
    def t(self, h, boxes=None):
        return build(h, boxes=boxes)["timing"]

    def test_time_to_report_is_creation_to_the_last_lead_run_when_all_have_run(self):
        t = self.t(hunt([lead("a", result="no-hits", count=0, ran_hours_ago=3), lead("b", result="no-hits", count=0, ran_hours_ago=2)], created_at=at(6)))
        self.assertEqual((t["time_to_report_hours"], t["state"], t["time_box_hours"], t["time_box_source"]), (4.0, "within-time-box", 8, "default"))

    def test_late_overdue_and_open(self):
        t = self.t(hunt([lead("a", result="no-hits", count=0, ran_hours_ago=1)], created_at=at(30)))
        self.assertEqual((t["state"], t["time_to_report_hours"]), ("late", 29.0))
        t = self.t(hunt([lead("a"), lead("b", result="no-hits", count=0)], created_at=at(30)))
        self.assertEqual((t["state"], t["time_to_report_hours"], t["report_ready_at"]), ("overdue", None, None))
        t = self.t(hunt([lead("a")], created_at=at(2)))
        self.assertEqual(t["state"], "open")

    def test_a_closed_hunt_is_ready_at_its_close_time_and_the_box_can_be_overridden(self):
        h = hunt([lead("a")], status="closed", outcome="not-found", created_at=at(30), closed_at=at(26))
        t = self.t(h, boxes={1: 48})
        self.assertEqual((t["time_to_report_hours"], t["state"], t["time_box_hours"], t["time_box_source"]), (4.0, "within-time-box", 48, "hunt"))

    def test_metrics(self):
        hs = [hunt([lead("a", result="no-hits", count=0, ran_hours_ago=1)], id=1, created_at=at(3)), hunt([lead("a", result="no-hits", count=0, ran_hours_ago=1)], id=2, created_at=at(11)),
              hunt([lead("a")], id=3, created_at=at(40))]
        m = hr.metrics(hs, now=NOW)
        self.assertEqual((m["hunts"], m["reports_ready"], m["median_hours"], m["mean_hours"]), (3, 2, 6.0, 6.0))
        self.assertEqual((m["within_time_box"], m["late"], m["overdue"], m["open"]), (1, 1, 1, 0))
        self.assertEqual(hr.metrics([], now=NOW)["median_hours"], None)


class Exports(unittest.TestCase):
    def setUp(self):
        q = lead("Shells spawned by server or office processes", "T1059", "hits", 2, rows("WEB-1", "WEB-2"), assessment="suspicious")
        self.r = build(hunt([q, lead("Server error bursts from one source", "T1190", "no-hits", 0), lead("sudo or UAC bypass patterns", "T1548")]))

    def test_markdown_has_the_table_the_queries_in_three_languages_and_the_sections(self):
        md = hr.to_markdown(self.r)
        for s in ("# Hunt report:", "## Executive summary", "## Trial hit execution summary", "| # | Trial hit | Domain | Source tool | Status | Hits | Affected entities |", "Splunk SPL:", "Sigma:",
                  "Sentinel KQL:", "## Results by domain", "## Benign-activity allow-list", "## Detection recommendations", "## Limits", "needs-investigation"):
            self.assertIn(s, md, s)
        self.assertEqual(md.count("```") % 2, 0)

    def test_html_is_standalone_escaped_and_print_friendly(self):
        l = lead("<script>alert(1)</script>", "T1059", "hits", 1, [{"host": "<b>x</b>"}])
        page = hr.to_html(build(hunt([l])))
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertNotIn("<script>", page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("@media print", page)

    def test_json_shape_is_complete(self):
        for k in ("topic", "gist", "look_back", "counts", "entities_observed", "verdict", "executive_summary", "trial_hits", "per_domain", "allowlist", "detection_recommendations", "timing", "limits"):
            self.assertIn(k, self.r)
        for k in ("n", "name", "domain", "source_tool", "status", "hits", "entities", "lead", "queries"):
            self.assertIn(k, self.r["trial_hits"][0])


class AllowStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")

    def tearDown(self):
        self.e.dispose()
        self.tmp.cleanup()

    def test_entries_are_unique_per_lead_field_and_value_and_listed_by_lead(self):
        a, b = lead("a", "T1059"), lead("b", "T1190")
        e1 = inv_store.add_allow(a, 1, "host", "SCAN-1", "Scanner", "me", self.e)
        with self.assertRaises(ValueError):
            inv_store.add_allow(a, 2, "host", "SCAN-1", "Scanner again", "me", self.e)
        inv_store.add_allow(b, 1, "host", "SCAN-1", "Scanner", "me", self.e)
        self.assertEqual(len(inv_store.list_allow(self.e)), 2)
        self.assertEqual([x["id"] for x in inv_store.list_allow(self.e, lead_keys={hr.lead_key(a)})], [e1["id"]])
        self.assertTrue(inv_store.remove_allow(e1["id"], self.e))
        self.assertFalse(inv_store.remove_allow(e1["id"], self.e))

    def test_time_boxes_round_trip(self):
        inv_store.set_time_box(5, 12, "me", self.e)
        inv_store.set_time_box(5, 24, "me", self.e)
        self.assertEqual(inv_store.time_boxes(self.e), {5: 24})


if __name__ == "__main__":
    unittest.main()
