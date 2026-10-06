"""
Core tests for the incident investigation report: the evidence-only rule, exact historical-correlation counts, IOC reputation and blast radius, unknown staying unknown, the
query playbook's budgets and look-back cap, follow-ups, the ITSM intake mapping and post-back, and the migration. No network: lookups and searches are hand-rolled fakes.
"""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine  # noqa: E402

from remediation.hunting import soc as hunt_soc, triage as hunt_triage  # noqa: E402
from remediation.investigation import followup, incident_report, itsm, playbook as qpb, store as inv_store  # noqa: E402
from remediation.investigation.evidence import Ledger  # noqa: E402
from remediation.utils import db as db_module, migrations  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, 12, 0, 0, tzinfo=datetime.timezone.utc)


def ts(days_ago, hour=10):
    return (NOW - datetime.timedelta(days=days_ago)).replace(hour=hour).strftime("%Y-%m-%dT%H:%M:%SZ")


def alert(i, host="WEB-1", user="bob", ips=("185.220.101.9", "10.0.0.5"), days_ago=0, technique="T1190", title=None, disposition=None, status="investigating", rule="web-shell", role="primary", **kw):
    return {"id": i, "source": "siem", "external_id": f"e{i}", "title": title or f"Shell spawned by web server {i}", "severity": "High", "asset": host, "technique": technique, "rule_name": rule,
            "detail": "", "status": status, "disposition": disposition, "occurred_at": ts(days_ago), "received_at": ts(days_ago), "closed_at": None, "action_taken": kw.get("action_taken"),
            "entities": {"host": host, "user": user, "ips": list(ips), "domains": kw.get("domains", []), "hashes": kw.get("hashes", []), "urls": []}, "role": role, "assignee": None, "notes": ""}


INCIDENT = {"id": 1, "title": "Shell spawned", "severity": "High", "status": "new", "tier": 1, "priority": "P2", "assignee": None, "verdict": None, "confidence": None, "updated_at": ts(0)}


def data_for(alerts_all, incident_map=None, investigations=None, **kw):
    return {"alerts_all": alerts_all, "incident_map": incident_map or {}, "investigations": investigations or {}, "findings": kw.get("findings", []), "ownership": kw.get("ownership", {}),
            "owners": kw.get("owners", {}), "assets": kw.get("assets", {}), "identity": kw.get("identity"), "recommended": kw.get("recommended", {}), "pb_cfg": kw.get("pb_cfg") or qpb.load(),
            "books": hunt_triage.runbooks()}


def stored(alert_row, alerts_all, findings=(), lookup=None, siem_run=None, rec_id=1):
    inv = hunt_soc.investigate(alert_row, alerts_all, list(findings), {}, lookup=lookup, siem_run=siem_run, now=NOW)
    return {"id": rec_id, "alert_id": alert_row["id"], "created_at": ts(0, 11), "investigation": inv}


def build(alerts, others=(), **kw):
    all_ = list(alerts) + list(others)
    d = data_for(all_, kw.pop("incident_map", None), kw.pop("investigations", None), **{k: kw.pop(k) for k in list(kw) if k in ("findings", "ownership", "owners", "assets", "identity", "recommended", "pb_cfg")})
    return incident_report.build(kw.pop("incident", INCIDENT), alerts, d, now=NOW, **kw)


def all_refs(r):
    """Every evidence reference cited anywhere in the report."""
    out = []
    for sect in ("summary",):
        out += [x for c in r[sect] for x in c["evidence"]]
    out += [x for c in r["verdict"]["rationale"] for x in c["evidence"]]
    for sect in ("history", "entities", "iocs", "attack", "timeline", "tool_actions", "recommended_actions"):
        out += [x for row in r[sect] for x in row["evidence"]]
    out += [x for c in r["followups"] for x in c["evidence"]]
    out += r["root_cause"]["evidence"]
    out += [x for n in r["attack_flow"]["nodes"] for x in n["evidence"]]
    return out


class LedgerRule(unittest.TestCase):
    def test_a_statement_without_evidence_is_dropped_and_counted(self):
        led = Ledger()
        ref = led.add("alert", "alert #1", "a")
        out = []
        self.assertIsNotNone(led.add_claim(out, "has evidence", [ref]))
        self.assertIsNone(led.add_claim(out, "no refs", []))
        self.assertIsNone(led.add_claim(out, "unknown ref", ["E99"]))
        self.assertEqual([c["text"] for c in out], ["has evidence"])
        self.assertEqual(led.dropped, ["no refs", "unknown ref"])

    def test_a_caller_can_keep_it_marked_not_evidenced(self):
        led = Ledger()
        c = led.claim("a guess", [], keep_unevidenced=True)
        self.assertEqual((c["status"], c["evidence"]), ("not evidenced", []))

    def test_the_same_evidence_gets_one_reference(self):
        led = Ledger()
        self.assertEqual(led.add("alert", "alert #1", "x", key=("alert", 1)), led.add("alert", "alert #1", "x", key=("alert", 1)))
        self.assertEqual(len(led.items), 1)

    def test_every_statement_in_a_built_report_cites_listed_evidence(self):
        a = alert(1)
        r = build([a], investigations={1: stored(a, [a])})
        listed = {e["ref"] for e in r["evidence"]}
        refs = all_refs(r)
        self.assertTrue(refs)
        self.assertTrue(set(refs) <= listed)
        for sect in (r["summary"], r["verdict"]["rationale"], r["history"], r["entities"], r["iocs"], r["recommended_actions"]):
            for row in sect:
                self.assertTrue(row.get("evidence"), row)


class HistoricalCorrelation(unittest.TestCase):
    def setUp(self):
        self.a = alert(1, host="WEB-1", user="bob")
        self.others = [alert(2, host="WEB-1", user="carol", days_ago=10, disposition="true-positive", status="closed", ips=()), alert(3, host="WEB-1", user="dave", days_ago=40, disposition="benign", status="closed", ips=()),
                       alert(4, host="WEB-1", user="erin", days_ago=200, ips=()), alert(5, host="DB-9", user="bob", days_ago=5, ips=(), rule="other")]

    def row(self, r, kind, value):
        return next(h for h in r["history"] if h["kind"] == kind and h["value"] == value)

    def test_counts_are_exact_inside_the_look_back_and_old_alerts_are_left_out(self):
        r = build([self.a], self.others, incident_map={2: 7, 3: 7})
        h = self.row(r, "host", "WEB-1")
        self.assertEqual((h["alerts"], h["true_positive"], h["noise"], h["open"], h["other_incidents"], h["look_back_days"]), (2, 1, 1, 0, 1, 90))
        self.assertEqual(h["alert_ids"], [3, 2])
        self.assertEqual((h["first_seen"][:10], h["last_seen"][:10]), (ts(40)[:10], ts(10)[:10]))
        self.assertIn("2 other alert(s)", h["text"])
        self.assertEqual(self.row(r, "user", "bob")["alerts"], 1)

    def test_none_is_said_plainly_with_the_window(self):
        r = build([self.a], self.others)
        h = self.row(r, "address", "185.220.101.9")
        self.assertEqual(h["alerts"], 0)
        self.assertTrue(h["text"].startswith("None in 90 days"))

    def test_the_incidents_own_alerts_are_not_counted_as_history(self):
        b = alert(6, host="WEB-1", user="bob", role="correlated")
        r = build([self.a, b], self.others)
        self.assertEqual(self.row(r, "host", "WEB-1")["alerts"], 2)

    def test_a_window_longer_than_stored_data_is_flagged_not_pretended(self):
        recent = [alert(2, host="X-1", user="u", days_ago=3, ips=())]
        r = build([alert(1, host="NEW-1", user="zed")], recent)
        h = self.row(r, "host", "NEW-1")
        self.assertEqual(h["covered_days"], 3)
        self.assertIn("only since", h["text"])

    def test_a_shorter_window_leaves_out_what_is_older(self):
        pb = qpb.load()
        pb["history_days"] = 30
        r = build([self.a], self.others, pb_cfg=pb)
        self.assertEqual((self.row(r, "host", "WEB-1")["alerts"], r["look_back_days"]), (1, 30))


class IocsAndReputation(unittest.TestCase):
    def setUp(self):
        self.a = alert(1)
        self.others = [alert(2, host="WEB-2", user="carol", ips=("185.220.101.9",), days_ago=2), alert(3, host="DB-1", user="carol", ips=("185.220.101.9",), days_ago=3), alert(4, host="DB-2", user="dave", ips=("8.8.4.4",))]

    def ioc(self, r, v):
        return next(i for i in r["iocs"] if i["value"] == v)

    def test_blast_radius_counts_hosts_users_alerts_and_incidents_in_quantas_data(self):
        r = build([self.a], self.others, incident_map={1: 1, 2: 2, 3: 3})
        b = self.ioc(r, "185.220.101.9")["blast_radius"]
        self.assertEqual((b["alerts"], b["hosts"], b["users"], b["incidents"]), (3, 3, 2, 3))
        self.assertEqual(b["incident_ids"], [1, 2, 3])
        self.assertEqual(self.ioc(r, "8.8.4.4")["blast_radius"]["alerts"], 1) if any(i["value"] == "8.8.4.4" for i in r["iocs"]) else None

    def test_nothing_looked_up_means_unknown_never_clean(self):
        r = build([self.a], self.others)
        i = self.ioc(r, "185.220.101.9")
        self.assertEqual((i["verdict"], i["reputation"]["status"]), ("unknown", "not-looked-up"))
        self.assertEqual(r["mode"]["reputation"], "not-run")
        self.assertTrue(any("not looked up" in g.lower() for g in r["gaps"]))

    def test_a_private_address_is_never_sent(self):
        sent = []

        def look(v):
            sent.append(v)
            return {"result": "seen", "malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 5, "total": 55}

        r = build([self.a], lookup=look, lookup_name="vt")
        self.assertEqual(sent, ["185.220.101.9"])
        self.assertEqual(self.ioc(r, "10.0.0.5")["reputation"]["status"], "private-not-sent")
        self.assertEqual(self.ioc(r, "10.0.0.5")["verdict"], "unknown")
        self.assertEqual(self.ioc(r, "185.220.101.9")["verdict"], "no-detections")
        self.assertEqual(r["mode"]["reputation"], "ran")

    def test_malicious_and_suspicious_are_separated_by_the_threshold(self):
        r = build([self.a], lookup=lambda v: {"result": "seen", "malicious": 30, "suspicious": 0, "harmless": 10, "undetected": 5, "total": 45})
        self.assertEqual(self.ioc(r, "185.220.101.9")["verdict"], "malicious")
        r = build([self.a], lookup=lambda v: {"result": "seen", "malicious": 2, "suspicious": 0, "harmless": 10, "undetected": 5, "total": 17})
        self.assertEqual(self.ioc(r, "185.220.101.9")["verdict"], "suspicious")
        r = build([self.a], lookup=lambda v: {"result": "unknown", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total": 0})
        self.assertEqual(self.ioc(r, "185.220.101.9")["verdict"], "unknown")

    def test_an_unavailable_service_is_reported_and_nothing_is_guessed(self):
        def boom(v):
            raise RuntimeError("rate limited")

        r = build([self.a], lookup=boom)
        i = self.ioc(r, "185.220.101.9")
        self.assertEqual((i["verdict"], i["reputation"]["status"]), ("unknown", "lookup-failed"))
        self.assertEqual(r["mode"]["reputation"], "failed")
        self.assertTrue(any("unavailable" in x for x in r["limits"]))

    def test_an_earlier_lookup_in_a_stored_investigation_is_used_and_attributed(self):
        a = self.a
        rec = stored(a, [a], lookup=lambda v: {"result": "seen", "malicious": 40, "suspicious": 0, "harmless": 1, "undetected": 1, "total": 42})
        r = build([a], investigations={1: rec})
        i = self.ioc(r, "185.220.101.9")
        self.assertEqual((i["verdict"], i["reputation"]["source"]), ("malicious", "stored investigation #1"))

    def test_the_lookup_limit_is_enforced(self):
        pb = qpb.load()
        pb["reputation"]["max_lookups"] = 1
        a = alert(1, ips=("185.220.101.9", "8.8.8.8", "1.1.1.1"))
        calls = []
        r = build([a], lookup=lambda v: calls.append(v) or {"result": "seen", "malicious": 0, "suspicious": 0, "harmless": 3, "undetected": 0, "total": 3}, pb_cfg=pb)
        self.assertEqual(len(calls), 1)
        self.assertEqual(sum(1 for i in r["iocs"] if i["reputation"]["status"] == "not-looked-up"), 2)


class UnknownStaysUnknown(unittest.TestCase):
    def test_owner_privilege_criticality_and_tool_action_default_to_unknown(self):
        r = build([alert(1)])
        host = next(e for e in r["entities"] if e["kind"] == "host")
        user = next(e for e in r["entities"] if e["kind"] == "user")
        self.assertEqual((host["owner"], host["team"], host["criticality"]), ("unknown", "unknown", "unknown"))
        self.assertEqual((user["privilege"], user["privilege_detail"]), ("unknown", "access records are not loaded"))
        self.assertEqual((r["tool_actions"][0]["action"], r["tool_actions"][0]["state"]), ("unknown", "unknown"))

    def test_privilege_is_reported_only_from_access_records(self):
        ident = {"bob": {"privileged": True, "systems": {"PROD-DB"}}, "other": {"privileged": False, "systems": set()}}
        r = build([alert(1, user="bob")], identity=ident)
        self.assertEqual(next(e for e in r["entities"] if e["kind"] == "user")["privilege"], "privileged")
        r = build([alert(1, user="zed")], identity=ident)
        u = next(e for e in r["entities"] if e["kind"] == "user")
        self.assertEqual((u["privilege"], u["privilege_detail"]), ("unknown", "the account is not in the access records Quanta holds"))
        r = build([alert(1, user="other")], identity=ident)
        self.assertEqual(next(e for e in r["entities"] if e["kind"] == "user")["privilege"], "not-privileged")

    def test_owner_team_and_criticality_when_known(self):
        r = build([alert(1)], ownership={"web-1": {"owner": "ana", "team": "web"}}, assets={"web-1": {"type": "unix-server", "criticality": "high"}},
                  findings=[{"id": "F1", "asset": {"name": "WEB-1"}, "kev": {"listed": True}, "status": "open"}, {"id": "F2", "asset": {"name": "WEB-1"}, "status": "open"}])
        h = next(e for e in r["entities"] if e["kind"] == "host")
        self.assertEqual((h["owner"], h["team"], h["criticality"], h["open_findings"], h["kev_findings"]), ("ana", "web", "high", 2, 1))

    def test_what_the_tools_did_comes_only_from_the_alert(self):
        r = build([alert(1, action_taken="Blocked by EDR"), alert(2, host="W2", action_taken=None, role="correlated")])
        by = {t["alert_id"]: t for t in r["tool_actions"]}
        self.assertEqual((by[1]["state"], by[1]["action"]), ("blocked", "Blocked by EDR"))
        self.assertEqual((by[2]["state"], by[2]["action"]), ("unknown", "unknown"))
        self.assertTrue(any("unknown for 1 alert" in g for g in r["gaps"]))

    def test_no_siem_is_stated_and_the_root_cause_is_a_hypothesis(self):
        r = build([alert(1)])
        self.assertEqual((r["mode"]["siem"], r["mode"]["stored_data_only"]), ("not-connected", True))
        self.assertIn("stored data only", r["live_search"]["note"])
        self.assertTrue(r["root_cause"]["is_hypothesis"])
        self.assertTrue(r["root_cause"]["text"].startswith("Hypothesis"))
        self.assertTrue(r["root_cause"]["gaps"])


class VerdictAndActions(unittest.TestCase):
    def test_no_investigation_means_action_needed_with_that_said(self):
        r = build([alert(1)])
        self.assertEqual((r["verdict"]["label"], r["verdict"]["basis"], r["verdict"]["confidence"]), ("action-needed", "automated", "unknown"))
        self.assertIn("No investigation has been saved", r["verdict"]["rationale"][0]["text"])

    def test_a_true_positive_signal_carries_its_evidence(self):
        a = alert(1)
        fnd = {"id": "FIND-1", "title": "Log4Shell", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": "WEB-1"}, "attack_techniques": [{"technique_id": "T1190"}],
               "kev": {"listed": True}, "epss": {"score": 0.9}, "status": "open"}
        rec = stored(a, [a], findings=[fnd], lookup=lambda v: {"result": "seen", "malicious": 30, "total": 80})
        r = build([a], investigations={1: rec})
        self.assertEqual(r["verdict"]["label"], "true-positive")
        text = " ".join(c["text"] for c in r["verdict"]["rationale"])
        self.assertIn("known-exploited", text)
        self.assertIn("185.220.101.9", text)
        kinds = {e["kind"] for e in r["evidence"]}
        self.assertTrue({"finding", "reputation", "investigation"} <= kinds)

    def test_a_signal_with_no_records_behind_it_is_dropped(self):
        a = alert(1)
        rec = stored(a, [a])
        rec["investigation"]["signals"]["kev_match"] = True                      # claimed, but the stored investigation lists no known-exploited finding
        rec["investigation"]["signals"]["ioc_malicious"] = True                  # claimed, but no indicator was flagged
        r = build([a], investigations={1: rec})
        text = " ".join(c["text"] for c in r["verdict"]["rationale"])
        self.assertNotIn("known-exploited", text)
        self.assertNotIn("flagged by the reputation", text)
        self.assertGreaterEqual(r["dropped_statements"], 2)

    def test_all_false_positive_signals_give_a_false_positive_and_an_analyst_verdict_wins(self):
        a = alert(1)
        rec = stored(a, [a])
        rec["investigation"]["verdict"] = "likely-false-positive"
        r = build([a], investigations={1: rec})
        self.assertEqual(r["verdict"]["label"], "false-positive")
        inc = {**INCIDENT, "status": "resolved", "verdict": "true-positive"}
        r = build([a], investigations={1: rec}, incident=inc)
        self.assertEqual((r["verdict"]["label"], r["verdict"]["basis"]), ("true-positive", "analyst-resolved"))

    def test_actions_say_which_need_a_second_person(self):
        rec_ = {"runbooks": [{"id": "rb-exploit-public-app", "name": "x"}], "playbooks": [{"playbook_id": "pb1", "name": "Isolate host", "basis": "history", "why": "worked before", "needs_second_person": True},
                                                                                       {"playbook_id": "pb2", "name": "Enrich", "basis": "trigger", "why": "matches", "needs_second_person": False}],
                "next_steps": ["Accept the incident to start the clock and begin triage."]}
        r = build([alert(1)], recommended=rec_)
        acts = {x["action"]: x for x in r["recommended_actions"]}
        self.assertTrue(acts["Run playbook 'Isolate host' (dry run first)"]["needs_second_person"])
        self.assertFalse(acts["Run playbook 'Enrich' (dry run first)"]["needs_second_person"])
        self.assertTrue(any(x["needs_second_person"] and "Contain" in x["action"] for x in r["recommended_actions"]))
        self.assertFalse(acts["Accept the incident to start the clock and begin triage."]["needs_second_person"])
        for x in r["recommended_actions"]:
            self.assertTrue(x["evidence"])

    def test_attack_rows_carry_the_next_step_and_flow_is_data_for_drawing(self):
        a, b = alert(1), alert(2, technique="T1059", host="WEB-1", days_ago=0, title="PowerShell child", role="correlated")
        r = build([a, b])
        t = {x["technique"]: x for x in r["attack"]}
        self.assertEqual(set(t), {"T1190", "T1059"})
        self.assertTrue(t["T1190"]["next_step"])
        f = r["attack_flow"]
        self.assertEqual(f["stages"], ["Initial Access", "Execution"])
        alerts_nodes = [n for n in f["nodes"] if n["kind"] == "alert"]
        self.assertEqual([n["stage"] for n in alerts_nodes], ["Initial Access", "Execution"])
        self.assertTrue(any(e["kind"] == "next-stage" for e in f["edges"]))
        self.assertTrue(any(n["kind"] == "entity" for n in f["nodes"]))
        c = alert(3, technique=None, title="Odd", host="WEB-1")
        self.assertIn("Unmapped", build([a, c])["attack_flow"]["stages"])


class QueryPlaybook(unittest.TestCase):
    def planned(self, n=5, cap=90):
        a = alert(1, ips=("185.220.101.9",), domains=["evil.example.org"], hashes=["a" * 64])
        a["entities"]["domains"] = ["evil.example.org"]
        return qpb.plan([a], qpb.load(), cap)

    def test_plan_is_technique_specific_first_and_the_look_back_is_capped(self):
        planned, skipped = self.planned(cap=3)
        self.assertGreaterEqual(len(planned), 4)
        self.assertEqual(planned[0]["technique"], "T1190")
        self.assertEqual(planned[0]["id"], "web-exploit-requests")
        self.assertTrue(all(p["days"] <= 3 for p in planned))
        self.assertEqual(skipped, [])
        planned, _ = self.planned(cap=365)
        self.assertEqual(max(p["days"] for p in planned), 30)               # the pattern's own limit still applies

    def test_an_unsafe_value_is_refused_not_escaped(self):
        a = alert(1, host='WEB-1" | delete')
        planned, skipped = qpb.plan([a], qpb.load(), 90)
        self.assertFalse(any('delete' in p["query"] for p in planned))
        self.assertTrue(skipped)

    def go(self, bud, results=None, n=None, clock=None):
        planned, _ = self.planned()
        planned = planned[: n or len(planned)]
        calls = []

        def run_fn(q, earliest, max_rows):
            calls.append((q, earliest, max_rows))
            return (results or (lambda i: {"count": 1, "rows": [{"host": "WEB-1"}]}))(len(calls))

        out = qpb.run(planned, run_fn, bud, **({"clock": clock} if clock else {}))
        return out, calls, planned

    BUD = {"max_queries": 6, "max_rows": 100, "rows_per_query": 10, "time_budget_seconds": 60, "max_consecutive_errors": 2}

    def test_completed_when_nothing_is_left(self):
        out, calls, planned = self.go({**self.BUD, "max_queries": 99})
        self.assertEqual((out["stop_reason"], out["queries_run"], len(calls), out["not_run"]), ("completed", len(planned), len(planned), []))

    def test_query_budget_stop_is_recorded_and_the_rest_listed(self):
        out, calls, planned = self.go({**self.BUD, "max_queries": 2})
        self.assertEqual((out["stop_reason"], out["queries_run"], len(calls)), ("stopped: query budget", 2, 2))
        self.assertEqual(len(out["not_run"]), len(planned) - 2)

    def test_exactly_the_budget_is_completed_not_stopped(self):
        out, _, planned = self.go({**self.BUD, "max_queries": 3}, n=3)
        self.assertEqual(out["stop_reason"], "completed")

    def test_row_budget_stop(self):
        out, calls, _ = self.go({**self.BUD, "max_rows": 2, "rows_per_query": 5}, results=lambda i: {"count": 9, "rows": [{"h": 1}, {"h": 2}]})
        self.assertEqual((out["stop_reason"], out["queries_run"], out["rows_seen"]), ("stopped: row budget", 1, 2))

    def test_the_rows_asked_for_never_exceed_what_is_left(self):
        out, calls, _ = self.go({**self.BUD, "max_rows": 12, "rows_per_query": 10}, results=lambda i: {"count": 9, "rows": [{"h": k} for k in range(10)]})
        self.assertEqual([c[2] for c in calls][:2], [10, 2])

    def test_time_budget_stop(self):
        ticks = iter([0, 0, 5, 5, 99, 99, 99, 99, 99, 99, 99, 99])
        out, calls, _ = self.go({**self.BUD, "time_budget_seconds": 10}, clock=lambda: next(ticks))
        self.assertEqual(out["stop_reason"], "stopped: time budget")
        self.assertLess(out["queries_run"], 6)

    def test_repeated_errors_stop_it_and_a_failure_is_not_a_hit(self):
        def bad(i):
            raise RuntimeError("search failed")

        out, calls, _ = self.go(self.BUD, results=bad)
        self.assertEqual((out["stop_reason"], out["queries_run"]), ("stopped: repeated errors", 2))
        self.assertTrue(all(r["error"] and r["count"] is None for r in out["results"]))

    def test_it_never_plans_from_results_so_it_cannot_recurse(self):
        out, calls, planned = self.go({**self.BUD, "max_queries": 99}, results=lambda i: {"count": 50, "rows": [{"host": "OTHER-HOST", "src_ip": "9.9.9.9"}]})
        self.assertEqual([c[0] for c in calls], [p["query"] for p in planned])
        self.assertFalse(any("OTHER-HOST" in c[0] or "9.9.9.9" in c[0] for c in calls))

    def test_build_records_live_results_and_the_stop_reason_as_evidence(self):
        pb = qpb.load()
        pb["budget"]["max_queries"] = 2
        seen = []

        def run_fn(q, earliest, max_rows):
            seen.append((q, earliest))
            return {"count": 4, "rows": [{"host": "WEB-1"}]}

        r = build([alert(1)], siem_run=run_fn, siem_connected=True, siem_name="splunk", pb_cfg=pb, cap_days=7, live_requested=True)
        live = r["live_search"]
        self.assertEqual((live["ran"], live["stop_reason"], live["queries_run"], live["connection"]), (True, "stopped: query budget", 2, "splunk"))
        self.assertTrue(all(e.startswith("-") and int(e[1:-1]) <= 7 for _, e in seen))
        self.assertEqual(r["mode"]["siem"], "ran")
        self.assertTrue(any(x["kind"] == "search" and x["source"].startswith("SIEM, read-only") for x in r["references"]))
        self.assertTrue(any("stopped: query budget" in c["text"] for c in r["verdict"]["rationale"]))
        self.assertTrue(all(q["evidence"] for q in live["results"]))

    def test_a_connected_siem_that_was_not_asked_is_not_run(self):
        r = build([alert(1)], siem_run=None, siem_connected=True)
        self.assertEqual((r["live_search"]["ran"], r["mode"]["siem"]), (False, "connected-not-run"))


class Followups(unittest.TestCase):
    def setUp(self):
        self.a = alert(1)
        self.others = [alert(2, host="WEB-2", user="carol", ips=("185.220.101.9",), days_ago=2, disposition="true-positive", status="closed"), alert(3, host="DB-1", user="dave", ips=("185.220.101.9",), days_ago=300)]
        self.data = {"alerts_all": [self.a] + self.others, "incident_map": {2: 5}}

    def ask(self, q, **kw):
        return followup.answer(INCIDENT, [self.a], q, self.data, now=NOW, **kw)

    def test_the_value_is_found_in_the_question_and_counted_exactly(self):
        r = self.ask("Has 185.220.101.9 been seen before?")
        self.assertEqual((r["value"], r["kind"], r["answerable"]), ("185.220.101.9", "entity-history", True))
        self.assertIn("1 earlier alert(s)", r["answer"])                      # the 300-day-old one is outside the window
        self.assertIn("1 closed as true positive", r["answer"])
        self.assertTrue(any(e["kind"] == "history" and "1 stored alert" in e["detail"] for e in r["evidence"]))

    def test_none_in_n_days_is_an_answer_with_evidence(self):
        r = self.ask("history of dave", kind="entity-history", value="dave")
        self.assertTrue(r["answer"].startswith("None in 90 days"))
        self.assertTrue(r["evidence"])

    def test_where_else_lists_other_hosts(self):
        r = self.ask("Where else was this seen?", kind="indicator-sightings", value="185.220.101.9")
        self.assertIn("web-2", r["answer"])

    def test_a_question_that_names_nothing_is_not_guessed_at(self):
        r = self.ask("Is this bad?")
        self.assertFalse(r["answerable"])
        self.assertIn("Cannot be answered from stored data", r["answer"])
        self.assertEqual(r["evidence"], [])

    def test_a_known_entity_in_the_question_is_used(self):
        r = self.ask("what has bob done elsewhere")
        self.assertEqual(r["value"], "bob")

    def test_siem_is_used_only_when_given_and_failures_are_reported(self):
        calls = []
        r = self.ask("history of 185.220.101.9", siem_run=lambda q, e, m: calls.append((q, e)) or {"count": 3, "rows": [{"hosts": "2"}]}, siem_name="splunk")
        self.assertEqual(len(calls), 1)
        self.assertIn("SIEM, last 90 days: 3 result row(s)", r["answer"])
        self.assertEqual(r["evidence"][-1]["kind"], "siem")

        def bad(q, e, m):
            raise RuntimeError("down")

        r = self.ask("history of 185.220.101.9", siem_run=bad)
        self.assertIn("The SIEM search failed", r["answer"])

    def test_a_bad_kind_is_refused(self):
        with self.assertRaises(ValueError):
            self.ask("x 1.2.3.4", kind="rumours")

    def test_merged_followups_appear_in_the_report_and_unevidenced_ones_do_not(self):
        good = {"id": 1, "question": "q1", "answer": "a1", "kind": "entity-history", "merged": True, "evidence": [{"kind": "history", "source": "count", "detail": "0 stored alerts", "at": None}]}
        bare = {"id": 2, "question": "q2", "answer": "a2", "kind": "entity-history", "merged": True, "evidence": []}
        pending = {"id": 3, "question": "q3", "answer": "a3", "kind": "entity-history", "merged": False, "evidence": [{"kind": "history", "source": "c", "detail": "d"}]}
        r = build([alert(1)], followups=[good, bare, pending])
        self.assertEqual([f["id"] for f in r["followups"]], [1])
        self.assertGreaterEqual(r["dropped_statements"], 1)


class ItsmIntake(unittest.TestCase):
    def test_severity_mapping(self):
        self.assertEqual(itsm.map_severity("servicenow", 1), ("Critical", True))
        self.assertEqual(itsm.map_severity("servicenow", "3 - Moderate"), ("Medium", True))
        self.assertEqual(itsm.map_severity("jira", "Highest"), ("Critical", True))
        self.assertEqual(itsm.map_severity("jira", "Low"), ("Low", True))
        self.assertEqual(itsm.map_severity("jira", None), ("Medium", False))
        self.assertEqual(itsm.map_severity("other", "weird"), ("Medium", False))

    def test_the_ticket_becomes_an_alert_and_says_when_it_defaulted(self):
        a = itsm.alert_from_ticket({"system": "servicenow", "ticket_id": "INC0012", "title": "Suspicious logon", "description": "from 203.0.113.9", "asset": "WEB-1", "user": "bob",
                                   "source_ip": "198.51.100.4", "domains": ["x.example.org"]}, "itsm:servicenow")
        self.assertEqual((a["external_id"], a["severity"], a["asset"], a["source"]), ("servicenow:INC0012", "Medium", "WEB-1", "itsm:servicenow"))
        self.assertIn("no recognisable severity", a["detail"])
        self.assertEqual(set(a["entities"]["ips"]), {"203.0.113.9", "198.51.100.4"})
        self.assertEqual((a["entities"]["user"], a["entities"]["domains"]), ("bob", ["x.example.org"]))

    def test_bad_tickets_are_refused(self):
        for body in ({"ticket_id": "bad id!", "title": "x"}, {"ticket_id": "A1", "title": ""}, {"ticket_id": "A1", "title": "x", "system": "carrier-pigeon"}):
            with self.assertRaises(ValueError):
                itsm.alert_from_ticket(body, "itsm:x")


class PostBack(unittest.TestCase):
    def report(self):
        a = alert(1)
        return build([a], recommended={"next_steps": ["Isolate the host if exploitation is confirmed."]})

    class Fake:
        def __init__(self, fail=False):
            self.sent, self.fail = [], fail

        def add_comment(self, ref, text):
            if self.fail:
                raise RuntimeError("403")
            self.sent.append((ref, text))

    def test_the_comment_is_concise_and_carries_verdict_summary_actions_and_a_link(self):
        r = self.report()
        text = itsm.compose_comment(r)
        self.assertIn("Verdict: action-needed", text)
        self.assertIn("Recommended actions:", text)
        self.assertIn("(needs a second person)", text)
        self.assertIn("incident #1", text)
        self.assertLessEqual(len(text), 3000)

    def test_dry_run_then_confirm_then_never_twice(self):
        r = self.report()
        fake = self.Fake()
        links = [{"system": "servicenow", "external_ref": "INC0012", "connection_id": None}, {"system": "jira", "external_ref": "SEC-4", "connection_id": None}, {"system": "other", "external_ref": "X1"}]
        make = lambda system, cid: (fake, "n") if system == "servicenow" else (None, None)  # noqa: E731
        res, text = itsm.post(r, links, make, set(), confirm=False)
        self.assertEqual([x["status"] for x in res], ["dry-run", "no-connection", "unsupported"])
        self.assertEqual(fake.sent, [])
        res, _ = itsm.post(r, links, make, set(), confirm=True)
        self.assertEqual([x["status"] for x in res], ["posted", "no-connection", "unsupported"])
        self.assertEqual(fake.sent, [("INC0012", text)])
        done = {("servicenow", "INC0012", res[0]["comment_digest"])}
        res, _ = itsm.post(r, links, make, done, confirm=True)
        self.assertEqual(res[0]["status"], "already-posted")
        self.assertEqual(len(fake.sent), 1)

    def test_one_failure_does_not_stop_the_other_tickets(self):
        r = self.report()
        bad, ok = self.Fake(fail=True), self.Fake()
        links = [{"system": "servicenow", "external_ref": "INC1"}, {"system": "jira", "external_ref": "SEC-1"}]
        res, _ = itsm.post(r, links, lambda s, c: (bad, "a") if s == "servicenow" else (ok, "b"), set(), confirm=True)
        self.assertEqual([x["status"] for x in res], ["failed", "posted"])
        self.assertEqual(len(ok.sent), 1)


class Storage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")

    def tearDown(self):
        self.e.dispose()
        self.tmp.cleanup()

    def test_reports_are_versioned_and_followups_merge_only_within_their_incident(self):
        a = inv_store.save_report(1, {"x": 1}, "me", engine=self.e)
        b = inv_store.save_report(1, {"x": 2}, "me", live=True, engine=self.e)
        self.assertEqual((a["version"], b["version"], inv_store.latest_report(1, self.e)["x"]), (1, 2, 2))
        self.assertIsNone(inv_store.latest_report(2, self.e))
        f = inv_store.add_followup(1, "entity-history", "bob", "q", "a", [{"id": 1}], [{"kind": "history"}], True, "me", self.e)
        g = inv_store.add_followup(2, "entity-history", "bob", "q", "a", None, [], True, "me", self.e)
        self.assertEqual(inv_store.set_merged(1, [f["id"], g["id"]], True, "me", self.e), [f["id"]])
        self.assertTrue(inv_store.get_followup(f["id"], self.e)["merged"])
        self.assertFalse(inv_store.get_followup(g["id"], self.e)["merged"])
        inv_store.set_merged(1, [f["id"]], False, "me", self.e)
        self.assertFalse(inv_store.get_followup(f["id"], self.e)["merged"])

    def test_the_migration_is_idempotent_and_registered(self):
        db_module.metadata.create_all(self.e, tables=[db_module.schema_migrations] if hasattr(db_module, "schema_migrations") else None)
        for _ in range(3):
            migrations._m011_investigation_reports(self.e)
        from sqlalchemy import inspect
        names = set(inspect(self.e).get_table_names())
        self.assertTrue({"investigation_reports", "incident_followups", "hunt_allowlist", "hunt_report_meta"} <= names)
        self.assertIn(11, [m[0] for m in migrations.MIGRATIONS])


if __name__ == "__main__":
    unittest.main()
