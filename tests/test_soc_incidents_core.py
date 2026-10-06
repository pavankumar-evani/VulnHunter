"""
Tests for SOC incident automation (remediation/soc/incidents): correlation with reasons, duplicates, kill-chain severity roll-up, the deterministic summary,
auto-routing (tier, skills, availability, workload, continuity, fairness, capacity, no-qualified fallback, SLA escalation, rebalance), auto-close under the
decision gate with undo, the state machine and its verdict requirement, merge/split, the manual exception, the timeline, the live feed and the migration.
"""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine, func, select, update  # noqa: E402

from remediation.decisions import calibration, registry, service as decision_service  # noqa: E402
from remediation.hunting import store as hunt_store  # noqa: E402
from remediation.soc import cases  # noqa: E402
from remediation.soc.incidents import correlate, migrate, roster, routing, service, store, stream, summary  # noqa: E402
from remediation.utils import db as db_module, migrations  # noqa: E402

T0 = datetime.datetime(2026, 10, 15, 9, 0, tzinfo=datetime.timezone.utc)   # a Thursday, 09:00 UTC
SIGNALS = ["ioc_malicious", "kev_match", "recurrence", "siem_corroboration", "critical_severity", "rule_noise_history", "clean_indicators", "prior_benign_same_host"]
NOTE = "Checked the host and the account; contained the process and confirmed the alert is real."


def at(minutes):
    return T0 + datetime.timedelta(minutes=minutes)


def inv(verdict="likely-true-positive", band="high", signals=(), category="endpoint", cves=(), kev=(), open_findings=None, owner=None):
    sig = {k: (k in signals) for k in SIGNALS}
    fnds = [{"id": f"F-{c}", "cve": c, "kev": c in kev, "related_to_alert": True, "severity": "High", "title": "x"} for c in list(cves) + [k for k in kev if k not in cves]]
    return {"alert_id": 0, "category": category, "verdict": verdict, "confidence": band, "signals": sig, "reasons": [f"Signals: {', '.join(signals) or 'none'}."],
            "host": {"asset": None, "owner": owner, "open_findings": len(fnds) if open_findings is None else open_findings, "kev_findings": len(kev), "findings": fnds},
            "runbook": {"id": "rb-generic", "name": "Generic runbook"}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.e)
        self.n = 0

    def tearDown(self):
        self.e.dispose()
        self.tmp.cleanup()

    def alert(self, minutes=0, title="Suspicious process", severity="High", asset="WEB-1", technique="T1059", rule="rule-a", entities=None, **kw):
        self.n += 1
        a, _ = hunt_store.receive_alert({"external_id": f"x{self.n}", "title": title, "severity": severity, "asset": asset, "technique": technique, "rule_name": rule,
                                         "entities": entities, **kw}, self.e)
        with self.e.begin() as conn:
            conn.execute(update(db_module.soc_alerts).where(db_module.soc_alerts.c.id == a["id"]).values(received_at=store.iso(at(minutes))))
        return hunt_store.get_alert(a["id"], self.e)

    def ingest(self, minutes=0, inv_=None, **kw):
        a = self.alert(minutes, **kw)
        return service.ingest(a, inv_ or inv(), service.Context(), self.e, at(minutes)), a

    def analyst(self, email, tier=1, **fields):
        roster.update_analyst(email, {"tier": tier, **fields}, self.e)

    def inc(self, i, now=T0):
        return store.get_incident(i, self.e, now)

    def kinds(self, i):
        return [x["kind"] for x in store.events(i, self.e)]


class Correlation(Base):
    def test_same_host_joins_with_reason_and_negative_cases_do_not(self):
        a, _ = self.ingest(0)
        b, _ = self.ingest(10, title="Second", rule="rule-b", technique="T1055")
        self.assertEqual(a["id"], b["id"])
        reasons = {r["reason"] for r in self.inc(a["id"])["alerts"][1]["reasons"]}
        self.assertIn("shared_host", reasons)
        # a different host, rule, technique and nothing else in common is not grouped
        c, _ = self.ingest(15, asset="DB-9", rule="rule-z", technique="T1190")
        self.assertNotEqual(a["id"], c["id"])
        self.assertEqual(len(store.list_incidents(self.e)), 2)

    def test_outside_the_window_is_a_new_incident(self):
        a, _ = self.ingest(0)
        b, _ = self.ingest(60 * 30, title="Much later")   # 30 hours; window is 24
        self.assertNotEqual(a["id"], b["id"])

    def test_shared_user_across_hosts_joins(self):
        a, _ = self.ingest(0, asset="PC-1", entities={"user": "jdoe"}, rule="r1")
        b, _ = self.ingest(5, asset="PC-2", entities={"user": "JDoe"}, rule="r2", technique="T1021")
        self.assertEqual(a["id"], b["id"])
        self.assertIn("shared_user", {r["reason"] for r in self.inc(a["id"])["alerts"][1]["reasons"]})

    def test_public_indicator_joins_but_a_shared_private_address_is_just_a_host(self):
        a, _ = self.ingest(0, asset="A", rule="r1", entities={"ips": ["185.220.101.9"]})
        b, _ = self.ingest(5, asset="B", rule="r2", technique="T1071", entities={"ips": ["185.220.101.9"]})
        self.assertEqual(a["id"], b["id"])
        self.assertIn("shared_indicator", {r["reason"] for r in self.inc(a["id"])["alerts"][1]["reasons"]})
        self.assertEqual(correlate.keys({"entities": {"ips": ["10.0.0.5"]}})["indicators"], set())
        self.assertEqual(correlate.keys({"entities": {"ips": ["10.0.0.5"]}})["hosts"], {"10.0.0.5"})

    def test_rule_burst_alone_is_not_enough_but_with_a_shared_cve_it_is(self):
        a, _ = self.ingest(0, asset="A", rule="burst", technique="T1190", inv_=inv(cves=["CVE-2024-1"]))
        b, _ = self.ingest(5, asset="B", rule="burst", technique="T1190", inv_=inv())   # same rule (0.6) + same technique (0.3) = 0.9: below the 1.0 threshold
        self.assertNotEqual(a["id"], b["id"])
        c, _ = self.ingest(8, asset="C", rule="burst", technique="T1190", inv_=inv(cves=["CVE-2024-1"]))
        self.assertEqual(c["id"], a["id"])
        why = {r["reason"] for r in self.inc(a["id"])["alerts"][-1]["reasons"]}
        self.assertTrue({"same_rule_burst", "shared_cve"} <= why)

    def test_duplicates_are_grouped_not_dropped(self):
        a, first = self.ingest(0)
        b, dup = self.ingest(10, title="Same again")      # same rule, same host, 10 minutes later
        out = self.inc(a["id"])
        self.assertEqual((a["id"], out["duplicate_count"], len(out["alerts"])), (b["id"], 1, 2))
        self.assertEqual([x["role"] for x in out["alerts"]], ["primary", "duplicate"])
        self.assertEqual(hunt_store.get_alert(dup["id"], self.e)["status"], "investigating")   # kept, visible, still open
        self.assertEqual(len(store.list_incidents(self.e)), 1)

    def test_idempotent_per_alert(self):
        a, alert = self.ingest(0)
        again = service.ingest(alert, inv(), service.Context(), self.e, at(1))
        self.assertEqual(again["id"], a["id"])
        self.assertEqual(len(self.inc(a["id"])["alerts"]), 1)


class KillChainAndSeverity(Base):
    def test_progression_raises_severity_with_reasons(self):
        a, _ = self.ingest(0, severity="Medium", technique="T1566", rule="r1")           # Initial Access
        self.ingest(10, severity="Medium", technique="T1059", rule="r2")                   # Execution
        self.assertEqual(self.inc(a["id"])["severity"], "Medium")                           # two early stages: no raise
        self.ingest(20, severity="Medium", technique="T1021", rule="r3")                   # Lateral Movement (late)
        out = self.inc(a["id"])
        self.assertEqual([s["tactic"] for s in out["kill_chain"]], ["Initial Access", "Execution", "Lateral Movement"])
        self.assertEqual((out["base_severity"], out["severity"]), ("Medium", "High"))
        ev = [e for e in out["timeline"] if e["kind"] == "severity_raised"]
        self.assertEqual(len(ev), 1)
        self.assertIn("kill chain", ev[0]["body"])

    def test_roll_up_unit(self):
        pol = store.policy()
        chain = lambda *t: correlate.kill_chain([{"id": i, "received_at": None, "facts": {"tactic": x}} for i, x in enumerate(t)], pol)  # noqa: E731
        self.assertEqual(correlate.roll_up_severity(["Low", "High"], chain("Execution"), pol)[:2], ("High", "High"))
        self.assertEqual(correlate.roll_up_severity(["Low", "High"], chain("Execution", "Persistence", "Discovery"), pol)[0], "Critical")
        self.assertEqual(correlate.roll_up_severity(["High"], chain("Execution", "Exfiltration"), pol)[0], "Critical")   # late stage after one earlier
        self.assertEqual(correlate.roll_up_severity(["Critical"], chain("Execution", "Exfiltration"), pol)[0], "Critical")   # capped
        self.assertEqual(correlate.kill_chain([{"id": 1, "received_at": None, "facts": {"tactic": "Not A Tactic"}}], pol), [])   # an unmapped tactic has no stage

    def test_severity_rise_reroutes_to_a_higher_tier(self):
        self.analyst("l1@t.test", 1)
        self.analyst("l3@t.test", 3)
        a, _ = self.ingest(0, severity="Low", technique="T1566", rule="r1")
        self.assertEqual((self.inc(a["id"])["tier"], self.inc(a["id"])["assignee"]), (1, "l1@t.test"))
        self.ingest(5, severity="Low", technique="T1059", rule="r2")
        self.ingest(9, severity="Low", technique="T1041", rule="r3")      # Exfiltration: late stage, three stages -> Medium, tier 3 by the late-stage rule
        out = self.inc(a["id"])
        self.assertEqual((out["tier"], out["assignee"]), (3, "l3@t.test"))
        self.assertTrue(any("late stage" in r for r in out["routing_reason"]))


class Summary(Base):
    def test_deterministic_and_uses_only_real_fields(self):
        a, _ = self.ingest(0, asset="WEB-1", technique="T1190", inv_=inv(signals=["kev_match"], kev=["CVE-2021-44228"], owner="web-team"), entities={"user": "svc-web"})
        s1 = self.inc(a["id"])["summary"]
        service.recompute(a["id"], self.e, at(0))
        self.assertEqual(s1, self.inc(a["id"])["summary"])
        for must in ("web-1", "svc-web", "CVE-2021-44228", "web-team", "Initial Access", "L2"):
            self.assertIn(must, s1)
        self.assertNotIn("no open findings", s1)

    def test_a_part_with_no_data_is_left_out(self):
        a, _ = self.ingest(0, asset=None, technique=None, inv_=inv(open_findings=None))
        text = self.inc(a["id"])["summary"]
        self.assertNotIn("Kill chain", text)
        self.assertNotIn("Vulnerability context", text.replace("Vulnerability context: Quanta holds no", "") if "holds no" not in text else "")
        prompt = summary.ai_prompt({**self.inc(a["id"]), "alert_count": 1})
        self.assertNotIn("Suspicious process", prompt)   # the prompt carries no alert text


class Routing(Base):
    def test_tier_required_rules(self):
        pol = store.policy()
        base = {"severity": "Medium", "confidence": 0.9, "hosts": ["a"]}
        self.assertEqual(routing.required_tier(base, pol)[0], 1)
        self.assertEqual(routing.required_tier({**base, "severity": "High"}, pol)[0], 2)
        self.assertEqual(routing.required_tier({**base, "kev": True}, pol)[0], 2)
        self.assertEqual(routing.required_tier({**base, "crown_jewel": True}, pol)[0], 3)
        self.assertEqual(routing.required_tier({**base, "severity": "High", "confidence": 0.3}, pol)[0], 2)
        self.assertEqual(routing.required_tier({**base, "hosts": list("abcd")}, pol)[0], 2)
        t, why = routing.required_tier({**base, "severity": "Critical", "critical_asset": True}, pol)
        self.assertEqual(t, 3)
        self.assertTrue(any("Raised" in w for w in why))

    def test_goes_to_a_qualified_analyst_never_a_lower_tier(self):
        self.analyst("l1@t.test", 1)
        self.analyst("l2@t.test", 2)
        i, _ = self.ingest(0, severity="High")
        self.assertEqual(i["assignee"], "l2@t.test")
        self.assertTrue(any("Routed to l2@t.test" in r for r in i["routing_reason"]))
        self.assertEqual(self.inc(i["id"])["case"]["tier"], 2)

    def test_lowest_sufficient_tier_keeps_seniors_free(self):
        self.analyst("l2@t.test", 2)
        self.analyst("l3@t.test", 3)
        i, _ = self.ingest(0, severity="High")
        self.assertEqual(i["assignee"], "l2@t.test")

    def test_skills_beat_lower_load(self):
        self.analyst("generalist@t.test", 2)
        self.analyst("ident@t.test", 2, skills=["identity"])
        self.ingest(0, asset="X1", rule="q1", technique="T1566")     # gives one of them a load
        i, _ = self.ingest(5, asset="PC-5", severity="High", title="Brute force login", technique="T1110", rule="auth", inv_=inv(category="identity"))
        self.assertEqual(i["assignee"], "ident@t.test")
        self.assertTrue(any("identity specialty" in r for r in i["routing_reason"]))

    def test_no_analyst_has_the_skill_routes_by_load_and_says_so(self):
        self.analyst("a@t.test", 2, skills=["endpoint"])
        i, _ = self.ingest(0, severity="High", title="s3 bucket made public", technique="T1530", inv_=inv(category="cloud"))
        self.assertEqual(i["assignee"], "a@t.test")
        self.assertTrue(any("no available analyst has it" in r for r in i["routing_reason"]))

    def test_fairness_least_loaded_among_qualified(self):
        self.analyst("a@t.test", 1)
        self.analyst("b@t.test", 1)
        got = []
        for k in range(4):
            i, _ = self.ingest(k * 100, asset=f"H{k}", rule=f"r{k}", technique="T1059", severity="Medium", title=f"t{k}")
            got.append(i["assignee"])
        self.assertEqual(sorted(got), ["a@t.test", "a@t.test", "b@t.test", "b@t.test"])
        self.assertEqual(got[0], "a@t.test")   # ties break on email, so the result repeats

    def test_continuity_beats_lower_load(self):
        self.analyst("a@t.test", 1)
        self.analyst("b@t.test", 1)
        first, _ = self.ingest(0, asset="DB-7", severity="Medium")                 # a takes it
        self.assertEqual(first["assignee"], "a@t.test")
        service.resolve(first["id"], "true-positive", NOTE, "a@t.test", self.e, at(30))
        busy, _ = self.ingest(35, asset="OTHER", rule="z", severity="Medium", title="gives a some load")
        self.assertEqual(busy["assignee"], "a@t.test")
        second, _ = self.ingest(40, asset="DB-7", rule="other-rule", technique="T1021", severity="Medium", title="same host again")
        # DB-7's first incident is resolved, so this is a new incident; b is the lighter analyst, but a handled the related one
        self.assertNotEqual(second["id"], first["id"])
        self.assertEqual(second["assignee"], "a@t.test")
        self.assertTrue(any("continuity" in r for r in second["routing_reason"]))

    def test_unavailable_and_off_shift_are_skipped_and_on_call_takes_urgent_work(self):
        self.analyst("off@t.test", 2, available=False)
        self.analyst("night@t.test", 2, shift_start="22:00", shift_end="06:00")
        self.analyst("oncall@t.test", 2, shift_start="22:00", shift_end="06:00", on_call=True)
        self.analyst("day@t.test", 2, shift_start="08:00", shift_end="17:00")
        self.assertEqual(self.ingest(0, severity="High", asset="H1")[0]["assignee"], "day@t.test")          # 09:00 UTC: only day is on shift
        # a P1 outside everyone's day shift goes to the on-call analyst; plain night staff without on-call stay out of this one? (they are on shift at 23:00)
        late = 14 * 60            # 23:00
        i, _ = self.ingest(late, severity="Critical", asset="H2", technique="T1190", rule="p1", inv_=inv(kev=["CVE-1"]), title="p1")
        self.assertIn(i["assignee"], ("night@t.test", "oncall@t.test"))
        self.assertNotIn(i["assignee"], ("off@t.test", "day@t.test"))
        r = roster.list_roster(self.e, at(late))
        self.assertEqual({a["email"]: a["on_shift"] for a in r}, {"day@t.test": False, "night@t.test": True, "oncall@t.test": True, "off@t.test": True})

    def test_on_call_outside_shift_only_for_urgent_priorities(self):
        self.analyst("oncall@t.test", 2, shift_start="22:00", shift_end="06:00", on_call=True)
        low, _ = self.ingest(0, severity="Medium", asset="L1", technique="T1566")                  # tier 1 needed, P4: not urgent
        self.assertIsNone(low["assignee"])
        self.assertIn("outside their shift", " ".join(low["routing_reason"]))
        urgent, _ = self.ingest(5, severity="Critical", asset="U1", technique="T1190", rule="u", inv_=inv(kev=["CVE-9"]))
        self.assertEqual(urgent["priority"], "P2")
        self.assertEqual(urgent["assignee"], "oncall@t.test")
        self.assertIn("on call outside their shift", " ".join(urgent["routing_reason"]))

    def test_capacity_cap(self):
        self.analyst("a@t.test", 1, capacity=1)
        first, _ = self.ingest(0, severity="Low", asset="A", rule="a", title="a", technique="T1059")
        second, _ = self.ingest(10, severity="Low", asset="B", rule="b", title="b", technique="T1055")
        self.assertEqual((first["assignee"], second["assignee"]), ("a@t.test", None))
        self.assertIn("at capacity", " ".join(second["routing_reason"]))

    def test_nobody_qualified_goes_to_the_queue_and_alerts_the_lead_once(self):
        self.analyst("l1@t.test", 1)
        i, _ = self.ingest(0, severity="High", asset="Q1")                   # needs L2; only an L1 exists
        self.assertEqual((i["assignee"], i["queue"], i["tier"]), (None, "L2", 2))
        self.assertIn("lead is alerted", " ".join(i["routing_reason"]))
        self.assertIn("unrouted", self.kinds(i["id"]))
        self.assertEqual(self.inc(i["id"])["status"], "new")                     # not dropped
        with self.e.connect() as conn:
            n = conn.execute(select(func.count()).select_from(db_module.activity_log).where(db_module.activity_log.c.action == "soc.incident.unrouted")).scalar()
        self.assertEqual(n, 1)
        service.sweep(self.e, at(5))
        with self.e.connect() as conn:
            n2 = conn.execute(select(func.count()).select_from(db_module.activity_log).where(db_module.activity_log.c.action == "soc.incident.unrouted")).scalar()
        self.assertEqual(n2, 1)                                                   # the sweep does not alert again

    def test_sweep_routes_a_queued_incident_when_someone_becomes_available(self):
        i, _ = self.ingest(0, severity="High", asset="Q2")
        self.assertIsNone(i["assignee"])
        self.analyst("late@t.test", 2)
        done = service.sweep(self.e, at(10))
        self.assertEqual(done["retried"], [i["id"]])
        self.assertEqual(self.inc(i["id"])["assignee"], "late@t.test")

    def test_escalates_when_the_clock_breaches_and_reroutes_up(self):
        self.analyst("l1@t.test", 1)
        self.analyst("l2@t.test", 2)
        i, _ = self.ingest(0, severity="Medium", asset="E1", technique="T1566")       # P4: ack 480 min, resolve 4320
        self.assertEqual((i["tier"], i["assignee"]), (1, "l1@t.test"))
        done = service.sweep(self.e, at(500))                                          # ack target (480) passed, never accepted
        self.assertEqual(done["escalated"], [i["id"]])
        out = self.inc(i["id"], at(500))
        self.assertEqual((out["tier"], out["assignee"], out["escalation_count"]), (2, "l2@t.test", 1))
        self.assertIn("auto_escalated", self.kinds(i["id"]))
        self.assertEqual(service.sweep(self.e, at(510))["escalated"], [])               # once per tier

    def test_unavailable_analyst_work_is_rerouted(self):
        self.analyst("a@t.test", 1)
        self.analyst("b@t.test", 1)
        i, _ = self.ingest(0, severity="Medium")
        owner = i["assignee"]
        other = "b@t.test" if owner == "a@t.test" else "a@t.test"
        roster.update_analyst(owner, {"available": False}, self.e)
        self.assertEqual(service.rebalance_analyst(owner, self.e, at(5)), [i["id"]])
        out = self.inc(i["id"])
        self.assertEqual(out["assignee"], other)
        self.assertIn("no longer qualifies", out["routing_reason"][0])
        self.assertIn("reassigned", self.kinds(i["id"]))

    def test_a_working_assignment_is_not_moved_by_a_re_route(self):
        self.analyst("a@t.test", 1)
        i, _ = self.ingest(0, severity="Medium")
        self.analyst("b@t.test", 1, skills=["endpoint"])
        service.route(i["id"], self.e, at(5), why="test", keep_current=True)
        self.assertEqual(self.inc(i["id"])["assignee"], "a@t.test")

    def test_preview_writes_nothing(self):
        self.analyst("a@t.test", 1)
        a, alert = self.ingest(0, severity="Medium")
        new = self.alert(5, title="Another", rule="r9", technique="T1055", severity="Medium")
        before = (len(store.list_incidents(self.e)), len(store.events(a["id"], self.e)))
        p = service.preview(new, self.e, at(5))
        self.assertEqual(p["would_join"], a["id"])
        self.assertIn("shared_host", {r["reason"] for r in p["correlation"]["reasons"]})
        self.assertEqual(p["routing"]["assignee"], "a@t.test")
        self.assertEqual((len(store.list_incidents(self.e)), len(store.events(a["id"], self.e))), before)
        self.assertIsNone(store.incident_for_alert(new["id"], self.e))
        other = self.alert(6, asset="ZZ", rule="zz", technique="T1190")
        self.assertIsNone(service.preview(other, self.e, at(6))["would_join"])


class AutoClose(Base):
    def gate(self, route="auto", conf=0.97):
        return {"gate": {"route": route, "confidence": conf, "thresholds": {"auto": 0.95, "review": 0.6}, "reasons": ["test gate"]}}

    def fp(self, **kw):
        return inv("likely-false-positive", **kw)

    def test_the_shipped_decision_policy_does_not_auto_close_a_high_band_verdict(self):
        # band "high" has probability 0.9 and the auto threshold is 0.95, so the real gate says review: nothing is closed until an admin tunes the policy
        i, alert = self.ingest(0, severity="Low", inv_=self.fp(signals=["rule_noise_history", "prior_benign_same_host"], band="high"))
        self.assertNotEqual(i["status"], "auto_closed")
        self.assertEqual(hunt_store.get_alert(alert["id"], self.e)["status"], "investigating")

    def test_auto_close_only_when_the_gate_says_auto(self):
        with patch.object(service, "evaluate", return_value=self.gate("review", 0.8)):
            i, _ = self.ingest(0, severity="Low", inv_=self.fp())
        self.assertNotEqual(i["status"], "auto_closed")
        with patch.object(service, "evaluate", return_value=self.gate("auto")):
            j, alert = self.ingest(5, severity="Low", asset="OTHER", rule="r2", inv_=self.fp())
        self.assertEqual((j["status"], j["verdict"], j["case_id"], j["assignee"]), ("auto_closed", "false-positive", None, None))
        row = hunt_store.get_alert(alert["id"], self.e)
        self.assertEqual((row["status"], row["disposition"], row["action_taken"]), ("closed", "false-positive", "auto-closed"))
        ev = [e for e in self.inc(j["id"])["timeline"] if e["kind"] == "auto_closed"][0]
        self.assertEqual(ev["data"]["gate"]["route"], "auto")
        self.assertIn(f"/api/soc/incidents/{j['id']}/undo-auto-close", ev["data"]["undo"])

    def test_a_critical_alert_is_never_auto_closed_even_if_the_gate_said_auto(self):
        with patch.object(service, "evaluate", return_value=self.gate("auto", 0.99)):
            i, alert = self.ingest(0, severity="Critical", inv_=self.fp())
        self.assertEqual(i["status"], "new")
        self.assertEqual(hunt_store.get_alert(alert["id"], self.e)["status"], "investigating")
        # and the decision layer itself never calls a Critical alert a likely false positive, nor routes it auto
        res = decision_service.evaluate("soc-alert-triage", {"signals": {k: False for k in SIGNALS} | {"rule_noise_history": True, "prior_benign_same_host": True}, "severity": "Critical"})
        self.assertEqual(res["answers"][0]["value"], "escalate-l2")
        self.assertNotEqual(res["gate"]["route"], "auto")

    def test_a_known_exploited_vulnerability_on_the_host_stops_auto_close(self):
        with patch.object(service, "evaluate", return_value=self.gate("auto")):
            i, _ = self.ingest(0, severity="Low", inv_=self.fp(kev=["CVE-2024-9"]))
        self.assertNotEqual(i["status"], "auto_closed")

    def test_an_alert_that_correlates_into_a_live_incident_is_not_auto_closed(self):
        live, _ = self.ingest(0, severity="Medium", asset="H1")
        with patch.object(service, "evaluate", return_value=self.gate("auto")):
            j, alert = self.ingest(5, severity="Low", asset="H1", rule="other", technique="T1055", inv_=self.fp())
        self.assertEqual(j["id"], live["id"])
        self.assertEqual(hunt_store.get_alert(alert["id"], self.e)["status"], "investigating")

    def test_auto_closed_duplicates_group_in_the_lane_and_the_lane_lists_them(self):
        with patch.object(service, "evaluate", return_value=self.gate("auto")):
            a, _ = self.ingest(0, severity="Low", inv_=self.fp())
            b, _ = self.ingest(5, severity="Low", inv_=self.fp(), title="again")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(len(self.inc(a["id"])["alerts"]), 2)
        self.assertEqual([x["id"] for x in store.list_incidents(self.e, status="auto_closed")], [a["id"]])

    def test_undo_restores_the_alert_routes_it_and_overrides_the_recommendation(self):
        self.analyst("a@t.test", 1)
        with patch.object(service, "evaluate", return_value=self.gate("auto")):
            i, alert = self.ingest(0, severity="Low", inv_=self.fp(signals=["rule_noise_history", "prior_benign_same_host"]))
        # the decision layer logged this verdict when the alert was investigated
        decision_service.log_soc_verdict(alert, inv(signals=["rule_noise_history", "prior_benign_same_host"]) | {"signals": {k: k in ("rule_noise_history", "prior_benign_same_host") for k in SIGNALS}}, self.e)
        out = service.undo_auto_close(i["id"], "ana@t.test", "this host is patching tonight", self.e, at(20))
        self.assertEqual((out["status"], out["assignee"]), ("new", "a@t.test"))
        row = hunt_store.get_alert(alert["id"], self.e)
        self.assertEqual((row["status"], row["disposition"], row["action_taken"]), ("investigating", None, None))
        self.assertIsNotNone(out["case_id"])
        self.assertIn("auto_close_undone", self.kinds(i["id"]))
        with self.e.connect() as conn:
            outcomes = [r.outcome for r in conn.execute(select(db_module.decision_log).where(db_module.decision_log.c.ref == f"alert:{alert['id']}"))]
        self.assertEqual(outcomes, ["overridden"])
        with self.assertRaises(ValueError):
            service.undo_auto_close(i["id"], "ana@t.test", None, self.e, at(21))    # only an auto-closed incident can be undone

    def test_auto_closed_alerts_do_not_count_as_a_persons_judgement_of_the_rule(self):
        from remediation.hunting import soc as hunt_soc
        with patch.object(service, "evaluate", return_value=self.gate("auto")):
            _, alert = self.ingest(0, severity="Low", inv_=self.fp())
        other = self.alert(1, asset="ELSE", rule="rule-a")
        h = hunt_soc.history(other, hunt_store.list_alerts(self.e), hunt_soc.config(), at(1))
        self.assertEqual(h["rule_closed"], 0)


class StateMachine(Base):
    def setUp(self):
        super().setUp()
        self.analyst("a@t.test", 1)
        self.i, self.al = self.ingest(0, severity="Medium")

    def test_resolve_requires_a_verdict_and_a_summary(self):
        with self.assertRaisesRegex(ValueError, "verdict is required"):
            service.resolve(self.i["id"], None, NOTE, "a@t.test", self.e, at(5))
        with self.assertRaisesRegex(ValueError, "verdict is required"):
            service.resolve(self.i["id"], "maybe", NOTE, "a@t.test", self.e, at(5))
        with self.assertRaisesRegex(ValueError, "summary"):
            service.resolve(self.i["id"], "true-positive", "done", "a@t.test", self.e, at(5))
        self.assertEqual(self.inc(self.i["id"])["status"], "new")

    def test_the_full_path_and_the_timeline(self):
        service.accept(self.i["id"], "a@t.test", self.e, at(2))
        self.assertEqual(self.inc(self.i["id"])["status"], "triaging")
        self.assertIsNotNone(self.inc(self.i["id"])["case"]["sla"]["ack"]["done"])
        service.advance(self.i["id"], "investigating", "a@t.test", self.e, at(3))
        service.advance(self.i["id"], "contained", "a@t.test", self.e, at(4))
        done = service.resolve(self.i["id"], "true-positive", NOTE, "a@t.test", self.e, at(5))
        self.assertEqual((done["status"], done["verdict"]), ("resolved", "true-positive"))
        self.assertEqual(hunt_store.get_alert(self.al["id"], self.e)["disposition"], "true-positive")
        kinds = self.kinds(self.i["id"])
        for k in ("created", "investigation", "routed", "accepted", "status", "resolved"):
            self.assertIn(k, kinds)
        self.assertEqual(kinds[0], "created")
        ts = [e["created_at"] for e in done["timeline"]]
        self.assertEqual(ts, sorted(ts))

    def test_invalid_transitions_and_ownership(self):
        with self.assertRaisesRegex(ValueError, "can move to"):
            service.advance(self.i["id"], "resolved", "a@t.test", self.e, at(1))
        with self.assertRaisesRegex(ValueError, "can move to"):
            service.advance(self.i["id"], "new", "a@t.test", self.e, at(1))
        with self.assertRaisesRegex(ValueError, "routed to a@t.test"):
            service.accept(self.i["id"], "someone@t.test", self.e, at(1))
        service.resolve(self.i["id"], "benign", NOTE, "a@t.test", self.e, at(2))
        with self.assertRaisesRegex(ValueError, "resolved"):
            service.accept(self.i["id"], "a@t.test", self.e, at(3))

    def test_reopen_needs_a_reason_and_re_routes(self):
        service.resolve(self.i["id"], "benign", NOTE, "a@t.test", self.e, at(2))
        with self.assertRaisesRegex(ValueError, "why"):
            service.reopen(self.i["id"], "  ", "a@t.test", self.e, at(3))
        out = service.reopen(self.i["id"], "it came back", "a@t.test", self.e, at(4))
        self.assertEqual((out["status"], out["verdict"], out["assignee"]), ("investigating", None, "a@t.test"))
        self.assertEqual(hunt_store.get_alert(self.al["id"], self.e)["status"], "investigating")

    def test_the_verdict_judges_the_recommendation(self):
        live = {k: k == "critical_severity" for k in SIGNALS}
        decision_service.log_soc_verdict(self.al, inv() | {"signals": live | {"ioc_malicious": True, "kev_match": True}}, self.e)
        service.resolve(self.i["id"], "false-positive", NOTE, "a@t.test", self.e, at(5))     # the layer said true positive; the analyst disagrees
        with self.e.connect() as conn:
            rows = list(conn.execute(select(db_module.decision_log).where(db_module.decision_log.c.ref == f"alert:{self.al['id']}")))
        self.assertEqual([r.outcome for r in rows], ["overridden"])

    def test_reassign_checks_tier_and_records_the_reason(self):
        self.analyst("b@t.test", 1)
        self.analyst("l2@t.test", 2)
        out = service.reassign(self.i["id"], "b@t.test", "boss@t.test", "a is on leave", self.e, at(3))
        self.assertEqual(out["assignee"], "b@t.test")
        self.assertEqual(self.inc(self.i["id"])["case"]["case_id"], out["case_id"])
        ev = [e for e in out["timeline"] if e["kind"] == "reassigned"][-1]
        self.assertEqual(ev["data"]["reason"], "a is on leave")
        with self.assertRaisesRegex(ValueError, "not an active analyst"):
            service.reassign(self.i["id"], "ghost@t.test", "boss@t.test", None, self.e, at(4))
        high, _ = self.ingest(10, severity="High", asset="H2", rule="h2", technique="T1190")
        with self.assertRaisesRegex(ValueError, "needs L2"):
            service.reassign(high["id"], "a@t.test", "boss@t.test", None, self.e, at(11))

    def test_escalate_needs_a_summary_and_moves_up(self):
        self.analyst("l2@t.test", 2)
        with self.assertRaisesRegex(ValueError, "summary"):
            service.escalate(self.i["id"], "no", "a@t.test", engine=self.e, now=at(3))
        out = service.escalate(self.i["id"], NOTE, "a@t.test", engine=self.e, now=at(4))
        self.assertEqual((out["tier"], out["assignee"], out["escalation_count"]), (2, "l2@t.test", 1))
        self.assertIn("escalated", self.kinds(self.i["id"]))


class MergeSplitManual(Base):
    def test_merge_moves_alerts_and_closes_the_source(self):
        self.analyst("a@t.test", 1)
        a, _ = self.ingest(0, severity="Medium", asset="A1", rule="ra", technique="T1566")
        b, _ = self.ingest(5, severity="Medium", asset="B1", rule="rb", technique="T1190")
        self.assertNotEqual(a["id"], b["id"])
        out = service.merge(a["id"], b["id"], "a@t.test", self.e, at(6))
        self.assertEqual(len(out["alerts"]), 2)
        src = self.inc(b["id"])
        self.assertEqual((src["status"], src["merged_into"]), ("merged", a["id"]))
        self.assertEqual(cases.get_case(src["case_id"], self.e)["status"], "closed")
        self.assertEqual(len(cases.get_case(a["case_id"], self.e)["alert_ids"]), 2)
        with self.assertRaises(ValueError):
            service.merge(a["id"], a["id"], "a@t.test", self.e, at(7))
        self.assertNotIn(b["id"], [x["id"] for x in store.list_incidents(self.e, open_only=True)])

    def test_split_makes_a_new_incident_and_keeps_at_least_one_alert(self):
        self.analyst("a@t.test", 1)
        a, first = self.ingest(0, severity="Medium", asset="A1", rule="ra", technique="T1566")
        _, second = self.ingest(5, severity="Medium", asset="A1", rule="rb", technique="T1190", title="second")
        self.assertEqual(len(self.inc(a["id"])["alerts"]), 2)
        with self.assertRaisesRegex(ValueError, "At least one"):
            service.split(a["id"], [first["id"], second["id"]], "a@t.test", self.e, at(6))
        with self.assertRaisesRegex(ValueError, "belong"):
            service.split(a["id"], [9999], "a@t.test", self.e, at(6))
        out = service.split(a["id"], [second["id"]], "a@t.test", self.e, at(6))
        self.assertEqual([x["id"] for x in out["original"]["alerts"]], [first["id"]])
        self.assertEqual([x["id"] for x in out["new"]["alerts"]], [second["id"]])
        self.assertNotEqual(out["new"]["id"], a["id"])
        self.assertEqual(cases.get_case(out["new"]["case_id"], self.e)["alert_ids"], [second["id"]])
        self.assertEqual(cases.get_case(a["case_id"], self.e)["alert_ids"], [first["id"]])

    def test_manual_creation_is_an_audited_exception_that_needs_a_reason(self):
        self.analyst("a@t.test", 1)
        with self.assertRaisesRegex(ValueError, "reason"):
            service.create_manual({"title": "Phone call from the CFO"}, "boss@t.test", "", self.e, at(0))
        out = service.create_manual({"title": "Phone call from the CFO", "severity": "High", "assets": ["MAIL-1"]}, "boss@t.test", "Reported by phone; no alert exists yet", self.e, at(0))
        self.assertEqual((out["source"], out["status"]), ("manual-exception", "new"))
        self.assertEqual(out["tier"], 2)       # routed by the same rules (no L2 on the roster, so queued)
        self.assertEqual(out["queue"], "L2")
        ev = out["timeline"][0]
        self.assertEqual((ev["kind"], ev["data"]["manual"]), ("created", True))
        with self.e.connect() as conn:
            acts = [r.action for r in conn.execute(select(db_module.activity_log))]
        self.assertIn("soc.incident.manual_create", acts)


class Roster(Base):
    def test_validation(self):
        with self.assertRaisesRegex(ValueError, "Unknown specialty"):
            roster.update_analyst("a@t.test", {"tier": 1, "skills": ["astrology"]}, self.e)
        with self.assertRaisesRegex(ValueError, "HH:MM"):
            roster.update_analyst("a@t.test", {"tier": 1, "shift_start": "9am"}, self.e)
        with self.assertRaisesRegex(ValueError, "tier"):
            roster.update_analyst("a@t.test", {"tier": 7}, self.e)
        with self.assertRaises(KeyError):
            roster.update_analyst("new@t.test", {"capacity": 3}, self.e)
        a = roster.update_analyst("a@t.test", {"tier": 2, "skills": ["Cloud", "identity"], "capacity": 4, "on_call": True}, self.e)
        self.assertEqual((a["skills"], a["capacity"], a["on_call"], a["available"]), (["cloud", "identity"], 4, True, True))
        self.assertEqual(roster.update_analyst("a@t.test", {"available": False}, self.e)["skills"], ["cloud", "identity"])    # only the fields sent change

    def test_shift_over_midnight(self):
        a = {"shift_start": "22:00", "shift_end": "06:00"}
        self.assertTrue(roster.on_shift(a, T0.replace(hour=23)))
        self.assertTrue(roster.on_shift(a, T0.replace(hour=2)))
        self.assertFalse(roster.on_shift(a, T0.replace(hour=12)))
        self.assertTrue(roster.on_shift({}, T0))


class Disabled(Base):
    def test_off_means_ingest_does_nothing(self):
        with patch.object(store, "policy", return_value={**store.policy(), "incidents": {"enabled": False}}):
            a = self.alert(0)
            self.assertIsNone(service.ingest(a, inv(), service.Context(), self.e, T0))
            self.assertEqual(service.sweep(self.e, T0), {"enabled": False})


class Stream(Base):
    def test_events_resume_and_format(self):
        self.analyst("a@t.test", 1)
        before = stream.latest_id(self.e)
        i, _ = self.ingest(0, severity="Medium")
        evs = stream.since(before, self.e)
        types = [e["type"] for e in evs]
        self.assertIn("incident.created", types)
        self.assertIn("incident.assigned", types)
        text = stream.format_event(evs[0])
        self.assertTrue(text.startswith(f"id: {evs[0]['id']}\nevent: incident.created\ndata: ") and text.endswith("\n\n"))
        service.advance(i["id"], "investigating", "a@t.test", self.e, at(1))
        self.assertEqual(stream.since(evs[-1]["id"], self.e)[-1]["type"], "incident.updated")

    def test_generator_sends_backlog_heartbeat_and_closes(self):
        self.analyst("a@t.test", 1)
        self.ingest(0, severity="Medium")
        clock = {"t": 0.0}
        def tick(s):
            clock["t"] += s
        out = list(stream.generate(self.e, after_id=0, max_seconds=40, poll_seconds=5, heartbeat_seconds=15, sleep=tick, clock=lambda: clock["t"]))
        joined = "".join(out)
        self.assertTrue(joined.startswith(": connected"))
        self.assertIn("event: incident.created", joined)
        self.assertGreaterEqual(joined.count(": heartbeat"), 2)
        self.assertTrue(joined.rstrip().endswith("reconnect to continue"))


class Migration(Base):
    def test_backfill_is_idempotent_and_loses_nothing(self):
        e = create_engine(f"sqlite:///{Path(self.tmp.name) / 'old.db'}")
        db_module.ensure_schema(e)
        a, _ = hunt_store.receive_alert({"external_id": "m1", "title": "Old alert", "severity": "High", "asset": "OLD-1"}, e)
        c1 = cases.open_case({"title": "Open case", "severity": "High", "assets": ["OLD-1"], "alert_ids": [a["id"]], "assignee": None}, "ann", e, T0)
        c2 = cases.open_case({"title": "Done case", "severity": "Low"}, "ann", e, T0)
        cases.assign(c2["id"], "x@t.test", "ann", e, T0)
        cases.resolve(c2["id"], "benign", NOTE, "x@t.test", e, at(5))
        self.assertEqual(migrate.backfill(e), 2)
        self.assertEqual(migrate.backfill(e), 0)
        migrations._m008_soc_incidents(e)
        migrations._m008_soc_incidents(e)
        incs = store.list_incidents(e)
        self.assertEqual(len(incs), 2)
        by = {i["case_id"]: i for i in incs}
        self.assertEqual((by[c1["id"]]["status"], by[c1["id"]]["source"], by[c1["id"]]["tier"]), ("new", "migrated", 1))
        self.assertEqual((by[c2["id"]]["status"], by[c2["id"]]["verdict"]), ("resolved", "benign"))
        self.assertEqual([x["id"] for x in store.get_incident(by[c1["id"]]["id"], e)["alerts"]], [a["id"]])
        self.assertEqual(cases.get_case(c1["id"], e)["title"], "Open case")      # the case itself is untouched
        e.dispose()

    def test_migration_registered_after_the_previous_highest(self):
        nums = [m[0] for m in migrations.MIGRATIONS]
        self.assertEqual(nums, list(range(1, len(nums) + 1)))
        self.assertEqual(dict((m[0], m[1]) for m in migrations.MIGRATIONS)[8], "soc_incidents_and_analyst_routing")


if __name__ == "__main__":
    unittest.main()
