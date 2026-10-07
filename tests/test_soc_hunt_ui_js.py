"""Pure JavaScript behind the SOC command center and the Threat Hunting page (socLogic.js, huntLogic.js), run under Node: kanban move rules, filter URL state, SLA ring maths,
attack-flow layout, live feed fallback, ATT&CK matrix aggregation, hunt-report grouping. Skipped without Node. The DOM parts of the pages are checked in a real browser."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

NODE = shutil.which("node")
JS = Path(__file__).resolve().parent.parent / "dashboard" / "static" / "js"


def run_js(body, module):
    uri = (JS / module).as_uri()
    script = f"import * as M from {json.dumps(uri)};\n{body}"
    proc = subprocess.run([NODE, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout)


@unittest.skipUnless(NODE, "node is not installed")
class KanbanMoveTests(unittest.TestCase):
    def plan(self, frm, to):
        return run_js(f"""console.log(JSON.stringify(M.planMove({{id: 1, status: {json.dumps(frm)}}}, {json.dumps(to)})));""", "socLogic.js")

    def test_new_to_triaging_is_accept_only(self):
        p = self.plan("new", "triaging")
        self.assertTrue(p["ok"])
        self.assertEqual([s["action"] for s in p["steps"]], ["accept"])

    def test_new_to_investigating_accepts_then_advances(self):
        p = self.plan("new", "investigating")
        self.assertEqual([(s["action"], s["body"]) for s in p["steps"]], [("accept", {}), ("advance", {"status": "investigating"})])

    def test_working_states_advance_in_either_direction(self):
        self.assertEqual(self.plan("contained", "investigating")["steps"][0], {"action": "advance", "body": {"status": "investigating"}, "needs": None})
        self.assertEqual(self.plan("triaging", "contained")["steps"][0]["action"], "advance")

    def test_resolve_needs_a_verdict_and_reopen_needs_a_reason(self):
        self.assertEqual(self.plan("investigating", "resolved")["steps"][0]["needs"], "verdict")
        self.assertEqual(self.plan("resolved", "triaging")["steps"][0], {"action": "reopen", "body": {}, "needs": "reason"})

    def test_impossible_moves_are_refused_with_a_reason(self):
        for frm, to in (("triaging", "new"), ("investigating", "auto_closed"), ("merged", "triaging")):
            p = self.plan(frm, to)
            self.assertFalse(p["ok"], (frm, to))
            self.assertTrue(p["reason"])
        self.assertTrue(self.plan("triaging", "triaging")["same"])

    def test_auto_closed_can_only_be_undone(self):
        p = self.plan("auto_closed", "investigating")
        self.assertEqual([s["action"] for s in p["steps"]], ["undo-auto-close"])

    def test_next_status(self):
        out = run_js("""console.log(JSON.stringify([M.nextStatus("new"), M.nextStatus("contained"), M.nextStatus("resolved")]));""", "socLogic.js")
        self.assertEqual(out, ["triaging", None, None])


@unittest.skipUnless(NODE, "node is not installed")
class FilterStateTests(unittest.TestCase):
    def test_round_trip_and_clean_default(self):
        out = run_js("""
          const f = M.parseFilters("?scope=mine&severity=High&tier=2&q=web%201&view=list&junk=1");
          console.log(JSON.stringify({f, back: M.filtersToSearch(f), empty: M.filtersToSearch(M.parseFilters("")), withId: M.filtersToSearch(M.parseFilters(""), {incident: 7})}));""", "socLogic.js")
        self.assertEqual(out["f"], {"view": "list", "scope": "mine", "tier": "2", "severity": "High", "status": "", "sla": "", "q": "web 1"})
        self.assertEqual(out["empty"], "")
        self.assertEqual(out["withId"], "?incident=7")
        self.assertIn("scope=mine", out["back"])
        self.assertNotIn("junk", out["back"])

    def test_invalid_values_fall_back(self):
        out = run_js("""console.log(JSON.stringify(M.parseFilters("?scope=evil&tier=9&severity=Bogus&status=nope&view=x")));""", "socLogic.js")
        self.assertEqual(out, {"view": "board", "scope": "all", "tier": "", "severity": "", "status": "", "sla": "", "q": ""})

    def test_apply_filters(self):
        out = run_js("""
          const L = [
            {id: 1, title: "Shell on web-1", severity: "High", tier: 2, status: "new", assignee: "me@x.org", entities: {hosts: ["web-1"]}},
            {id: 2, title: "Beacon", severity: "Low", tier: 1, status: "triaging", assignee: null, entities: {hosts: ["db-1"]}},
            {id: 3, title: "Phish", severity: "High", tier: 1, status: "new", assignee: "bo@x.org", entities: {users: ["carol"]}, sla: {worst: "breached"}}];
          const ids = (f) => M.applyFilters(L, M.parseFilters(f), "ME@x.org").map((i) => i.id);
          console.log(JSON.stringify({mine: ids("?scope=mine"), un: ids("?scope=unassigned"), team: ids("?scope=team"), sev: ids("?severity=High"), tier: ids("?tier=1"), q: ids("?q=web"), q2: ids("?q=carol"), q3: ids("?q=%232"), sla: ids("?sla=any"), sla2: ids("?sla=at_risk")}));""", "socLogic.js")
        self.assertEqual(out, {"mine": [1], "un": [2], "team": [2, 3], "sev": [1, 3], "tier": [2, 3], "q": [1], "q2": [3], "q3": [2], "sla": [3], "sla2": []})


@unittest.skipUnless(NODE, "node is not installed")
class SlaRingTests(unittest.TestCase):
    def test_ring_uses_first_running_clock(self):
        out = run_js("""
          const sla = {ack: {target_minutes: 120, elapsed_minutes: 30, remaining_minutes: 90, state: "running", done: false}, pickup: null, resolve: {target_minutes: 480, elapsed_minutes: 30, remaining_minutes: 450, state: "running", done: false}, worst: "ok"};
          console.log(JSON.stringify(M.slaRing(sla)));""", "socLogic.js")
        self.assertEqual(out["clock"], "ack")
        self.assertEqual(out["state"], "ok")
        self.assertAlmostEqual(out["fraction"], 0.25)
        self.assertEqual(out["label"], "ack 1h 30m left")

    def test_breached_at_risk_and_done(self):
        out = run_js("""
          const mk = (st, el, rem) => ({ack: {target_minutes: 60, elapsed_minutes: el, remaining_minutes: rem, state: st, done: false}});
          console.log(JSON.stringify([M.slaRing(mk("breached", 90, -30)), M.slaRing(mk("at_risk", 50, 10)), M.slaRing({ack: {done: true, state: "met"}}), M.slaRing(null)]));""", "socLogic.js")
        self.assertEqual([o["state"] for o in out], ["breached", "at_risk", "done", "none"])
        self.assertEqual(out[0]["fraction"], 1)               # clamped
        self.assertEqual(out[0]["label"], "ack 30m late")

    def test_minutes_formatting_and_dash(self):
        out = run_js("""console.log(JSON.stringify([M.fmtMinutes(5), M.fmtMinutes(90), M.fmtMinutes(120), M.fmtMinutes(-45), M.fmtMinutes(null), M.fmtMinutes(4000), M.ringDash(0.5, 10)]));""", "socLogic.js")
        self.assertEqual(out[:6], ["5m", "1h 30m", "2h", "45m late", "n/a", "3d"])
        self.assertAlmostEqual(out[6]["offset"], out[6]["circumference"] / 2, places=1)


@unittest.skipUnless(NODE, "node is not installed")
class KpiAndBoardTests(unittest.TestCase):
    def test_kpis(self):
        out = run_js("""
          const L = [
            {id: 1, status: "new", severity: "Critical", assignee: "me@x.org", sla: {worst: "breached"}},
            {id: 2, status: "triaging", severity: "High", assignee: null, sla: {worst: "at_risk"}},
            {id: 3, status: "resolved", severity: "High", assignee: "me@x.org"},
            {id: 4, status: "auto_closed", severity: "Low", updated_at: "2026-10-07T01:00:00Z"},
            {id: 5, status: "auto_closed", severity: "Low", updated_at: "2026-10-01T01:00:00Z"}];
          console.log(JSON.stringify(M.kpis(L, "ME@x.org", new Date("2026-10-07T12:00:00Z"))));""", "socLogic.js")
        self.assertEqual((out["open"], out["mine"], out["unassigned"], out["atRisk"], out["breached"], out["autoClosedToday"], out["autoClosed"]), (2, 1, 1, 1, 1, 1, 2))
        self.assertEqual(out["bySeverity"]["Critical"], 1)

    def test_sparkline_needs_history(self):
        out = run_js("""
          const d = (n) => Array.from({length: n}, (_, i) => ({opened: i % 3, resolved: 0}));
          console.log(JSON.stringify([M.sparkSeries(d(2), "opened"), M.sparkSeries(d(10), "opened"), M.sparkSeries(d(10), "resolved"), M.halfDelta([1, 2, 3, 4]), M.halfDelta([1, 2])]));""", "socLogic.js")
        self.assertIsNone(out[0])
        self.assertEqual(len(out[1]), 10)
        self.assertIsNone(out[2])                       # all zero: no signal
        self.assertEqual(out[3], {"current": 7, "previous": 3})
        self.assertIsNone(out[4])

    def test_kill_chain_dots_and_columns(self):
        out = run_js("""
          const kc = M.killChainDots([{tactic: "Initial Access"}, {tactic: "Execution"}, {tactic: "Odd Stage"}]);
          const cols = M.boardColumns([{status: "new"}, {status: "new"}, {status: "resolved"}, {status: "auto_closed"}]).map((c) => [c.status, c.items.length]);
          console.log(JSON.stringify({count: kc.count, extra: kc.extra, first: kc.dots[0], cols}));""", "socLogic.js")
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["extra"], ["Odd Stage"])
        self.assertTrue(out["first"]["reached"])
        self.assertEqual(out["cols"], [["new", 2], ["triaging", 0], ["investigating", 0], ["contained", 0], ["resolved", 1]])

    def test_live_merge_helpers(self):
        out = run_js("""
          const a = [{id: 1, status: "new", severity: "High"}, {id: 2, status: "new", severity: "Low"}];
          const b = [{id: 1, status: "triaging", severity: "High"}, {id: 2, status: "new", severity: "Low"}, {id: 3, status: "new", severity: "Critical"}];
          console.log(JSON.stringify({ch: M.changedIds(a, b), crit: M.newCritical(a, b).map((i) => i.id), up: M.upsertIncident(a, {id: 2, status: "contained"}).map((i) => i.status),
            ins: M.upsertIncident(a, {id: 9}).map((i) => i.id), sort: M.sortIncidents([{id: 1, status: "resolved", priority: "P1"}, {id: 2, status: "new", priority: "P3", severity: "Low"}, {id: 3, status: "new", priority: "P1", severity: "High"}]).map((i) => i.id)}));""", "socLogic.js")
        self.assertEqual(out["ch"], [1, 3])
        self.assertEqual(out["crit"], [3])
        self.assertEqual(out["up"], ["new", "contained"])
        self.assertEqual(out["ins"], [9, 1, 2])
        self.assertEqual(out["sort"], [3, 2, 1])

    def test_initials(self):
        out = run_js("""console.log(JSON.stringify([M.initials("ana.lopez@corp.example"), M.initials("bo@x"), M.initials(""), M.hueOf("a") === M.hueOf("a")]));""", "socLogic.js")
        self.assertEqual(out, ["AL", "BO", "?", True])


@unittest.skipUnless(NODE, "node is not installed")
class AttackFlowTests(unittest.TestCase):
    FLOW = """const flow = {stages: ["Initial Access", "Execution", "Unmapped"], nodes: [
        {id: "a1", kind: "alert", label: "Exploit", stage: "Initial Access", at: "2026-10-06T09:00:00Z", severity: "High"},
        {id: "a2", kind: "alert", label: "Shell", stage: "Execution", at: "2026-10-06T09:05:00Z", severity: "High"},
        {id: "a3", kind: "alert", label: "Second shell", stage: "Execution", at: "2026-10-06T09:06:00Z", severity: "Medium"},
        {id: "e1", kind: "entity", entity_kind: "host", label: "WEB-1", stage: null}],
      edges: [{from: "a1", to: "a2", kind: "next-stage"}, {from: "a2", to: "a3", kind: "same-stage"}, {from: "a1", to: "e1", kind: "involves"}, {from: "zz", to: "a1", kind: "x"}]};"""

    def test_nodes_are_placed_in_their_lane_in_time_order(self):
        out = run_js(self.FLOW + """const L = M.attackFlowLayout(flow); console.log(JSON.stringify({w: L.width, lanes: L.lanes.map((l) => [l.stage, l.x]), nodes: L.nodes.map((n) => [n.id, n.x, n.y]), edges: L.edges.length, h: L.height}));""", "socLogic.js")
        nodes = {n[0]: n for n in out["nodes"]}
        self.assertEqual(out["lanes"], [["Initial Access", 0], ["Execution", 190], ["Unmapped", 380]])
        self.assertLess(nodes["a1"][1], nodes["a2"][1])               # a later stage is further right
        self.assertEqual(nodes["a2"][1], nodes["a3"][1])              # same lane, same x
        self.assertLess(nodes["a2"][2], nodes["a3"][2])               # stacked in time order
        self.assertGreater(nodes["e1"][2], nodes["a3"][2])            # entities below every alert
        self.assertEqual(out["edges"], 3)                             # the edge to a missing node is dropped, not drawn
        self.assertGreater(out["h"], nodes["e1"][2])

    def test_every_edge_has_a_path_and_empty_flow_is_safe(self):
        out = run_js(self.FLOW + """const L = M.attackFlowLayout(flow); console.log(JSON.stringify({paths: L.edges.map((e) => e.path.startsWith("M")), empty: M.attackFlowLayout(null).nodes.length, none: M.attackFlowLayout({nodes: []}).width}));""", "socLogic.js")
        self.assertTrue(all(out["paths"]))
        self.assertEqual((out["empty"], out["none"]), (0, 0))

    def test_timeline_filter_by_node(self):
        out = run_js("""
          const t = [{event: "Alert raised: x", alert_id: 1}, {event: "Alert raised: y on WEB-1", alert_id: 2}, {event: "Resolved by ana"}];
          console.log(JSON.stringify({a: M.filterTimeline(t, {kind: "alert", id: "a2"}).length, e: M.filterTimeline(t, {kind: "entity", label: "web-1"}).length, all: M.filterTimeline(t, null).length,
            icons: [M.timelineIcon("Alert raised: x"), M.timelineIcon("Resolved by ana"), M.timelineIcon("something")]}));""", "socLogic.js")
        self.assertEqual((out["a"], out["e"], out["all"]), (1, 1, 3))
        self.assertEqual(out["icons"], ["alert", "check", "dot"])


@unittest.skipUnless(NODE, "node is not installed")
class EvidenceAndFeedTests(unittest.TestCase):
    def test_evidence_marks(self):
        out = run_js("""
          const ev = [{ref: "E1", source: "stored alert #1"}, {ref: "E2", source: "x"}];
          console.log(JSON.stringify([M.evidenceMarks({evidence: ["E1", "E9"]}, ev), M.evidenceMarks({evidence: []}, ev), M.evidenceMarks({}, null)]));""", "socLogic.js")
        self.assertTrue(out[0]["evidenced"])
        self.assertEqual(out[0]["missing"], ["E9"])
        self.assertFalse(out[1]["evidenced"])
        self.assertFalse(out[2]["evidenced"])

    def test_feed_delivers_events_and_falls_back_to_polling(self):
        out = run_js("""
          class FakeES { constructor(u) { FakeES.last = this; this.u = u; this.l = {}; this.readyState = 1; }
            addEventListener(t, f) { this.l[t] = f; } close() { this.closed = true; } }
          const timers = []; const env = {EventSource: FakeES, setTimeout: (f, ms) => { timers.push([f, ms]); return timers.length; }, clearTimeout: () => {}};
          const events = []; const modes = []; let polls = 0;
          const feed = M.connectIncidentFeed(env, {onEvent: (d, t) => events.push([t, d.incident_id]), onMode: (m) => modes.push(m), pollFn: async () => { polls++; }});
          FakeES.last.onopen();
          FakeES.last.l["incident.created"]({data: JSON.stringify({incident_id: 7})});
          FakeES.last.l["incident.updated"]({data: "not json"});
          FakeES.last.onerror(); FakeES.last.onerror(); FakeES.last.onerror();   // three failures in a row
          await new Promise((r) => setTimeout(r, 0));
          const hadTimer = timers.length;
          feed.stop();
          console.log(JSON.stringify({events, modes, closed: FakeES.last.closed === true, hadTimer, url: FakeES.last.u}));""", "socLogic.js")
        self.assertEqual(out["events"], [["incident.created", 7]])
        self.assertEqual(out["modes"], ["live", "reconnecting", "poll"])
        self.assertTrue(out["closed"])
        self.assertEqual(out["hadTimer"], 1)
        self.assertEqual(out["url"], "/api/soc/incidents/stream")

    def test_feed_without_eventsource_polls_immediately_and_stops(self):
        out = run_js("""
          const timers = []; let cleared = 0;
          const env = {EventSource: null, setTimeout: (f, ms) => { timers.push([f, ms]); return timers.length; }, clearTimeout: () => { cleared++; }};
          const modes = []; let polls = 0;
          const feed = M.connectIncidentFeed(env, {onMode: (m) => modes.push(m), pollFn: async () => { polls++; }, pollEvery: 5000});
          timers[0][0]();
          await new Promise((r) => setTimeout(r, 5));
          feed.stop();
          console.log(JSON.stringify({modes, polls, every: timers[0][1], rescheduled: timers.length, cleared}));""", "socLogic.js")
        self.assertEqual(out["modes"], ["poll"])
        self.assertEqual(out["polls"], 1)
        self.assertEqual(out["every"], 5000)
        self.assertEqual(out["rescheduled"], 2)
        self.assertGreaterEqual(out["cleared"], 1)


@unittest.skipUnless(NODE, "node is not installed")
class HuntLogicTests(unittest.TestCase):
    PAYLOAD = """const P = {tactics: ["Initial Access", "Execution", "Impact"], techniques: [
        {technique_id: "T1190", name: "Exploit", tactic: "Initial Access", state: "covered", exposure: 4, rules: ["r"], hunts: [], findings: 3, alerts: 1},
        {technique_id: "T1059", name: "Shell", tactic: "Execution", state: "gap", exposure: 2, rules: [], hunts: [], findings: 2, alerts: 0},
        {technique_id: "T1047", name: "WMI", tactic: "Execution", state: "hunted", exposure: 1, rules: [], hunts: [3], findings: 1, alerts: 0},
        {technique_id: "T1486", name: "Ransom", tactic: "Impact", state: "quiet", exposure: 0, rules: [], hunts: [], findings: 0, alerts: 0}],
      totals: {techniques: 4, observed: 3, covered: 1, observed_covered: 1, observed_hunted: 1, observed_gap: 1, rules_recorded: true}};"""

    def test_matrix_columns_counts_and_coverage(self):
        out = run_js(self.PAYLOAD + """const a = M.aggregateMatrix(P); console.log(JSON.stringify({cols: a.columns.map((c) => [c.tactic, c.cells.length, c.observed, c.covered, c.gaps, c.hunted]), pct: a.observedCoveragePct, max: a.max, shown: a.shown}));""", "huntLogic.js")
        self.assertEqual(out["cols"], [["Initial Access", 1, 1, 1, 0, 0], ["Execution", 2, 2, 0, 1, 1], ["Impact", 1, 0, 0, 0, 0]])
        self.assertEqual((out["pct"], out["max"], out["shown"]), (33, 4, 4))

    def test_matrix_filters_drop_empty_columns(self):
        out = run_js(self.PAYLOAD + """
          const g = M.aggregateMatrix(P, {state: "gap"}); const o = M.aggregateMatrix(P, {observedOnly: true}); const q = M.aggregateMatrix(P, {q: "wmi"});
          console.log(JSON.stringify({g: g.columns.map((c) => c.tactic), o: o.shown, q: q.columns.map((c) => c.cells.map((x) => x.technique_id))}));""", "huntLogic.js")
        self.assertEqual(out["g"], ["Execution"])
        self.assertEqual(out["o"], 3)
        self.assertEqual(out["q"], [["T1047"]])

    def test_heat_levels_and_no_rules(self):
        out = run_js("""console.log(JSON.stringify([M.heatLevel(0, 5), M.heatLevel(1, 8), M.heatLevel(3, 8), M.heatLevel(5, 8), M.heatLevel(8, 8), M.aggregateMatrix({tactics: [], techniques: [], totals: {}}).observedCoveragePct]));""", "huntLogic.js")
        self.assertEqual(out, [0, 1, 2, 3, 4, None])

    def test_suggestion_filters_and_facets(self):
        out = run_js("""
          const L = [{id: "a", hunt_type: "intel-driven", title: "Log4j follow-on", hypothesis: "x", tactics: ["Initial Access"], techniques: [{technique_id: "T1190", technique_name: "Exploit"}], scope: {assets: ["WEB-1"]}, data_readiness: {status: "connected"}},
                     {id: "b", hunt_type: "baseline-anomaly", title: "Bursts", hypothesis: "y", tactics: ["Execution"], techniques: [{technique_id: "T1059", technique_name: "Shell"}], scope: {assets: []}, data_readiness: {status: "cannot-tell"}}];
          const ids = (f) => M.filterSuggestions(L, f).map((s) => s.id);
          console.log(JSON.stringify({t: ids({type: "intel-driven"}), tac: ids({tactic: "execution"}), q: ids({q: "web-1"}), tech: ids({technique: "T1059"}), ready: ids({ready: "connected"}), f: M.facetCounts(L)}));""", "huntLogic.js")
        self.assertEqual((out["t"], out["tac"], out["q"], out["tech"], out["ready"]), (["a"], ["b"], ["a"], ["b"], ["a"]))
        self.assertEqual(out["f"]["types"], {"intel-driven": 1, "baseline-anomaly": 1})

    def test_hunt_state_url_round_trip(self):
        out = run_js("""const s = M.parseHuntState("?tab=matrix&hunt=7&type=intel-driven&tactic=Execution&ready=connected&type2=x"); console.log(JSON.stringify([s, M.huntStateToSearch(s), M.huntStateToSearch({})]));""", "huntLogic.js")
        self.assertEqual(out[0]["hunt"], 7)
        self.assertEqual(out[0]["type"], "intel-driven")
        self.assertIn("hunt=7", out[1])
        self.assertEqual(out[2], "")

    def test_score_bars_domains_progress(self):
        out = run_js("""
          const bars = M.scoreBars({score: 50, breakdown: [{factor: "likelihood", points: 15, max: 30, note: "n"}, {factor: "effort", points: -4, max: 0, note: ""}]});
          const g = M.groupByDomain([{domain: "network", n: 1}, {domain: "endpoint", n: 2}, {domain: "weird", n: 3}]);
          console.log(JSON.stringify({bars, g, prog: [M.huntProgress({trial_hits: 4, run: 3}), M.huntProgress({trial_hits: 0})], tone: [M.scoreTone(80), M.scoreTone(10)],
            q: M.queryTabs({query: "search x", kql: "union *"}).map((t) => t.id)}));""", "huntLogic.js")
        self.assertEqual(out["bars"][0]["pct"], 50)
        self.assertTrue(out["bars"][1]["negative"])
        self.assertEqual(out["g"]["endpoint"][0]["n"], 2)
        self.assertEqual(len(out["g"]["weird"]), 1)
        self.assertEqual(out["prog"][0]["pct"], 75)
        self.assertEqual(out["prog"][1]["label"], "No trial hits yet")
        self.assertEqual(out["tone"], ["critical", "neutral"])
        self.assertEqual(out["q"], ["spl", "kql"])


if __name__ == "__main__":
    unittest.main()
