"""Pure JavaScript behind the rebuilt module pages (queueLogic.js, moduleLogic.js), run under Node: queue filters kept in the URL, filtering and sorting, SLA maths, bulk selection,
optimistic updates, saved views, board move rules, approval/exception rules, aggregation maths. Skipped without Node. The DOM parts of the pages are checked in a real browser."""
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


def call(module, expr):
    return run_js(f"console.log(JSON.stringify({expr}));", module)


FINDINGS = [
    {"id": "F1", "title": "Log4Shell RCE", "priority": "Critical", "score": 90, "cve": "CVE-2021-44228", "asset": {"name": "web-01", "type": "linux"}, "kev": {"listed": True}, "epss": {"score": 0.97}, "sla": {"due_date": "2026-01-10", "days_remaining": -5, "breached": True}, "first_seen": "2025-12-01", "owner": "a@x", "team": "Web"},
    {"id": "F2", "title": "Weak TLS", "priority": "Medium", "score": 30, "cve": None, "asset": {"name": "web-02", "type": "linux"}, "kev": None, "epss": {"score": 0.1}, "sla": {"due_date": "2026-03-01", "days_remaining": 2, "breached": False}, "first_seen": "2026-01-01"},
    {"id": "F3", "title": "Old kernel", "priority": "High", "score": 60, "cve": "CVE-2020-1", "asset": {"name": "db-01", "type": "linux"}, "kev": {"listed": False}, "epss": None, "sla": {"due_date": "2026-09-01", "days_remaining": 40, "breached": False}, "first_seen": "2026-02-01", "team": "Data"},
    {"id": "F4", "title": "No dates", "priority": "Low", "score": 5, "cve": None, "asset": {"name": "x", "type": "app"}, "kev": None, "epss": None, "sla": {"due_date": None, "days_remaining": None, "breached": None}, "first_seen": None},
]


@unittest.skipUnless(NODE, "node is not installed")
class QueueUrlStateTests(unittest.TestCase):
    def test_default_state_has_no_query(self):
        self.assertEqual(call("queueLogic.js", 'M.queueStateToSearch(M.parseQueueState(""))'), "")

    def test_round_trip_keeps_only_non_defaults(self):
        s = "?priority=Critical&kevOnly=true&asset=web-01&q=log4j&sort=sla&dir=asc"
        out = call("queueLogic.js", f'M.queueStateToSearch(M.parseQueueState({json.dumps(s)}))')
        self.assertEqual(sorted(out.lstrip("?").split("&")), sorted(s.lstrip("?").split("&")))

    def test_legacy_deep_link_params_still_work(self):
        st = call("queueLogic.js", 'M.parseQueueState("?category=infra-vm&infraType=os&ageBucket=90%2B&cloudProvider=AWS&eolStatus=eol&slaStatus=breached&highlight=FIND-9")')
        self.assertEqual(st["filters"]["category"], "infra-vm")
        self.assertEqual(st["filters"]["ageBucket"], "90+")
        self.assertEqual(st["filters"]["slaStatus"], "breached")
        self.assertEqual(st["highlight"], "FIND-9")

    def test_garbage_is_ignored(self):
        st = call("queueLogic.js", 'M.parseQueueState("?priority=Bogus&sort=evil&dir=sideways&nonsense=1")')
        self.assertEqual(st["filters"]["priority"], "all")
        self.assertEqual(st["sort"], {"key": "priority", "dir": "desc"})

    def test_chips_and_clear(self):
        out = run_js('const st=M.parseQueueState("?priority=High&unowned=true&q=x"); console.log(JSON.stringify({n:M.activeFilterCount(st.filters), chips:M.activeFilterChips(st.filters).map(c=>c.key), cleared:M.clearFilter(st.filters,"unownedOnly").unownedOnly}));', "queueLogic.js")
        self.assertEqual(out["n"], 3)
        self.assertEqual(sorted(out["chips"]), ["priority", "q", "unownedOnly"])
        self.assertFalse(out["cleared"])


@unittest.skipUnless(NODE, "node is not installed")
class QueueFilterSortTests(unittest.TestCase):
    def filt(self, search, now="2026-03-01"):
        return run_js(f'const st=M.parseQueueState({json.dumps(search)}); console.log(JSON.stringify(M.applyQueueFilters({json.dumps(FINDINGS)}, st.filters, new Date({json.dumps(now)})).map(f=>f.id)));', "queueLogic.js")

    def test_priority_kev_and_sla(self):
        self.assertEqual(self.filt("?priority=Critical"), ["F1"])
        self.assertEqual(self.filt("?kevOnly=true"), ["F1"])
        self.assertEqual(self.filt("?slaStatus=breached"), ["F1"])
        self.assertEqual(self.filt("?slaStatus=at_risk"), ["F2"])
        self.assertEqual(self.filt("?slaStatus=on_track"), ["F3", "F4"])  # no SLA date counts as on track, like the server

    def test_epss_and_unowned(self):
        self.assertEqual(self.filt("?highEpssOnly=true"), ["F1"])
        self.assertEqual(self.filt("?unowned=true"), ["F2", "F4"])

    def test_free_text_matches_every_word(self):
        self.assertEqual(self.filt("?q=log4shell web-01"), ["F1"])
        self.assertEqual(self.filt("?q=CVE-2020"), ["F3"])
        self.assertEqual(self.filt("?q=nothing-here"), [])

    def test_age_bucket(self):
        self.assertEqual(self.filt("?ageBucket=90%2B", now="2026-06-01"), ["F1", "F2", "F3"])
        self.assertEqual(self.filt("?ageBucket=0-30", now="2026-02-10"), ["F3"])

    def test_sorting_priority_then_score_and_empty_last(self):
        out = run_js(f'console.log(JSON.stringify([M.sortQueue({json.dumps(FINDINGS)}, "priority", "desc").map(f=>f.id), M.sortQueue({json.dumps(FINDINGS)}, "sla", "asc").map(f=>f.id), M.sortQueue({json.dumps(FINDINGS)}, "sla", "desc").map(f=>f.id), M.sortQueue({json.dumps(FINDINGS)}, "epss", "desc").map(f=>f.id)]));', "queueLogic.js")
        self.assertEqual(out[0], ["F1", "F3", "F2", "F4"])
        self.assertEqual(out[1], ["F1", "F2", "F3", "F4"])
        self.assertEqual(out[2], ["F3", "F2", "F1", "F4"])  # a finding with no SLA date stays last in both directions
        self.assertEqual(out[3], ["F1", "F2", "F3", "F4"])

    def test_kpis_and_priority_breakdown(self):
        k = call("queueLogic.js", f"M.queueKpis({json.dumps(FINDINGS)})")
        self.assertEqual((k["total"], k["breached"], k["atRisk"], k["kev"], k["highEpss"], k["unowned"]), (4, 1, 1, 1, 1, 2))
        self.assertEqual(k["byPriority"], {"Critical": 1, "High": 1, "Medium": 1, "Low": 1})

    def test_facets_sorted_by_count(self):
        out = call("queueLogic.js", f'M.facetCounts({json.dumps(FINDINGS)}, (f) => f.asset.type)')
        self.assertEqual(out[0], {"value": "linux", "count": 3})


@unittest.skipUnless(NODE, "node is not installed")
class QueueSlaRingTests(unittest.TestCase):
    def ring(self, f):
        return call("queueLogic.js", f"M.slaRingFor({json.dumps(f)}, new Date('2026-03-01'))")

    def test_breached_is_full(self):
        r = self.ring(FINDINGS[0])
        self.assertEqual((r["state"], r["fraction"]), ("breached", 1))
        self.assertIn("5 days ago", r["label"])

    def test_at_risk_and_fraction(self):
        r = self.ring({"first_seen": "2026-02-01", "sla": {"due_date": "2026-03-03", "days_remaining": 2, "breached": False}})
        self.assertEqual(r["state"], "at_risk")
        self.assertGreater(r["fraction"], 0.9)

    def test_no_date_has_no_ring(self):
        self.assertEqual(self.ring(FINDINGS[3])["state"], "none")


@unittest.skipUnless(NODE, "node is not installed")
class QueueSelectionTests(unittest.TestCase):
    def test_toggle_and_range(self):
        out = run_js('''const ids=["a","b","c","d","e"]; let s=M.toggleSelection(new Set(),"b"); const r=M.rangeSelection(s,ids,"b","d"); const off=M.rangeSelection(r,ids,"b","d");
          console.log(JSON.stringify({s:[...s], r:[...r].sort(), off:[...off].sort(), reverse:[...M.rangeSelection(new Set(),ids,"d","b")].sort(), unknownAnchor:[...M.rangeSelection(new Set(),ids,"zz","c")]}));''', "queueLogic.js")
        self.assertEqual(out["s"], ["b"])
        self.assertEqual(out["r"], ["b", "c", "d"])
        self.assertEqual(out["off"], [])  # shift-clicking an already selected row clears the whole range from the anchor
        self.assertEqual(out["reverse"], ["b", "c", "d"])
        self.assertEqual(out["unknownAnchor"], ["c"])

    def test_prune_keeps_identity_when_nothing_changes(self):
        out = run_js('const s=new Set(["a","b"]); const same=M.pruneSelection(s,["a","b","c"]); const pruned=M.pruneSelection(s,["a"]); console.log(JSON.stringify({same:same===s, pruned:[...pruned]}));', "queueLogic.js")
        self.assertTrue(out["same"])
        self.assertEqual(out["pruned"], ["a"])

    def test_selection_state_and_batches(self):
        out = run_js('console.log(JSON.stringify([M.selectionState(new Set(),["a","b"]), M.selectionState(new Set(["a"]),["a","b"]), M.selectionState(new Set(["a","b"]),["a","b"]), M.bulkBatches([1,2,3,4,5],2)]));', "queueLogic.js")
        self.assertEqual(out, ["none", "some", "all", [[1, 2], [3, 4], [5]]])

    def test_keyboard_focus_movement_is_clamped(self):
        out = run_js('console.log(JSON.stringify([M.moveFocusIndex(0,"k",5), M.moveFocusIndex(4,"j",5), M.moveFocusIndex(2,"PageDown",30), M.moveFocusIndex(-1,"ArrowDown",5), M.moveFocusIndex(3,"Home",5), M.moveFocusIndex(0,"x",0)]));', "queueLogic.js")
        self.assertEqual(out, [0, 4, 12, 1, 0, -1])


@unittest.skipUnless(NODE, "node is not installed")
class QueueOptimisticTests(unittest.TestCase):
    def test_apply_and_undo_restore_exact_objects(self):
        out = run_js(f'''const all={json.dumps(FINDINGS)}; const r=M.applyOptimistic(all,["F1","F3"],{{assignee:"me"}}); const back=r.undo(r.next);
          console.log(JSON.stringify({{count:r.count, patched:r.next.filter(f=>f.assignee==="me"&&f.pending).map(f=>f.id), untouched:r.next[1]===all[1], restored:JSON.stringify(back)===JSON.stringify(all)}}));''', "queueLogic.js")
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["patched"], ["F1", "F3"])
        self.assertTrue(out["untouched"])
        self.assertTrue(out["restored"])

    def test_settle_clears_pending_only_for_ids(self):
        out = run_js(f'''const r=M.applyOptimistic({json.dumps(FINDINGS)},["F1","F2"],{{x:1}}); const s=M.settle(r.next,["F1"]); console.log(JSON.stringify(s.map(f=>!!f.pending)));''', "queueLogic.js")
        self.assertEqual(out, [False, True, False, False])


@unittest.skipUnless(NODE, "node is not installed")
class QueueSavedViewTests(unittest.TestCase):
    def test_add_replaces_same_name_and_caps(self):
        out = run_js('''let v=[]; let r=M.addView(v,"  Payments  ","?team=Pay"); v=r.views; r=M.addView(v,"payments","?team=Pay2"); v=r.views;
          let full=Array.from({length:12},(_,i)=>({name:"v"+i,search:""})); const capped=M.addView(full,"extra","");
          console.log(JSON.stringify({v, err:M.addView([],"   ","").error, capped:capped.error}));''', "queueLogic.js")
        self.assertEqual(out["v"], [{"name": "payments", "search": "?team=Pay2"}])
        self.assertIn("name", out["err"])
        self.assertIn("At most", out["capped"])

    def test_sanitize_drops_foreign_or_malformed_entries(self):
        out = call("queueLogic.js", 'M.sanitizeViews([{name:"ok",search:"?a=1"},{name:"bad",search:"javascript:alert(1)"},{name:1,search:""},null,"x"])')
        self.assertEqual(out, [{"name": "ok", "search": "?a=1"}])

    def test_same_state_ignores_parameter_order(self):
        self.assertTrue(call("queueLogic.js", 'M.sameState("?kevOnly=true&priority=High","?priority=High&kevOnly=true")'))
        self.assertFalse(call("queueLogic.js", 'M.sameState("?kevOnly=true","")'))


if __name__ == "__main__":
    unittest.main()
