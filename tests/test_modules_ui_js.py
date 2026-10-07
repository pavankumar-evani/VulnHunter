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


ROW = {"id": "F1", "assignment": {"status": "open", "assignee_email": "me@x"}, "sla": {"due_date": "2026-01-01", "days_remaining": -3, "breached": True}}
UNASSIGNED = {"id": "F2", "assignment": None, "sla": {"due_date": "2026-09-01", "days_remaining": 2, "breached": False}}
ME = {"email": "me@x", "role": "user"}
ADMIN = {"email": "boss@x", "role": "admin"}


@unittest.skipUnless(NODE, "node is not installed")
class AssignmentBoardRuleTests(unittest.TestCase):
    def plan(self, row, to, me):
        return call("moduleLogic.js", f"M.planAssignmentMove({json.dumps(row)}, {json.dumps(to)}, {json.dumps(me)})")

    def test_assignee_moves_own_work(self):
        p = self.plan(ROW, "in_progress", ME)
        self.assertEqual((p["ok"], p["action"], p["status"]), (True, "status", "in_progress"))

    def test_blocked_needs_a_note_and_resolved_explains_itself(self):
        self.assertEqual(self.plan(ROW, "blocked", ME)["needs"], "note")
        self.assertIn("next scan", self.plan(ROW, "resolved", ME)["note"])

    def test_someone_else_cannot_move_it_but_an_admin_can(self):
        self.assertFalse(self.plan(ROW, "blocked", {"email": "other@x", "role": "user"})["ok"])
        self.assertTrue(self.plan(ROW, "blocked", ADMIN)["ok"])

    def test_taking_unassigned_work_assigns_it_first(self):
        p = self.plan(UNASSIGNED, "in_progress", ME)
        self.assertEqual((p["ok"], p["action"], p["then"]), (True, "take", "in_progress"))
        self.assertIsNone(self.plan(UNASSIGNED, "open", ME)["then"])

    def test_nothing_moves_back_to_unassigned_by_drag(self):
        self.assertFalse(self.plan(ROW, "unassigned", ME)["ok"])
        self.assertIn("administrator", self.plan(ROW, "unassigned", ME)["reason"])

    def test_same_column_is_a_no_op(self):
        p = self.plan(ROW, "open", ME)
        self.assertTrue(p["same"])
        self.assertFalse(p["ok"])

    def test_kpis_count_open_work_for_sla(self):
        rows = [ROW, UNASSIGNED, {"id": "F3", "assignment": {"status": "resolved"}, "sla": {"breached": True, "days_remaining": -9}}]
        k = call("moduleLogic.js", f"M.assignmentKpis({json.dumps(rows)})")
        self.assertEqual((k["total"], k["unassigned"], k["open"], k["resolved"], k["breached"], k["atRisk"]), (3, 1, 1, 1, 1, 1))

    def test_url_state_round_trip_and_defaults(self):
        out = run_js('const s=M.parseAssignState("?view=team&priority=High&status=blocked&mode=table&include_resolved=true&q=web"); console.log(JSON.stringify([s, M.assignStateToSearch(s), M.assignStateToSearch(M.parseAssignState("")), M.parseAssignState("?view=bogus&status=bogus&priority=bogus").view]));', "moduleLogic.js")
        self.assertEqual(out[0]["view"], "team")
        self.assertTrue(out[0]["includeResolved"])
        self.assertEqual(sorted(out[1].lstrip("?").split("&")), sorted("view=team&priority=High&status=blocked&q=web&include_resolved=true&mode=table".split("&")))
        self.assertEqual(out[2], "")
        self.assertEqual(out[3], "mine")

    def test_sla_clock_wording(self):
        out = run_js('console.log(JSON.stringify([M.slaClock(null), M.slaClock({breached:true,days_remaining:-4,due_date:"x"}), M.slaClock({days_remaining:0,due_date:"x",breached:false}), M.slaClock({days_remaining:2,due_date:"x"}), M.slaClock({days_remaining:30,due_date:"2026-12-01"})]));', "moduleLogic.js")
        self.assertEqual([o["tone"] for o in out], ["none", "bad", "warn", "warn", "good"])
        self.assertEqual(out[1]["text"], "Breached 4d ago")
        self.assertEqual(out[2]["text"], "Due today")


PENDING = {"id": "APR-1", "status": "pending", "computed_status": "pending", "requested_by": "req@x", "playbook_lint": {"passed": True, "errors": 0, "warnings": 1}, "created_on": "2026-01-01"}


@unittest.skipUnless(NODE, "node is not installed")
class ApprovalRuleTests(unittest.TestCase):
    def can(self, fn, a, me):
        return call("moduleLogic.js", f"M.{fn}({json.dumps(a)}, {json.dumps(me)})")

    def test_admin_other_than_requester_can_approve(self):
        self.assertTrue(self.can("canApprove", PENDING, ADMIN)["ok"])

    def test_separation_of_duties(self):
        r = self.can("canApprove", PENDING, {"email": "REQ@x", "role": "admin"})
        self.assertFalse(r["ok"])
        self.assertIn("Separation of duties", r["reason"])

    def test_failed_lint_blocks_approval_with_the_count(self):
        r = self.can("canApprove", {**PENDING, "playbook_lint": {"passed": False, "errors": 2, "warnings": 0}}, ADMIN)
        self.assertFalse(r["ok"])
        self.assertIn("2 errors", r["reason"])
        self.assertTrue(self.can("canReject", {**PENDING, "playbook_lint": {"passed": False, "errors": 2, "warnings": 0}}, ADMIN)["ok"])

    def test_non_admin_and_decided_requests_cannot_be_decided(self):
        self.assertFalse(self.can("canApprove", PENDING, ME)["ok"])
        self.assertFalse(self.can("canApprove", {**PENDING, "computed_status": "approved"}, ADMIN)["ok"])
        self.assertFalse(self.can("canReject", {**PENDING, "computed_status": "expired"}, ADMIN)["ok"])

    def test_reason_validation(self):
        out = call("moduleLogic.js", 'M.validateReason("  too  ")')
        self.assertIn("at least 8", out)
        self.assertEqual(call("moduleLogic.js", 'M.validateReason("Needs a staging run first")'), "")

    def test_timeline_for_a_rejected_request_stops_at_the_decision(self):
        steps = call("moduleLogic.js", f'M.approvalTimeline({json.dumps({**PENDING, "computed_status": "rejected", "rejected_by": "boss@x", "rejected_at": "2026-01-02", "rejection_reason": "no"})})')
        self.assertEqual([s["id"] for s in steps], ["requested", "staging", "decision"])
        self.assertEqual(steps[2]["label"], "Rejected")

    def test_timeline_for_an_approved_triggered_request_waits_on_verification(self):
        a = {**PENDING, "computed_status": "remediation_triggered", "approved_by": "boss@x", "approved_at": "2026-01-02", "triggered_at": "2026-01-03", "triggered_by": "boss@x", "verification": {"state": "awaiting-rescan", "detail": "d"}}
        steps = call("moduleLogic.js", f"M.approvalTimeline({json.dumps(a)})")
        self.assertEqual([s["state"] for s in steps], ["done", "pending", "done", "done", "current"])
        a["verification"] = {"state": "still-present", "detail": "still there"}
        self.assertEqual(call("moduleLogic.js", f"M.approvalTimeline({json.dumps(a)})")[-1]["state"], "failed")

    def test_pending_with_a_passed_window_is_skipped_not_current(self):
        steps = call("moduleLogic.js", f'M.approvalTimeline({json.dumps({**PENDING, "computed_status": "expired"})})')
        self.assertEqual(steps[2]["state"], "skipped")

    def test_buckets_and_kpis(self):
        apps = [PENDING, {**PENDING, "id": "A2", "computed_status": "approved"}, {**PENDING, "id": "A3", "computed_status": "remediation_triggered", "verification": {"state": "still-present"}}, {**PENDING, "id": "A4", "computed_status": "rejected"},
                {**PENDING, "id": "A5", "playbook_lint": {"passed": False, "errors": 1, "warnings": 0}}]
        out = run_js(f'const a={json.dumps(apps)}; console.log(JSON.stringify({{b:a.map(M.approvalBucket), k:M.approvalKpis(a,{{avg_days_request_to_approval:2.5,fix_hold_rate:0.5}})}}));', "moduleLogic.js")
        self.assertEqual(out["b"], ["pending", "approved", "approved", "closed", "pending"])
        k = out["k"]
        self.assertEqual((k["pending"], k["approved"], k["triggered"], k["rejected"], k["lintFailed"], k["stillPresent"], k["avgDaysToApproval"], k["fixHoldRate"]), (2, 1, 1, 1, 1, 1, 2.5, 0.5))

    def test_needs_approval_orders_by_priority_and_skips_requested(self):
        fs = [{"id": "F10", "priority": "Low", "remediation_policy": {"change_type": "normal"}}, {"id": "F2", "priority": "Critical", "remediation_policy": {"change_type": "emergency"}},
              {"id": "F3", "priority": "High", "remediation_policy": {"change_type": "standard"}}, {"id": "F4", "priority": "High", "remediation_policy": {"change_type": "normal"}}]
        out = call("moduleLogic.js", f'M.needsApproval({json.dumps(fs)}, [{{finding_id:"F4"}}]).map(f=>f.id)')
        self.assertEqual(out, ["F2", "F10"])


@unittest.skipUnless(NODE, "node is not installed")
class ExceptionRuleTests(unittest.TestCase):
    NOW = "new Date(2026, 5, 15)"

    def test_states_and_countdown(self):
        out = run_js(f'const n={self.NOW}; console.log(JSON.stringify([M.exceptionState({{computed_status:"active",expires_on:"2026-06-20"}},n), M.exceptionState({{computed_status:"active",expires_on:"2026-06-15"}},n), M.exceptionState({{computed_status:"active",expires_on:"2026-09-01"}},n), M.exceptionState({{computed_status:"revoked"}},n), M.exceptionState({{computed_status:"expired"}},n)]));', "moduleLogic.js")
        self.assertEqual([o["key"] for o in out], ["expiring", "expiring", "active", "revoked", "expired"])
        self.assertEqual(out[0]["label"], "5d left")
        self.assertEqual(out[1]["label"], "Expires today")

    def test_kpis_count_expiring_inside_active(self):
        ex = [{"computed_status": "active", "expires_on": "2026-06-20"}, {"computed_status": "active", "expires_on": "2026-12-20"}, {"computed_status": "expired"}, {"computed_status": "revoked"}]
        k = run_js(f"console.log(JSON.stringify(M.exceptionKpis({json.dumps(ex)}, {self.NOW})));", "moduleLogic.js")
        self.assertEqual(k, {"active": 2, "expiring": 1, "expired": 1, "revoked": 1, "total": 4})

    def validate(self, **kw):
        base = {"finding_id": "F1", "reason": "Compensating control: isolated segment", "requested_by": "a@x", "approved_by": "b@x", "expires_on": "2026-07-15"}
        base.update(kw)
        return run_js(f"console.log(JSON.stringify(M.validateException({json.dumps(base)}, {self.NOW})));", "moduleLogic.js")

    def test_a_good_request_passes(self):
        self.assertEqual(self.validate(), "")

    def test_each_rule_the_server_enforces(self):
        self.assertIn("finding", self.validate(finding_id="").lower())
        self.assertIn("reason", self.validate(reason="short").lower())
        self.assertIn("future", self.validate(expires_on="2026-06-15"))
        self.assertIn("365", self.validate(expires_on="2028-01-01"))
        self.assertIn("Separation of duties", self.validate(approved_by="A@x"))
        self.assertIn("approves", self.validate(approved_by=""))
        self.assertIn("expiry", self.validate(expires_on="").lower())

    def test_add_days_iso(self):
        self.assertEqual(run_js('console.log(JSON.stringify(M.addDaysIso(30, new Date(2026, 0, 15))));', "moduleLogic.js"), "2026-02-14")

    def test_filter_records_requires_every_word(self):
        out = run_js('console.log(JSON.stringify(M.filterRecords([{a:"web server",b:"x"},{a:"web",b:"db"}], "web db", [(r)=>r.a,(r)=>r.b]).length));', "moduleLogic.js")
        self.assertEqual(out, 1)


@unittest.skipUnless(NODE, "node is not installed")
class PostureLogicTests(unittest.TestCase):
    def test_setting_text_by_kind(self):
        out = run_js('''console.log(JSON.stringify([
          M.settingText({kind:"env", key:"QUANTA_PRODUCTION", value:"true"}),
          M.settingText({kind:"helm", key:"replicaCount", value:3}),
          M.settingText({kind:"yaml", where:"remediation/config/ai_usage_policy.yaml", key:"allowed_models", value:["a","b"]}),
          M.settingText({kind:"page", where:"/applications", key:"x", value:"y"}),
          M.settingText({kind:"process", where:"CI", key:"POST /api/ingest/sbom", value:"on every release"}),
          M.settingText(null)]));''', "moduleLogic.js")
        self.assertEqual(out[0], "QUANTA_PRODUCTION=true")
        self.assertEqual(out[1], "--set replicaCount=3")
        self.assertEqual(out[2], '# remediation/config/ai_usage_policy.yaml\nallowed_models: ["a","b"]')
        self.assertEqual(out[3:], ["", "", ""])  # a page or a process has no setting to paste

    def test_actions_markdown_lists_each_action_with_its_setting(self):
        actions = [{"title": "Turn on X", "framework_title": "Zero trust", "status": "fail", "evidence": ["0 of 5"], "recommendation": "Set it.", "change": {"kind": "env", "key": "A", "value": "1", "where": "environment"}},
                   {"title": "Open it", "framework_title": "SDLC", "status": "partial", "evidence": [], "recommendation": "", "change": {"kind": "page", "where": "/x", "key": "k", "value": "v"}}]
        md = call("moduleLogic.js", f'M.actionsMarkdown({json.dumps(actions)}, "2026-01-01")')
        self.assertIn("# Security posture actions (2026-01-01)", md)
        self.assertIn("1. **Turn on X** (Zero trust, gap)", md)
        self.assertIn("A=1", md)
        self.assertIn("2. **Open it** (SDLC, partial)", md)
        self.assertIn("Where: /x > k (v)", md)

    def test_reading_history_is_throttled_and_capped(self):
        out = run_js('''let h=[]; h=M.pushReading(h,{overall:10},1000); h=M.pushReading(h,{overall:11},1000+60000); const afterGap=M.pushReading(h,{overall:12},1000+M.READING_GAP_MS+1);
          let big=[]; for(let i=0;i<40;i++) big=M.pushReading(big,{overall:i},i*M.READING_GAP_MS*2);
          console.log(JSON.stringify({sameWindow:h.length, afterGap:afterGap.length, capped:big.length, last:big[big.length-1].overall, junk:M.pushReading([null,{x:1},{t:5,overall:1}],{overall:2},9e9).length}));''', "moduleLogic.js")
        self.assertEqual(out, {"sameWindow": 1, "afterGap": 2, "capped": 24, "last": 39, "junk": 2})

    def test_reading_series_skips_missing_values(self):
        out = call("moduleLogic.js", 'M.readingSeries([{fw:{a:10}},{fw:{a:null}},{fw:{a:30}},{fw:{a:25}}], (r)=>r.fw.a)')
        self.assertEqual(out, {"values": [10, 30, 25], "current": 25, "previous": 30})
        self.assertEqual(call("moduleLogic.js", 'M.readingSeries([], (r)=>1)'), {"values": [], "current": None, "previous": None})

    def test_score_tone_and_totals(self):
        self.assertEqual(call("moduleLogic.js", '[M.scoreTone(null), M.scoreTone(10), M.scoreTone(40), M.scoreTone(70)]'), ["none", "bad", "warn", "good"])
        t = call("moduleLogic.js", 'M.postureTotals([{counts:{pass:1,fail:2}},{counts:{pass:3,unknown:4}},{}])')
        self.assertEqual(t, {"pass": 4, "partial": 0, "fail": 2, "unknown": 4, "na": 0})

    def test_filter_checks(self):
        checks = [{"status": "fail", "title": "Backups tested"}, {"status": "partial", "title": "Logging", "detail": "retention is short"}, {"status": "pass", "title": "MFA"}, {"status": "unknown", "title": "Backups offsite"}]
        out = run_js(f'const c={json.dumps(checks)}; console.log(JSON.stringify([M.filterChecks(c,"gaps").length, M.filterChecks(c,"fail").length, M.filterChecks(c,"all","backups").length, M.filterChecks(c,"all","retention short").length, M.filterChecks(c,"pass","backups").length]));', "moduleLogic.js")
        self.assertEqual(out, [2, 1, 2, 1, 0])


@unittest.skipUnless(NODE, "node is not installed")
class ComplianceLogicTests(unittest.TestCase):
    RISKS = [{"id": 1, "inherent_likelihood": 5, "inherent_impact": 5}, {"id": 2, "inherent_likelihood": 5, "inherent_impact": 5}, {"id": 3, "inherent_likelihood": 1, "inherent_impact": 1}, {"id": 4, "inherent_likelihood": 9, "inherent_impact": 0}]

    def test_grid_is_five_by_five_with_impact_five_on_top(self):
        grid = call("moduleLogic.js", f"M.riskGrid({json.dumps(self.RISKS)})")
        self.assertEqual((len(grid), len(grid[0])), (5, 5))
        self.assertEqual((grid[0][4]["likelihood"], grid[0][4]["impact"], grid[0][4]["count"], grid[0][4]["ids"]), (5, 5, 2, [1, 2]))
        self.assertEqual((grid[4][0]["likelihood"], grid[4][0]["impact"], grid[4][0]["count"]), (1, 1, 1))
        self.assertEqual(sum(c["count"] for row in grid for c in row), 3)  # an out-of-range risk is not drawn

    def test_residual_grid_uses_residual_fields(self):
        grid = call("moduleLogic.js", 'M.riskGrid([{id:1,residual_likelihood:2,residual_impact:3}], "residual")')
        self.assertEqual(grid[2][1]["count"], 1)  # impact 3 is row index 2, likelihood 2 is column index 1

    def test_grid_levels_match_the_register_bands(self):
        out = call("moduleLogic.js", "[M.gridLevel(1,4), M.gridLevel(1,5), M.gridLevel(2,5), M.gridLevel(3,5), M.gridLevel(5,5)]")
        self.assertEqual(out, ["Low", "Medium", "High", "Critical", "Critical"])

    def test_result_counts_and_filter(self):
        tests = [{"result": "pass"}, {"result": "fail"}, {"result": "pass"}, {"result": "weird"}]
        self.assertEqual(call("moduleLogic.js", f"M.resultCounts({json.dumps(tests)})"), {"pass": 2, "fail": 1, "warn": 0, "na": 0, "error": 0})
        self.assertEqual(call("moduleLogic.js", f'M.filterByResult({json.dumps(tests)}, "fail").length'), 1)
        self.assertEqual(call("moduleLogic.js", f'M.filterByResult({json.dumps(tests)}, "all").length'), 4)

    def test_controls_sort_with_what_needs_work_first(self):
        cs = [{"control_id": "AC-10", "status": "satisfied"}, {"control_id": "AC-2", "status": "not-satisfied"}, {"control_id": "AC-1", "status": "partially"}, {"control_id": "AC-3", "status": "not-satisfied"}]
        out = call("moduleLogic.js", f"M.sortControls({json.dumps(cs)}).map((c) => c.control_id)")
        self.assertEqual(out, ["AC-2", "AC-3", "AC-1", "AC-10"])

    def test_framework_bar_has_every_status(self):
        parts = call("moduleLogic.js", 'M.frameworkBar({satisfied:3, partially:1, "not-satisfied":2, "not-evidenced":4})')
        self.assertEqual([p["value"] for p in parts], [3, 1, 2, 0, 4])


@unittest.skipUnless(NODE, "node is not installed")
class FixPrLifecycleTests(unittest.TestCase):
    def lane(self, **kw):
        return call("moduleLogic.js", f"M.prLane({json.dumps(kw)})")

    def test_each_status_has_one_lane(self):
        self.assertEqual(self.lane(status="draft"), "proposed")
        self.assertEqual(self.lane(status="approved"), "approved")
        self.assertEqual(self.lane(status="pr-opened"), "open")
        self.assertEqual(self.lane(status="in-review"), "open")
        self.assertEqual(self.lane(status="merged", verified_state="awaiting-rescan"), "merged")
        self.assertEqual(self.lane(status="merged", verified_state="still-present"), "merged")
        self.assertEqual(self.lane(status="merged", verified_state="verified"), "verified")
        for s in ("failed", "closed", "discarded", "something-new"):
            self.assertEqual(self.lane(status=s), "stopped")

    def test_groups_and_kpis(self):
        ps = [{"id": 1, "status": "draft"}, {"id": 2, "status": "pr-opened", "checks_state": "failing"}, {"id": 3, "status": "merged", "verified_state": "still-present"}, {"id": 4, "status": "merged", "verified_state": "verified"}, {"id": 5, "status": "failed"}]
        k = call("moduleLogic.js", f"M.prKpis({json.dumps(ps)})")
        self.assertEqual((k["total"], k["proposed"], k["open"], k["merged"], k["verified"], k["stopped"], k["attention"]), (5, 1, 1, 1, 1, 1, 3))

    def test_attention_reasons(self):
        out = call("moduleLogic.js", 'M.prAttention({status:"in-review", review_state:"changes_requested", checks_state:"failure"})')
        self.assertEqual(out, ["Checks are failing", "Changes were requested"])
        self.assertEqual(call("moduleLogic.js", 'M.prAttention({status:"draft"})'), [])

    def test_actions_depend_on_status_and_role(self):
        self.assertEqual(call("moduleLogic.js", 'M.prActions({status:"draft"}, true)'), ["approve", "discard"])
        self.assertEqual(call("moduleLogic.js", 'M.prActions({status:"approved"}, true)'), ["preview", "discard"])
        self.assertEqual(call("moduleLogic.js", 'M.prActions({status:"failed"}, true)'), ["preview", "discard"])
        self.assertEqual(call("moduleLogic.js", 'M.prActions({status:"in-review"}, true)'), ["sync"])
        self.assertEqual(call("moduleLogic.js", 'M.prActions({status:"merged"}, true)'), [])
        self.assertEqual(call("moduleLogic.js", 'M.prActions({status:"draft"}, false)'), [])


@unittest.skipUnless(NODE, "node is not installed")
class GateHistoryTests(unittest.TestCase):
    HIST = [
        {"application": "web", "environment": "prod", "decision": "fail", "evaluated_at": "2026-01-02T10:00:00Z"},
        {"application": "web", "environment": "prod", "decision": "pass", "evaluated_at": "2026-01-03T10:00:00Z"},
        {"application": "api", "environment": "prod", "decision": "warn", "evaluated_at": "2026-01-03T12:00:00Z"},
        {"application": "api", "environment": "dev", "decision": "pass", "evaluated_at": "2026-01-01T09:00:00Z"},
    ]

    def test_stats(self):
        s = call("moduleLogic.js", f"M.gateStats({json.dumps(self.HIST)})")
        self.assertEqual((s["n"], s["pass"], s["warn"], s["fail"], s["passRate"]), (4, 2, 1, 1, 50))
        self.assertEqual([(h["application"], h["decision"]) for h in s["latest"]], [("api", "warn"), ("web", "pass")])

    def test_empty_history_has_no_rate(self):
        s = call("moduleLogic.js", "M.gateStats([])")
        self.assertEqual((s["n"], s["passRate"], s["latest"]), (0, None, []))

    def test_grouping_by_day_newest_first(self):
        g = call("moduleLogic.js", f"M.groupByDay({json.dumps(self.HIST)}, (h) => h.evaluated_at)")
        self.assertEqual([x["day"] for x in g], ["2026-01-03", "2026-01-02", "2026-01-01"])
        self.assertEqual(len(g[0]["items"]), 2)


if __name__ == "__main__":
    unittest.main()
