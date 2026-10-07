"""Pure JavaScript of the UI kit, run under Node: fuzzy matching (fuzzy.js), table and counter maths (tableMath.js), live updates (live.js).
Skipped when Node is not installed (the app itself needs no Node: this only tests browser modules). The DOM parts (ui.js, the palette) are checked in a real browser."""
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
class FuzzyTests(unittest.TestCase):
    def test_subsequence_matches_and_non_matches(self):
        out = run_js("""console.log(JSON.stringify({a: !!M.fuzzyScore("rqu", "Remediation Queue"), b: M.fuzzyScore("zzz", "Remediation Queue"), c: !!M.fuzzyScore("", "x")}));""", "fuzzy.js")
        self.assertTrue(out["a"])
        self.assertIsNone(out["b"])
        self.assertTrue(out["c"])

    def test_scattered_letters_are_not_a_match_but_initials_are(self):
        out = run_js("""console.log(JSON.stringify({scattered: M.fuzzyScore("hunt", "Search, reputation and response endpoints"), initials: !!M.fuzzyScore("rq", "Remediation Queue"), close: !!M.fuzzyScore("hnt", "Hunting")}));""", "fuzzy.js")
        self.assertIsNone(out["scattered"])
        self.assertTrue(out["initials"])
        self.assertTrue(out["close"])

    def test_secondary_text_matches_by_substring_only(self):
        out = run_js("""
          const items = [{label: "Splunk", extra: "Search, reputation and response endpoints"}, {label: "Hunting", extra: "x"}];
          console.log(JSON.stringify(M.rank(items, "hunt", (i) => [i.label, i.extra]).map((r) => r.item.label)));""", "fuzzy.js")
        self.assertEqual(out, ["Hunting"])

    def test_every_word_must_match(self):
        out = run_js("""console.log(JSON.stringify({both: !!M.fuzzyScore("fire wall", "Firewall rules"), missing: M.fuzzyScore("fire zebra", "Firewall rules")}));""", "fuzzy.js")
        self.assertTrue(out["both"])
        self.assertIsNone(out["missing"])

    def test_prefix_and_word_start_beat_scattered_letters(self):
        out = run_js("""
          const items = [{label: "Threat models"}, {label: "Hunting and SOC triage"}, {label: "Hunt"}];
          console.log(JSON.stringify(M.rank(items, "hunt").map((r) => r.item.label)));""", "fuzzy.js")
        self.assertEqual(out[0], "Hunt")           # exact, short
        self.assertIn("Hunting and SOC triage", out)
        self.assertNotIn("Threat models", out)     # t-h-u-n-t is not an in-order subsequence of it

    def test_a_secondary_field_can_match_but_ranks_below_the_label(self):
        out = run_js("""
          const items = [{label: "Alpha", extra: "queue of work"}, {label: "Queue"}];
          console.log(JSON.stringify(M.rank(items, "queue", (i) => [i.label, i.extra]).map((r) => r.item.label)));""", "fuzzy.js")
        self.assertEqual(out, ["Queue", "Alpha"])

    def test_highlight_wraps_matched_letters_and_escapes_the_text(self):
        out = run_js("""console.log(JSON.stringify({h: M.highlight("a<b", [0, 2]), none: M.highlight("<i>", [])}));""", "fuzzy.js")
        self.assertEqual(out["h"], "<mark>a</mark>&lt;<mark>b</mark>")
        self.assertEqual(out["none"], "&lt;i&gt;")

    def test_empty_query_returns_items_in_order(self):
        out = run_js("""console.log(JSON.stringify(M.rank([{label:"b"},{label:"a"}], "").map((r) => r.item.label)));""", "fuzzy.js")
        self.assertEqual(out, ["b", "a"])


@unittest.skipUnless(NODE, "node is not installed")
class TableMathTests(unittest.TestCase):
    def test_sort_numbers_dates_severity_and_text_naturally(self):
        out = run_js("""
          const s = (rows, type, dir) => M.sortRows(rows, (r) => r, type, dir);
          console.log(JSON.stringify({
            num: s([10, 2, 33], "number", "asc"),
            date: s(["2026-03-01", "2025-12-31"], "date", "asc"),
            sev: s(["Low", "Critical", "Medium", "High"], "severity", "desc"),
            nat: s(["host10", "host2", "Host1"], "text", "asc")}));""", "tableMath.js")
        self.assertEqual(out["num"], [2, 10, 33])
        self.assertEqual(out["date"], ["2025-12-31", "2026-03-01"])
        self.assertEqual(out["sev"], ["Critical", "High", "Medium", "Low"])
        self.assertEqual(out["nat"], ["Host1", "host2", "host10"])

    def test_empty_values_sort_last_in_both_directions_and_the_sort_is_stable(self):
        out = run_js("""
          const rows = [{v: 3, n: "a"}, {v: null, n: "b"}, {v: 3, n: "c"}, {v: 1, n: "d"}];
          const names = (dir) => M.sortRows(rows, (r) => r.v, "number", dir).map((r) => r.n).join("");
          console.log(JSON.stringify({asc: names("asc"), desc: names("desc")}));""", "tableMath.js")
        self.assertEqual(out["asc"], "dacb")
        self.assertEqual(out["desc"], "acdb")

    def test_virtual_window_covers_the_viewport_with_overscan_and_honest_spacers(self):
        out = run_js("""
          const w = M.virtualWindow({total: 20000, rowHeight: 40, viewportHeight: 400, scrollTop: 40000, overscan: 5});
          const top = M.virtualWindow({total: 20000, rowHeight: 40, viewportHeight: 400, scrollTop: 0, overscan: 5});
          const end = M.virtualWindow({total: 20000, rowHeight: 40, viewportHeight: 400, scrollTop: 800000, overscan: 5});
          console.log(JSON.stringify({w, top, end, empty: M.virtualWindow({total: 0, rowHeight: 40, viewportHeight: 400, scrollTop: 0})}));""", "tableMath.js")
        w = out["w"]
        self.assertEqual(w["start"], 995)                       # row 1000 is at the top of the view; 5 rows of overscan above
        self.assertEqual(w["end"] - w["start"], 20)              # 10 visible rows + 5 overscan above and below: a screenful, never the 20,000
        self.assertEqual(w["padTop"] + (w["end"] - w["start"]) * 40 + w["padBottom"], 20000 * 40)   # scrollbar height stays exact
        self.assertEqual(out["top"]["start"], 0)
        self.assertEqual(out["end"]["end"], 20000)
        self.assertEqual(out["end"]["padBottom"], 0)
        self.assertEqual(out["empty"], {"start": 0, "end": 0, "padTop": 0, "padBottom": 0})

    def test_csv_quotes_and_defuses_spreadsheet_formulas(self):
        out = run_js("""
          const cols = [{label: "A"}, {label: "B"}];
          console.log(JSON.stringify(M.toCsv(cols, [["x,y", 'say "hi"'], ["=1+1", "-5"], ["+cmd", "line\\nbreak"]], (r, c) => r[c.label === "A" ? 0 : 1])));""", "tableMath.js")
        lines = out.split("\r\n")
        self.assertEqual(lines[0], "A,B")
        self.assertEqual(lines[1], '"x,y","say ""hi"""')
        self.assertEqual(lines[2], "'=1+1,-5")                  # formula neutralised; a plain negative number is left alone
        self.assertTrue(lines[3].startswith("'+cmd,"))

    def test_sparkline_points_scale_to_the_box_and_flat_series_are_centred(self):
        out = run_js("""console.log(JSON.stringify({p: M.sparkPoints([0, 5, 10], 100, 20, 0), flat: M.sparkPoints([4, 4], 100, 20, 0), few: M.sparkPoints([1], 100, 20)}));""", "tableMath.js")
        self.assertEqual(out["p"], [[0, 20], [50, 10], [100, 0]])   # higher value, higher on screen (smaller y)
        self.assertEqual([pt[1] for pt in out["flat"]], [10, 10])
        self.assertEqual(out["few"], [])

    def test_delta_direction_and_percentage(self):
        out = run_js("""console.log(JSON.stringify({up: M.delta(120, 100), down: M.delta(80, 100), flat: M.delta(5, 5), fromZero: M.delta(3, 0), bad: M.delta("x", 1)}));""", "tableMath.js")
        self.assertEqual(out["up"], {"pct": 20, "dir": "up"})
        self.assertEqual(out["down"], {"pct": -20, "dir": "down"})
        self.assertEqual(out["flat"]["dir"], "flat")
        self.assertEqual(out["fromZero"], {"pct": None, "dir": "up"})
        self.assertIsNone(out["bad"])

    def test_counter_easing_runs_from_start_to_end_monotonically(self):
        out = run_js("""console.log(JSON.stringify({a: M.easeCount(0, 100, 0), b: M.easeCount(0, 100, 1), over: M.easeCount(0, 100, 5), mid: M.easeCount(0, 100, 0.5), dec: M.easeCount(0, 1, 1, 1)}));""", "tableMath.js")
        self.assertEqual((out["a"], out["b"], out["over"]), (0, 100, 100))
        self.assertTrue(50 < out["mid"] < 100)                   # ease-out: past halfway at half time
        self.assertEqual(out["dec"], 1)

    def test_age_labels_and_states(self):
        out = run_js("""console.log(JSON.stringify([M.ageLabel(1000), M.ageLabel(30000), M.ageLabel(120000), M.ageLabel(7200000), M.ageLabel(3 * 86400000), M.ageState(1000), M.ageState(120000), M.ageState(9e6)]));""", "tableMath.js")
        self.assertEqual(out, ["just now", "30s ago", "2m ago", "2h ago", "3d ago", "fresh", "aging", "stale"])

    def test_column_width_is_clamped(self):
        out = run_js("""console.log(JSON.stringify([M.clampWidth(10), M.clampWidth(200.4), M.clampWidth(9999)]));""", "tableMath.js")
        self.assertEqual(out, [60, 200, 640])


FAKES = """
class FakeES {
  static last = null;
  constructor(url) { this.url = url; this.readyState = 1; this.listeners = {}; this.closed = false; FakeES.last = this; }
  addEventListener(t, cb) { (this.listeners[t] ||= []).push(cb); }
  close() { this.closed = true; this.readyState = 2; }
  emit(topic, data) { const ev = {data: JSON.stringify({topic, data})}; (this.listeners[topic] || []).forEach((cb) => cb(ev)); }
}
function fakeTimers() {
  const q = []; let id = 0;
  return { q, setTimeout: (fn, ms) => { q.push({id: ++id, fn, ms}); return id; }, clearTimeout: (i) => { const k = q.findIndex((t) => t.id === i); if (k >= 0) q.splice(k, 1); },
    async fire() { const t = q.shift(); if (t) await t.fn(); return t ? t.ms : null; } };
}
"""


@unittest.skipUnless(NODE, "node is not installed")
class LiveTests(unittest.TestCase):
    def test_backoff_doubles_up_to_the_cap_and_jitter_only_adds(self):
        out = run_js("""console.log(JSON.stringify({d: [0,1,2,3,4,5,9].map((n) => M.backoffDelay(n, 15000, 120000, 0)), j: M.backoffDelay(0, 10000, 120000, 1)}));""", "live.js")
        self.assertEqual(out["d"], [15000, 30000, 60000, 120000, 120000, 120000, 120000])
        self.assertEqual(out["j"], 12500)

    def test_subscribe_returns_an_unsubscribe_and_a_throwing_subscriber_does_not_stop_the_others(self):
        out = run_js("""
          const bus = new M.Bus(); const got = [];
          const off = bus.subscribe("t", (p) => got.push("a" + p));
          bus.subscribe("t", () => { throw new Error("boom"); });
          bus.subscribe("t", (p) => got.push("c" + p));
          const origErr = console.error; console.error = () => {};
          bus.emit("t", 1); off(); bus.emit("t", 2);
          console.error = origErr;
          console.log(JSON.stringify({got, count: bus.count()}));""", "live.js")
        self.assertEqual(out["got"], ["a1", "c1", "c2"])
        self.assertEqual(out["count"], 2)

    def test_server_sent_events_are_delivered_by_topic_and_the_mode_becomes_sse(self):
        out = run_js(FAKES + """
          const t = fakeTimers();
          const live = M.createLive({EventSource: FakeES, setTimeout: t.setTimeout, clearTimeout: t.clearTimeout, hidden: () => false, onVisible: () => {}});
          const got = []; const modes = [];
          live.subscribe("activity", (p) => got.push(p));
          live.subscribe("live.mode", (p) => modes.push(p.mode));
          FakeES.last.onopen();
          FakeES.last.emit("activity", {action: "a.b"});
          FakeES.last.emit("other", {x: 1});
          console.log(JSON.stringify({got, modes, url: FakeES.last.url, mode: live.state.mode}));""", "live.js")
        self.assertEqual(out["got"], [{"action": "a.b"}])
        self.assertEqual(out["modes"], ["sse"])
        self.assertEqual(out["url"], "/api/events")

    def test_a_refused_stream_closes_and_falls_back_to_polling_mode(self):
        out = run_js(FAKES + """
          const live = M.createLive({EventSource: FakeES, hidden: () => false, onVisible: () => {}});
          live.subscribe("activity", () => {});
          FakeES.last.readyState = 2; FakeES.last.onerror();
          console.log(JSON.stringify({mode: live.state.mode}));""", "live.js")
        self.assertEqual(out["mode"], "poll")

    def test_without_event_source_support_it_polls_and_never_throws(self):
        out = run_js("""
          const live = M.createLive({EventSource: null, hidden: () => false, onVisible: () => {}});
          live.subscribe("x", () => {});
          console.log(JSON.stringify({mode: live.state.mode}));""", "live.js")
        self.assertEqual(out["mode"], "poll")

    def test_poller_backs_off_while_nothing_changes_and_resets_when_something_does(self):
        out = run_js(FAKES + """
          const t = fakeTimers();
          const live = M.createLive({EventSource: null, setTimeout: t.setTimeout, clearTimeout: t.clearTimeout, hidden: () => false, onVisible: () => {}, rand: () => 0});
          let value = "a"; const seen = [];
          live.subscribe("data", (p) => seen.push(p.result));
          live.poll("data", async () => value, {every: 10000});
          await new Promise((r) => setTimeout(r, 5));          // first run: silent baseline
          const delays = [];
          for (let i = 0; i < 3; i++) { delays.push(await t.fire()); await new Promise((r) => setTimeout(r, 5)); }
          value = "b";
          delays.push(await t.fire()); await new Promise((r) => setTimeout(r, 5));
          delays.push(t.q[0].ms);
          console.log(JSON.stringify({delays, seen}));""", "live.js")
        # baseline scheduled 10s; unchanged reads double the wait; a change emits and returns to the base delay
        self.assertEqual(out["seen"], ["b"])
        self.assertEqual(out["delays"][0], 10000)
        self.assertEqual(out["delays"][1], 20000)
        self.assertEqual(out["delays"][2], 40000)
        self.assertEqual(out["delays"][-1], 10000)

    def test_polling_pauses_in_a_hidden_tab_and_resumes_when_visible(self):
        out = run_js(FAKES + """
          const t = fakeTimers(); let hidden = true; let visibleCb = null; let calls = 0;
          const live = M.createLive({EventSource: null, setTimeout: t.setTimeout, clearTimeout: t.clearTimeout, hidden: () => hidden, onVisible: (cb) => { visibleCb = cb; }, rand: () => 0});
          live.poll("p", async () => { calls++; return calls; }, {every: 1000});
          await new Promise((r) => setTimeout(r, 5));
          const whileHidden = {calls, queued: t.q.length};
          hidden = false; visibleCb(); await new Promise((r) => setTimeout(r, 5));
          console.log(JSON.stringify({whileHidden, after: calls}));""", "live.js")
        self.assertEqual(out["whileHidden"], {"calls": 0, "queued": 0})
        self.assertEqual(out["after"], 1)

    def test_stop_closes_the_stream_and_clears_timers(self):
        out = run_js(FAKES + """
          const t = fakeTimers();
          const live = M.createLive({EventSource: FakeES, setTimeout: t.setTimeout, clearTimeout: t.clearTimeout, hidden: () => false, onVisible: () => {}});
          live.subscribe("a", () => {});
          const stop = live.poll("a.poll", async () => 1, {every: 1000});
          await new Promise((r) => setTimeout(r, 5));
          live.stop();
          console.log(JSON.stringify({closed: FakeES.last.closed, timers: t.q.length, mode: live.state.mode}));""", "live.js")
        self.assertTrue(out["closed"])
        self.assertEqual(out["timers"], 0)
        self.assertEqual(out["mode"], "idle")


if __name__ == "__main__":
    unittest.main()
