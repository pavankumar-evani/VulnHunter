// Pure logic behind the Remediation queue page (pages/queue.js): filter state in the URL, filtering, sorting, SLA maths, priority breakdown,
// bulk selection rules, saved views and optimistic-update helpers. No DOM, no network, so it is tested under Node (tests/test_modules_ui_js.py).

export const PRIORITIES = ["Critical", "High", "Medium", "Low"];
export const PRIORITY_RANK = { Critical: 3, High: 2, Medium: 1, Low: 0 };

// Every filter the page understands, with its URL parameter name, default and kind. Names are the ones older links already use, so
// deep links from other pages (?category=infra-vm, ?kevOnly=true, ?asset=web-01 ...) keep working.
export const FILTERS = [
  { key: "priority", param: "priority", def: "all" },
  { key: "assetType", param: "assetType", def: "all" },
  { key: "environment", param: "environment", def: "all" },
  { key: "category", param: "category", def: "all" },
  { key: "infraType", param: "infraType", def: "all" },
  { key: "slaStatus", param: "slaStatus", def: "all" },
  { key: "kevOnly", param: "kevOnly", def: false, bool: true },
  { key: "highEpssOnly", param: "highEpssOnly", def: false, bool: true },
  { key: "unownedOnly", param: "unowned", def: false, bool: true },
  { key: "cve", param: "cve", def: null },
  { key: "title", param: "title", def: null },
  { key: "assetName", param: "asset", def: null },
  { key: "severity", param: "severity", def: null },
  { key: "team", param: "team", def: null },
  { key: "ageBucket", param: "ageBucket", def: null },
  { key: "cloudProvider", param: "cloudProvider", def: null },
  { key: "assetOs", param: "assetOs", def: null },
  { key: "eolStatus", param: "eolStatus", def: null },
  { key: "q", param: "q", def: "" },
];
export const SORT_KEYS = ["priority", "id", "asset", "title", "cve", "epss", "kev", "sla", "last_seen", "first_seen", "score"];

export function defaultState() {
  const filters = {};
  for (const f of FILTERS) filters[f.key] = f.def;
  return { filters, sort: { key: "priority", dir: "desc" }, highlight: null };
}

// URL query string -> state. Unknown parameters are ignored, so a hand-edited link never breaks the page.
export function parseQueueState(search) {
  const p = new URLSearchParams(search || "");
  const st = defaultState();
  for (const f of FILTERS) {
    const v = p.get(f.param);
    if (v === null || v === "") continue;
    st.filters[f.key] = f.bool ? v === "true" || v === "1" : v;
  }
  if (!PRIORITIES.includes(st.filters.priority) && st.filters.priority !== "all") st.filters.priority = "all";
  const s = p.get("sort");
  if (s && SORT_KEYS.includes(s)) st.sort = { key: s, dir: p.get("dir") === "asc" ? "asc" : "desc" };
  st.highlight = p.get("highlight") || null;
  return st;
}

// state -> query string with only the non-default values, so the URL stays short and a default page has no query at all.
export function queueStateToSearch(st) {
  const p = new URLSearchParams();
  for (const f of FILTERS) {
    const v = st.filters[f.key];
    if (f.bool ? v === true : (v !== f.def && v !== null && v !== undefined && v !== "")) p.set(f.param, f.bool ? "true" : String(v));
  }
  if (st.sort && (st.sort.key !== "priority" || st.sort.dir !== "desc")) { p.set("sort", st.sort.key); p.set("dir", st.sort.dir); }
  if (st.highlight) p.set("highlight", st.highlight);
  const s = p.toString();
  return s ? `?${s}` : "";
}

export function activeFilterCount(filters) {
  let n = 0;
  for (const f of FILTERS) {
    const v = filters[f.key];
    if (f.bool ? v === true : v !== f.def && v !== null && v !== undefined && v !== "") n += 1;
  }
  return n;
}

// A readable label for each active filter (for the removable chips under the toolbar).
const FILTER_LABELS = {
  priority: "Priority", assetType: "Asset type", environment: "Environment", category: "Category", infraType: "Infra type", slaStatus: "SLA", kevOnly: "KEV only",
  highEpssOnly: "EPSS 50%+", unownedOnly: "Unowned", cve: "CVE", title: "Title", assetName: "Asset", severity: "Severity", team: "Team", ageBucket: "Age (days)",
  cloudProvider: "Cloud", assetOs: "OS", eolStatus: "EOL", q: "Search",
};
export function activeFilterChips(filters) {
  const chips = [];
  for (const f of FILTERS) {
    const v = filters[f.key];
    const active = f.bool ? v === true : v !== f.def && v !== null && v !== undefined && v !== "";
    if (active) chips.push({ key: f.key, label: FILTER_LABELS[f.key] || f.key, value: f.bool ? "" : String(v) });
  }
  return chips;
}
export function clearFilter(filters, key) {
  const f = FILTERS.find((x) => x.key === key);
  return f ? { ...filters, [key]: f.def } : { ...filters };
}

// ---------------------------------------------------------------- SLA
export function slaStatusOf(f) {
  const s = f.sla;
  if (s && s.breached) return "breached";
  if (s && s.days_remaining !== null && s.days_remaining !== undefined && s.days_remaining <= 3) return "at_risk";
  return "on_track";
}
export function slaSummary(findings) {
  const out = { breached: 0, at_risk: 0, on_track: 0 };
  for (const f of findings) out[slaStatusOf(f)] += 1;
  return out;
}
// The share of the SLA window already used, for the ring: window = due date minus first seen; no dates means no ring.
export function slaRingFor(f, now = new Date()) {
  const s = f.sla;
  if (!s || !s.due_date) return { state: "none", fraction: 0, label: "No SLA date" };
  if (s.breached) return { state: "breached", fraction: 1, label: `Breached ${Math.abs(s.days_remaining)} day${Math.abs(s.days_remaining) === 1 ? "" : "s"} ago` };
  const due = new Date(s.due_date).getTime();
  const start = f.first_seen ? new Date(f.first_seen).getTime() : NaN;
  const total = Number.isFinite(start) ? Math.max(1, Math.round((due - start) / 86400000)) : null;
  const left = s.days_remaining ?? Math.round((due - now.getTime()) / 86400000);
  const fraction = total ? Math.min(1, Math.max(0, (total - left) / total)) : 0.5;
  const state = left <= 3 ? "at_risk" : "ok";
  return { state, fraction, label: `${left} day${left === 1 ? "" : "s"} left of ${total ?? "?"}` };
}

// ---------------------------------------------------------------- filtering
export function ageBucketOf(firstSeen, today) {
  if (!firstSeen) return null;
  const seen = new Date(firstSeen);
  if (Number.isNaN(seen.getTime())) return null;
  const days = Math.floor((today - seen) / 86400000);
  if (days < 0) return null;
  return days <= 30 ? "0-30" : days <= 60 ? "31-60" : days <= 90 ? "61-90" : "90+";
}

function haystack(f) {
  return [f.id, f.title, f.cve, f.asset && f.asset.name, f.owner, f.team, f.source, f.rule_id].filter(Boolean).join(" ").toLowerCase();
}

export function applyQueueFilters(findings, flt, now = new Date()) {
  const q = String(flt.q || "").trim().toLowerCase();
  const words = q ? q.split(/\s+/) : [];
  return findings.filter((f) => {
    if (flt.priority !== "all" && f.priority !== flt.priority) return false;
    if (flt.assetType !== "all" && (f.asset && f.asset.type) !== flt.assetType) return false;
    if (flt.environment !== "all" && (f.environment || "unknown") !== flt.environment) return false;
    if (flt.category !== "all" && f.scan_type !== flt.category) return false;
    if (flt.infraType !== "all" && f.infra_category !== flt.infraType) return false;
    if (flt.kevOnly && !(f.kev && f.kev.listed)) return false;
    if (flt.highEpssOnly && !(f.epss && f.epss.score >= 0.5)) return false;
    if (flt.unownedOnly && (f.owner || f.team || f.assignee)) return false;
    if (flt.slaStatus && flt.slaStatus !== "all" && slaStatusOf(f) !== flt.slaStatus) return false;
    if (flt.cve && f.cve !== flt.cve) return false;
    if (flt.title && f.title !== flt.title) return false;
    if (flt.assetName && (f.asset && f.asset.name) !== flt.assetName) return false;
    if (flt.severity && f.severity !== flt.severity) return false;
    if (flt.team && f.team !== flt.team) return false;
    if (flt.ageBucket && ageBucketOf(f.first_seen, now) !== flt.ageBucket) return false;
    if (flt.cloudProvider && (f.cloud_provider || "Not attributed") !== flt.cloudProvider) return false;
    if (flt.assetOs && (f.asset && f.asset.os) !== flt.assetOs) return false;
    if (flt.eolStatus && (f.eol_status && f.eol_status.status) !== flt.eolStatus) return false;
    if (words.length) { const h = haystack(f); if (!words.every((w) => h.includes(w))) return false; }
    return true;
  });
}

// ---------------------------------------------------------------- sorting
function sortValue(f, key) {
  switch (key) {
    case "priority": return PRIORITY_RANK[f.priority] ?? -1;
    case "score": return f.score ?? null;
    case "sla": return f.sla && f.sla.days_remaining !== null && f.sla.days_remaining !== undefined ? f.sla.days_remaining : null;
    case "epss": return f.epss ? f.epss.score : null;
    case "kev": return f.kev && f.kev.listed ? 1 : 0;
    case "asset": return (f.asset && f.asset.name) || null;
    default: return f[key] ?? null;
  }
}
// Stable; findings with no value for the key always sort last, in both directions. Breaks priority ties by score so the top of the list is the real top.
export function sortQueue(findings, key = "priority", dir = "desc") {
  const sign = dir === "asc" ? 1 : -1;
  const dec = findings.map((f, i) => ({ f, i, v: sortValue(f, key), s: f.score ?? 0 }));
  dec.sort((a, b) => {
    const ae = a.v === null || a.v === undefined || a.v === "";
    const be = b.v === null || b.v === undefined || b.v === "";
    if (ae || be) return (ae ? 1 : 0) - (be ? 1 : 0) || a.i - b.i;
    let c = typeof a.v === "string" ? a.v.localeCompare(b.v, undefined, { numeric: true, sensitivity: "base" }) : a.v - b.v;
    if (c === 0 && key === "priority") c = a.s - b.s;
    return c * sign || a.i - b.i;
  });
  return dec.map((d) => d.f);
}

// ---------------------------------------------------------------- summaries
export function priorityBreakdown(findings) {
  const out = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const f of findings) if (f.priority in out) out[f.priority] += 1;
  return out;
}
// Counts for each facet value in the current slice, for the facet strip: [{value,count}] sorted by count desc.
export function facetCounts(findings, getValue, limit = 8) {
  const m = new Map();
  for (const f of findings) { const v = getValue(f); if (v === null || v === undefined || v === "") continue; m.set(v, (m.get(v) || 0) + 1); }
  return [...m.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || String(a.value).localeCompare(String(b.value))).slice(0, limit);
}
export function queueKpis(findings) {
  const sla = slaSummary(findings);
  const kev = findings.filter((f) => f.kev && f.kev.listed).length;
  const highEpss = findings.filter((f) => f.epss && f.epss.score >= 0.5).length;
  const unowned = findings.filter((f) => !f.owner && !f.team && !f.assignee).length;
  const excepted = findings.filter((f) => f.exception).length;
  return { total: findings.length, breached: sla.breached, atRisk: sla.at_risk, onTrack: sla.on_track, kev, highEpss, unowned, excepted, byPriority: priorityBreakdown(findings) };
}
// "Why this priority": the engine's own reasons plus the score, as ordered lines (never invented).
export function priorityReasons(f) {
  const lines = Array.isArray(f.reasons) ? f.reasons.slice() : [];
  return { score: f.score ?? null, priority: f.priority || null, lines };
}

// ---------------------------------------------------------------- selection (bulk actions)
export const MAX_BULK = 2000;
export function toggleSelection(selected, id) {
  const next = new Set(selected);
  if (next.has(id)) next.delete(id); else next.add(id);
  return next;
}
// Shift-click: select (or deselect) every id between the anchor and the target in the current visible order.
export function rangeSelection(selected, orderedIds, anchorId, targetId) {
  const a = orderedIds.indexOf(anchorId);
  const b = orderedIds.indexOf(targetId);
  if (a < 0 || b < 0) return toggleSelection(selected, targetId);
  const [lo, hi] = a < b ? [a, b] : [b, a];
  const next = new Set(selected);
  const turnOn = !selected.has(targetId);
  for (let i = lo; i <= hi; i += 1) { if (turnOn) next.add(orderedIds[i]); else next.delete(orderedIds[i]); }
  return next;
}
// Drop ids that are no longer in the data (a refresh may remove findings); returns the same Set when nothing changed.
export function pruneSelection(selected, validIds) {
  const valid = validIds instanceof Set ? validIds : new Set(validIds);
  let changed = false;
  const next = new Set();
  for (const id of selected) { if (valid.has(id)) next.add(id); else changed = true; }
  return changed ? next : selected;
}
export function selectionState(selected, visibleIds) {
  const n = visibleIds.filter((id) => selected.has(id)).length;
  return n === 0 ? "none" : n === visibleIds.length ? "all" : "some";
}
// Splits ids into batches the API accepts.
export function bulkBatches(ids, size = MAX_BULK) {
  const out = [];
  for (let i = 0; i < ids.length; i += size) out.push(ids.slice(i, i + size));
  return out;
}

// ---------------------------------------------------------------- optimistic updates
// Apply a patch to the selected findings immediately; returns { next, undo } where undo restores the exact previous objects.
export function applyOptimistic(findings, ids, patch) {
  const set = new Set(ids);
  const prev = new Map();
  const next = findings.map((f) => {
    if (!set.has(f.id)) return f;
    prev.set(f.id, f);
    return { ...f, ...patch, pending: true };
  });
  const undo = (current) => current.map((f) => (prev.has(f.id) ? prev.get(f.id) : f));
  return { next, undo, count: prev.size };
}
export function settle(findings, ids) {
  const set = new Set(ids);
  return findings.map((f) => (set.has(f.id) && f.pending ? { ...f, pending: false } : f));
}

// ---------------------------------------------------------------- saved views
export const MAX_VIEWS = 12;
export function normalizeViewName(name) { return String(name || "").replace(/\s+/g, " ").trim().slice(0, 40); }
export function addView(views, name, search) {
  const n = normalizeViewName(name);
  if (!n) return { views, error: "Give the view a name." };
  const rest = views.filter((v) => v.name.toLowerCase() !== n.toLowerCase());
  if (rest.length >= MAX_VIEWS) return { views, error: `At most ${MAX_VIEWS} saved views. Delete one first.` };
  return { views: [...rest, { name: n, search: String(search || "") }], error: "" };
}
export function removeView(views, name) { return views.filter((v) => v.name !== name); }
export function sanitizeViews(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.filter((v) => v && typeof v.name === "string" && typeof v.search === "string" && (v.search === "" || v.search.startsWith("?"))).slice(0, MAX_VIEWS)
    .map((v) => ({ name: normalizeViewName(v.name), search: v.search })).filter((v) => v.name);
}
// A view is "current" when its stored search describes the same state as the page right now.
export function sameState(searchA, searchB) {
  const a = queueStateToSearch(parseQueueState(searchA));
  const b = queueStateToSearch(parseQueueState(searchB));
  return a === b;
}

// ---------------------------------------------------------------- pagination of the visible window (for keyboard row navigation)
export function moveFocusIndex(current, key, total, pageSize = 10) {
  if (!total) return -1;
  const c = current < 0 ? 0 : current;
  if (key === "ArrowDown" || key === "j") return Math.min(total - 1, c + 1);
  if (key === "ArrowUp" || key === "k") return Math.max(0, c - 1);
  if (key === "PageDown") return Math.min(total - 1, c + pageSize);
  if (key === "PageUp") return Math.max(0, c - pageSize);
  if (key === "Home") return 0;
  if (key === "End") return total - 1;
  return c;
}
