// Pure logic for the SOC command center (no DOM, no fetch), so it is tested under Node: tests/test_soc_hunt_ui_js.py.
// Everything that decides something lives here; pages/soc.js and socIncident.js only draw it and call the API.

export const WORKING = ["new", "triaging", "investigating", "contained"];
export const STATUS_ORDER = ["new", "triaging", "investigating", "contained", "resolved"];
export const STATUS_LABEL = { new: "New", triaging: "Triaging", investigating: "Investigating", contained: "Contained", resolved: "Resolved", auto_closed: "Auto-closed", merged: "Merged" };
export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
export const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
export const KILL_CHAIN = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact"];
export const VERDICTS = ["true-positive", "false-positive", "benign", "duplicate", "insufficient-data", "accepted-risk"];

// ---------------------------------------------------------------- moving a card (drag and drop, or the keyboard menu)
// Returns what the server calls would be, or why the move is not allowed. The caller runs `steps` in order; a step with `needs`
// asks the analyst first (a resolve needs a verdict and a written summary, a reopen needs a reason).
export function planMove(incident, toStatus) {
  const from = incident && incident.status;
  if (!incident || !toStatus) return { ok: false, reason: "Nothing to move." };
  if (from === toStatus) return { ok: false, same: true, reason: "" };
  if (from === "merged") return { ok: false, reason: "A merged incident is closed to changes; open the one it was merged into." };
  if (from === "auto_closed") {
    return { ok: true, steps: [{ action: "undo-auto-close", body: {}, needs: null }], note: "Undo the automatic closure and send it back through routing." };
  }
  if (toStatus === "auto_closed" || toStatus === "merged") return { ok: false, reason: "Quanta closes and merges incidents itself; an analyst resolves one with a verdict." };
  if (toStatus === "new") return { ok: false, reason: "An incident cannot go back to New. Move it to Triaging, or reassign it." };
  if (from === "resolved") {
    return { ok: true, steps: [{ action: "reopen", body: {}, needs: "reason" }], note: "Reopen it first (a reason is required)." };
  }
  if (toStatus === "resolved") return { ok: true, steps: [{ action: "resolve", body: {}, needs: "verdict" }], note: "Resolving needs a verdict and a short written summary." };
  const steps = [];
  if (from === "new") steps.push({ action: "accept", body: {}, needs: null });
  if (toStatus !== "triaging" || from !== "new") steps.push({ action: "advance", body: { status: toStatus }, needs: null });
  return { ok: true, steps };
}

// Next status for the "advance" key, or null when the incident is at the end of the working states.
export function nextStatus(status) {
  const i = WORKING.indexOf(status);
  return i >= 0 && i < WORKING.length - 1 ? WORKING[i + 1] : null;
}

// ---------------------------------------------------------------- filters kept in the URL
export const FILTER_KEYS = ["view", "scope", "tier", "severity", "status", "sla", "q"];
export function parseFilters(search) {
  const p = new URLSearchParams(String(search || "").replace(/^\?/, ""));
  const f = { view: p.get("view") === "list" ? "list" : "board", scope: ["mine", "unassigned", "team"].includes(p.get("scope")) ? p.get("scope") : "all",
    tier: ["1", "2", "3"].includes(p.get("tier")) ? p.get("tier") : "", severity: SEVERITIES.includes(p.get("severity")) ? p.get("severity") : "",
    status: [...STATUS_ORDER, "auto_closed"].includes(p.get("status")) ? p.get("status") : "", sla: ["at_risk", "breached", "any"].includes(p.get("sla")) ? p.get("sla") : "", q: (p.get("q") || "").slice(0, 80) };
  return f;
}
// Only non-default values are written, so the plain /soc link stays clean. `extra` carries things like `incident`.
export function filtersToSearch(f, extra = {}) {
  const p = new URLSearchParams();
  if (f.view === "list") p.set("view", "list");
  if (f.scope && f.scope !== "all") p.set("scope", f.scope);
  for (const k of ["tier", "severity", "status", "sla", "q"]) if (f[k]) p.set(k, f[k]);
  for (const [k, v] of Object.entries(extra)) if (v !== null && v !== undefined && v !== "") p.set(k, v);
  const s = p.toString();
  return s ? `?${s}` : "";
}
export function applyFilters(list, f, me) {
  const q = (f.q || "").trim().toLowerCase();
  const email = String(me || "").toLowerCase();
  return list.filter((i) => {
    if (f.scope === "mine" && String(i.assignee || "").toLowerCase() !== email) return false;
    if (f.scope === "unassigned" && i.assignee) return false;
    if (f.scope === "team" && String(i.assignee || "").toLowerCase() === email) return false;
    if (f.tier && String(i.tier) !== f.tier) return false;
    if (f.severity && i.severity !== f.severity) return false;
    if (f.status && i.status !== f.status) return false;
    if (f.sla) {
      const w = i.sla && i.sla.worst;
      if (f.sla === "any" ? !(w === "at_risk" || w === "breached") : w !== f.sla) return false;
    }
    if (q) {
      const hay = [i.id, "#" + i.id, i.title, i.assignee, i.severity, i.status, ...(i.entities ? [...(i.entities.hosts || []), ...(i.entities.users || []), ...(i.entities.indicators || [])] : []),
        ...(i.cves || []), ...(i.techniques || []).map((t) => t.id)].join(" ").toLowerCase();
      if (!q.split(/\s+/).every((w) => hay.includes(w))) return false;
    }
    return true;
  });
}

// ---------------------------------------------------------------- SLA ring
export function fmtMinutes(m) {
  if (m === null || m === undefined || Number.isNaN(Number(m))) return "n/a";
  const late = m < 0;
  const a = Math.abs(Math.round(m));
  const h = Math.floor(a / 60);
  const txt = h >= 48 ? `${Math.round(h / 24)}d` : h >= 1 ? `${h}h ${a % 60 ? (a % 60) + "m" : ""}`.trim() : `${a}m`;
  return late ? `${txt} late` : txt;
}
// The ring shows the clock that matters now: the first running clock in ack, pickup, resolve order. fraction is elapsed over target (0..1), so a full ring means due.
export function slaRing(sla) {
  if (!sla) return { state: "none", fraction: 0, label: "No clock", clock: null };
  for (const clock of ["ack", "pickup", "resolve"]) {
    const c = sla[clock];
    if (!c || c.done) continue;
    const target = Number(c.target_minutes) || 0;
    const elapsed = Number(c.elapsed_minutes);
    const fraction = target > 0 && Number.isFinite(elapsed) ? Math.max(0, Math.min(1, elapsed / target)) : 0;
    const state = c.state === "breached" ? "breached" : c.state === "at_risk" ? "at_risk" : "ok";
    return { state, fraction, clock, label: `${clock} ${fmtMinutes(c.remaining_minutes)}${c.remaining_minutes < 0 ? "" : " left"}`, remaining: c.remaining_minutes };
  }
  return { state: "done", fraction: 1, label: "Clocks met", clock: null };
}
export function ringDash(fraction, radius = 11) {
  const c = 2 * Math.PI * radius;
  return { circumference: Math.round(c * 100) / 100, offset: Math.round(c * (1 - Math.max(0, Math.min(1, fraction))) * 100) / 100 };
}

// ---------------------------------------------------------------- KPI strip
const dayOf = (iso) => String(iso || "").slice(0, 10);
export function kpis(incidents, me, now = new Date()) {
  const email = String(me || "").toLowerCase();
  const open = incidents.filter((i) => WORKING.includes(i.status));
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((i) => i.severity === s).length]));
  const today = now.toISOString().slice(0, 10);
  return {
    open: open.length, bySeverity,
    mine: open.filter((i) => String(i.assignee || "").toLowerCase() === email && email).length,
    unassigned: open.filter((i) => !i.assignee).length,
    atRisk: open.filter((i) => i.sla && i.sla.worst === "at_risk").length,
    breached: open.filter((i) => i.sla && i.sla.worst === "breached").length,
    autoClosedToday: incidents.filter((i) => i.status === "auto_closed" && dayOf(i.updated_at || i.created_at) === today).length,
    autoClosed: incidents.filter((i) => i.status === "auto_closed").length,
  };
}
// metrics.daily is [{date, opened, resolved}]; a sparkline needs at least 3 points with some signal, otherwise "not enough history".
export function sparkSeries(daily, key, n = 14) {
  const v = (daily || []).slice(-n).map((d) => Number(d[key]) || 0);
  return v.length >= 3 && v.some((x) => x > 0) ? v : null;
}
// Compare the last half of the window with the one before it; null when either half is empty of data.
export function halfDelta(series) {
  if (!series || series.length < 4) return null;
  const mid = Math.floor(series.length / 2);
  const prev = series.slice(0, mid).reduce((a, b) => a + b, 0);
  const cur = series.slice(series.length - mid).reduce((a, b) => a + b, 0);
  return { current: cur, previous: prev };
}

// ---------------------------------------------------------------- the card's kill-chain dots
export function killChainDots(killChain) {
  const reached = new Set((killChain || []).map((s) => s.tactic));
  const dots = KILL_CHAIN.map((t) => ({ tactic: t, reached: reached.has(t) }));
  return { dots, count: dots.filter((d) => d.reached).length, extra: [...reached].filter((t) => !KILL_CHAIN.includes(t)) };
}

// ---------------------------------------------------------------- ordering and live merge
export function sortIncidents(list) {
  return [...list].sort((a, b) => {
    const wa = WORKING.includes(a.status) ? 0 : 1; const wb = WORKING.includes(b.status) ? 0 : 1;
    if (wa !== wb) return wa - wb;
    const pa = String(a.priority || "P9"); const pb = String(b.priority || "P9");
    if (pa !== pb) return pa < pb ? -1 : 1;
    const sa = SEV_RANK[a.severity] ?? 9; const sb = SEV_RANK[b.severity] ?? 9;
    if (sa !== sb) return sa - sb;
    return String(b.updated_at || "").localeCompare(String(a.updated_at || ""));
  });
}
export function upsertIncident(list, incident) {
  const i = list.findIndex((x) => x.id === incident.id);
  if (i < 0) return [incident, ...list];
  const next = list.slice();
  next[i] = { ...list[i], ...incident };
  return next;
}
// Ids whose visible fields changed between two lists (for the brief highlight), plus ids that are new.
export function changedIds(prev, next) {
  const before = new Map(prev.map((i) => [i.id, i]));
  const out = [];
  for (const i of next) {
    const b = before.get(i.id);
    if (!b || b.status !== i.status || b.assignee !== i.assignee || b.severity !== i.severity || b.tier !== i.tier || (b.sla && b.sla.worst) !== (i.sla && i.sla.worst) || b.verdict !== i.verdict) out.push(i.id);
  }
  return out;
}
export function newCritical(prev, next) {
  const had = new Set(prev.map((i) => i.id));
  return next.filter((i) => !had.has(i.id) && i.severity === "Critical" && WORKING.includes(i.status));
}
export function boardColumns(incidents) {
  return STATUS_ORDER.map((s) => ({ status: s, items: incidents.filter((i) => i.status === s) }));
}

// ---------------------------------------------------------------- initials and colour for an assignee avatar
export function initials(email) {
  const name = String(email || "").split("@")[0].replace(/[._-]+/g, " ").trim();
  if (!name) return "?";
  const parts = name.split(/\s+/);
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : name.slice(0, 2)).toUpperCase();
}
export function hueOf(text) {
  let h = 0;
  for (const ch of String(text || "")) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return h;
}

// ---------------------------------------------------------------- attack flow layout
// Lanes are the stages (left to right in kill-chain order as the report gives them); alert nodes stack in their lane in time order; entities sit in a row below.
export function attackFlowLayout(flow, { laneW = 190, nodeW = 168, nodeH = 54, gapY = 16, padTop = 34, entityH = 34, entityGap = 10, entityRowGap = 34, maxEntityW = 150 } = {}) {
  if (!flow || !Array.isArray(flow.nodes) || !flow.nodes.length) return { width: 0, height: 0, lanes: [], nodes: [], edges: [] };
  const stages = (flow.stages || []).slice();
  const alerts = flow.nodes.filter((n) => n.kind === "alert");
  for (const n of alerts) if (n.stage && !stages.includes(n.stage)) stages.push(n.stage);
  const lanes = stages.map((s, i) => ({ stage: s, x: i * laneW, w: laneW, count: 0 }));
  const laneOf = new Map(lanes.map((l) => [l.stage, l]));
  const placed = [];
  const sorted = alerts.slice().sort((a, b) => String(a.at || "").localeCompare(String(b.at || "")));
  let tallest = 0;
  for (const n of sorted) {
    const lane = laneOf.get(n.stage) || laneOf.get("Unmapped") || lanes[lanes.length - 1];
    if (!lane) continue;
    const y = padTop + lane.count * (nodeH + gapY);
    lane.count += 1;
    placed.push({ ...n, x: lane.x + (laneW - nodeW) / 2, y, w: nodeW, h: nodeH });
    tallest = Math.max(tallest, y + nodeH);
  }
  const width = Math.max(lanes.length * laneW, laneW);
  const ents = flow.nodes.filter((n) => n.kind !== "alert");
  const rowY = tallest + entityRowGap;
  const per = Math.max(1, Math.floor((width + entityGap) / (maxEntityW + entityGap)));
  const entW = Math.min(maxEntityW, per ? (width - entityGap * (per - 1)) / per : maxEntityW);
  let height = tallest + padTop / 2;
  ents.forEach((n, i) => {
    const row = Math.floor(i / per);
    const col = i % per;
    placed.push({ ...n, x: col * (entW + entityGap), y: rowY + row * (entityH + entityGap), w: entW, h: entityH });
    height = Math.max(height, rowY + row * (entityH + entityGap) + entityH);
  });
  height += 12;
  const byId = new Map(placed.map((n) => [n.id, n]));
  const edges = [];
  for (const e of flow.edges || []) {
    const a = byId.get(e.from); const b = byId.get(e.to);
    if (!a || !b) continue;
    let path;
    if (b.kind === "entity") {
      const x1 = a.x + a.w / 2; const y1 = a.y + a.h; const x2 = b.x + b.w / 2; const y2 = b.y;
      const my = (y1 + y2) / 2;
      path = `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`;
    } else if (a.x === b.x) {
      const x = a.x + a.w / 2;
      path = a.y <= b.y ? `M${x},${a.y + a.h} L${x},${b.y}` : `M${x},${a.y} L${x},${b.y + b.h}`;
    } else {
      const forward = a.x < b.x;
      const x1 = forward ? a.x + a.w : a.x; const x2 = forward ? b.x : b.x + b.w;
      const y1 = a.y + a.h / 2; const y2 = b.y + b.h / 2;
      const mx = (x1 + x2) / 2;
      path = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
    }
    edges.push({ ...e, path });
  }
  return { width, height, lanes, nodes: placed, edges, laneHeight: tallest + padTop / 2 };
}

// Timeline filtered by a node click: keep events that name the node's alert; with no selection, everything.
export function filterTimeline(timeline, node) {
  if (!node) return timeline;
  if (node.kind === "alert") {
    const id = Number(String(node.id).replace(/^a/, ""));
    return timeline.filter((e) => e.alert_id === id);
  }
  const needle = String(node.label || "").toLowerCase();
  return needle ? timeline.filter((e) => String(e.event || "").toLowerCase().includes(needle)) : timeline;
}
export function timelineIcon(event) {
  const t = String(event || "").toLowerCase();
  if (t.startsWith("alert raised")) return "alert";
  if (t.includes("investigat")) return "search";
  if (t.includes("block") || t.includes("contain") || t.includes("isolat")) return "shield";
  if (t.includes("resolved") || t.includes("closed")) return "check";
  if (t.includes("escalat")) return "up";
  return "dot";
}

// ---------------------------------------------------------------- evidence marks
// A statement with no evidence refs is shown as "not evidenced"; refs that point at nothing are reported rather than hidden.
export function evidenceMarks(statement, evidenceList) {
  const known = new Map((evidenceList || []).map((e) => [e.ref, e]));
  const refs = (statement && statement.evidence) || [];
  const found = refs.filter((r) => known.has(r)).map((r) => known.get(r));
  return { evidenced: found.length > 0, items: found, missing: refs.filter((r) => !known.has(r)) };
}

// ---------------------------------------------------------------- follow-up and verdict presentation
export function verdictTone(label) {
  return label === "true-positive" ? "critical" : label === "false-positive" ? "good" : label === "action-needed" ? "warn" : "neutral";
}
export function verdictText(label) {
  return { "true-positive": "True positive", "false-positive": "False positive", "action-needed": "Action needed", benign: "Benign", duplicate: "Duplicate", "insufficient-data": "Insufficient data", "accepted-risk": "Accepted risk" }[label] || (label ? String(label) : "Not yet assessed");
}
export function confidenceText(c) { return c === null || c === undefined ? "confidence not stated" : `${Math.round(Number(c) * 100)}% confidence`; }

// ---------------------------------------------------------------- the live feed
// One EventSource on /api/soc/incidents/stream when the browser has one; a refusal or repeated errors switch to polling `pollFn`. All browser parts are injected for tests.
export function connectIncidentFeed(env, { onEvent, onMode, pollFn, pollEvery = 20000, url = "/api/soc/incidents/stream" }) {
  const E = { ES: env.EventSource !== undefined ? env.EventSource : null, st: env.setTimeout, ct: env.clearTimeout };
  const TYPES = ["incident.created", "incident.assigned", "incident.updated"];
  let src = null; let timer = null; let stopped = false; let fails = 0; let mode = "idle";
  const setMode = (m) => { if (m !== mode) { mode = m; if (onMode) onMode(m); } };
  const poll = () => {
    if (stopped) return;
    Promise.resolve(pollFn && pollFn()).catch(() => {}).finally(() => { if (!stopped) timer = E.st(poll, pollEvery); });
  };
  const fallback = () => {
    if (src) { try { src.close(); } catch { /* already closed */ } src = null; }
    if (stopped || mode === "poll") return;
    setMode("poll");
    timer = E.st(poll, pollEvery);
  };
  if (!E.ES) fallback();
  else {
    try {
      src = new E.ES(url);
      src.onopen = () => { fails = 0; setMode("live"); };
      for (const t of TYPES) src.addEventListener(t, (ev) => { let d = null; try { d = JSON.parse(ev.data); } catch { return; } if (onEvent) onEvent(d, t); });
      src.onerror = () => { fails += 1; if (fails >= 3 || (src && src.readyState === 2)) fallback(); else setMode("reconnecting"); };
    } catch { fallback(); }
  }
  return { stop() { stopped = true; if (timer) E.ct(timer); if (src) { try { src.close(); } catch { /* ignore */ } } }, mode: () => mode };
}
