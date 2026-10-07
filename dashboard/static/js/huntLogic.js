// Pure logic for the Threat Hunting page (no DOM, no fetch); tested under Node in tests/test_soc_hunt_ui_js.py.

export const HUNT_TYPES = ["intel-driven", "hypothesis-driven", "baseline-anomaly", "model-assisted"];
export const TYPE_LABEL = { "intel-driven": "Intel-driven", "hypothesis-driven": "Hypothesis-driven", "baseline-anomaly": "Baseline anomaly", "model-assisted": "Model-assisted" };
export const DOMAINS = ["endpoint", "network", "identity-email"];
export const DOMAIN_LABEL = { endpoint: "Endpoint", network: "Network", "identity-email": "Identity and email" };
export const CELL_STATES = ["covered", "hunted", "gap", "quiet"];
export const STATE_LABEL = { covered: "Detection coverage", hunted: "Hunted, no detection", gap: "Exposed, no detection or hunt", quiet: "Nothing observed" };

// ---------------------------------------------------------------- URL state
export function parseHuntState(search) {
  const p = new URLSearchParams(String(search || "").replace(/^\?/, ""));
  const tab = p.get("tab") || "";
  return { tab, hunt: p.get("hunt") ? Number(p.get("hunt")) : null, type: HUNT_TYPES.includes(p.get("type")) ? p.get("type") : "", tactic: p.get("tactic") || "", q: (p.get("q") || "").slice(0, 80),
    technique: p.get("technique") || "", ready: p.get("ready") === "connected" ? "connected" : "" };
}
export function huntStateToSearch(s) {
  const p = new URLSearchParams();
  for (const k of ["tab", "type", "tactic", "q", "technique", "ready"]) if (s[k]) p.set(k, s[k]);
  if (s.hunt) p.set("hunt", String(s.hunt));
  const t = p.toString();
  return t ? `?${t}` : "";
}

// ---------------------------------------------------------------- suggested hunts board
export function filterSuggestions(list, { type = "", tactic = "", q = "", ready = "", technique = "" } = {}) {
  const needle = q.trim().toLowerCase();
  return list.filter((s) => {
    if (type && s.hunt_type !== type) return false;
    if (tactic && !(s.tactics || []).some((t) => t.toLowerCase() === tactic.toLowerCase())) return false;
    if (technique && !(s.techniques || []).some((t) => t.technique_id === technique)) return false;
    if (ready === "connected" && !(s.data_readiness && s.data_readiness.status === "connected")) return false;
    if (needle) {
      const hay = [s.title, s.hypothesis, ...(s.techniques || []).map((t) => `${t.technique_id} ${t.technique_name}`), ...((s.scope && s.scope.assets) || [])].join(" ").toLowerCase();
      if (!needle.split(/\s+/).every((w) => hay.includes(w))) return false;
    }
    return true;
  });
}
export function facetCounts(list) {
  const types = {}; const tactics = {};
  for (const s of list) {
    types[s.hunt_type] = (types[s.hunt_type] || 0) + 1;
    for (const t of s.tactics || []) tactics[t] = (tactics[t] || 0) + 1;
  }
  return { types, tactics };
}
// The "why this score" popover: each factor as a bar of its own maximum (a negative factor, such as effort, has max 0 and is drawn as a deduction).
export function scoreBars(priority) {
  const rows = (priority && priority.breakdown) || [];
  return rows.map((r) => {
    const max = Number(r.max) || 0; const pts = Number(r.points) || 0;
    return { factor: r.factor, points: pts, max, note: r.note || "", pct: max > 0 ? Math.max(0, Math.min(100, Math.round((pts / max) * 100))) : 0, negative: pts < 0 };
  });
}
export function scoreTone(score) { return score >= 70 ? "critical" : score >= 50 ? "warn" : score >= 30 ? "info" : "neutral"; }
export function readinessText(r) {
  if (!r) return { label: "Cannot tell", tone: "neutral", detail: "Quanta has no record of the data this hunt needs." };
  if (r.status === "connected") return { label: "Data connected", tone: "good", detail: r.note || "A connection proves the data is reachable." };
  return { label: "Cannot tell", tone: "neutral", detail: r.note || "Quanta cannot see whether your logs hold this data." };
}
export const SIEM_LANGS = [["spl", "SPL"], ["sigma", "Sigma"], ["kql", "KQL"]];
export function queryTabs(q) {
  const out = [];
  if (q && q.query) out.push({ id: "spl", label: "SPL", text: q.query });
  if (q && q.sigma) out.push({ id: "sigma", label: "Sigma", text: q.sigma });
  if (q && q.kql) out.push({ id: "kql", label: "KQL", text: q.kql });
  return out;
}

// ---------------------------------------------------------------- ATT&CK matrix
// payload is GET /api/hunting/attack-matrix. filters: state (one of CELL_STATES), tactic, q, observedOnly.
export function aggregateMatrix(payload, { state = "", tactic = "", q = "", observedOnly = false } = {}) {
  const needle = q.trim().toLowerCase();
  const all = (payload && payload.techniques) || [];
  const keep = all.filter((c) => (!state || c.state === state) && (!tactic || c.tactic === tactic) && (!observedOnly || c.exposure > 0)
    && (!needle || `${c.technique_id} ${c.name}`.toLowerCase().includes(needle)));
  const max = Math.max(1, ...all.map((c) => c.exposure || 0));
  const columns = ((payload && payload.tactics) || []).map((t) => {
    const cells = keep.filter((c) => c.tactic === t);
    const inCol = all.filter((c) => c.tactic === t);
    const observed = inCol.filter((c) => c.exposure > 0);
    return { tactic: t, cells, total: inCol.length, observed: observed.length, covered: observed.filter((c) => c.state === "covered").length,
      hunted: observed.filter((c) => c.state === "hunted").length, gaps: observed.filter((c) => c.state === "gap").length };
  }).filter((col) => col.cells.length || (!state && !needle && !observedOnly && !tactic));
  const t = (payload && payload.totals) || {};
  const pct = t.observed ? Math.round((100 * t.observed_covered) / t.observed) : null;
  return { columns, max, shown: keep.length, observedCoveragePct: pct, rulesRecorded: !!t.rules_recorded, totals: t };
}
export function heatLevel(exposure, max) {
  if (!exposure || exposure <= 0) return 0;
  const r = exposure / Math.max(1, max);
  return r > 0.75 ? 4 : r > 0.5 ? 3 : r > 0.25 ? 2 : 1;
}
export function cellTitle(c) {
  const parts = [`${c.technique_id} ${c.name}`, c.tactic];
  if (c.rules && c.rules.length) parts.push(`${c.rules.length} detection rule(s)`);
  else if (c.rules_disabled && c.rules_disabled.length) parts.push("only disabled rules");
  if (c.hunts && c.hunts.length) parts.push(`${c.hunts.length} hunt(s)`);
  if (c.findings) parts.push(`${c.findings} open finding(s)`);
  if (c.alerts) parts.push(`${c.alerts} alert(s)`);
  return parts.join(" - ");
}

// ---------------------------------------------------------------- hunt report
export function groupByDomain(trialHits) {
  const out = {};
  for (const d of DOMAINS) out[d] = [];
  for (const t of trialHits || []) (out[t.domain] || (out[t.domain] = [])).push(t);
  return out;
}
export function huntProgress(counts) {
  const total = (counts && counts.trial_hits) || 0;
  if (!total) return { total: 0, run: 0, pct: 0, label: "No trial hits yet" };
  const run = counts.run || 0;
  return { total, run, pct: Math.round((100 * run) / total), label: `${run} of ${total} run` };
}
export const STATUS_TONE = { "no-hit": "good", "needs-investigation": "warn", "not-run": "neutral" };
export const STATUS_TEXT = { "no-hit": "No hit", "needs-investigation": "Needs investigation", "not-run": "Not run" };
export function verdictTone(label) { return label === "confirmed" ? "critical" : label === "needs-investigation" ? "warn" : label === "no-ioc-match" ? "good" : "neutral"; }
export function verdictText(label) { return { confirmed: "Confirmed", "needs-investigation": "Needs investigation", "no-ioc-match": "No IOC match", "not-run": "Not run" }[label] || String(label || ""); }
export function timingText(t) {
  if (!t) return "";
  if (t.time_to_report_hours !== null && t.time_to_report_hours !== undefined) return `Report ready in ${t.time_to_report_hours} h (time box ${t.time_box_hours} h): ${String(t.state || "").replace("-", " ")}`;
  return `Time box ${t.time_box_hours} h, ${String(t.state || "open").replace("-", " ")}`;
}
export function recommendationTone(r) { return r === "promote" ? "good" : r === "assess-then-promote" || r === "consider" ? "warn" : "neutral"; }
