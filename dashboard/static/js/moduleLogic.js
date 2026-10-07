// Pure logic shared by the rebuilt module pages beyond the queue: assignment board rules, approval stages and rules, exception states and validation,
// trend/score maths. No DOM, no network: tested under Node (tests/test_modules_ui_js.py).

// ---------------------------------------------------------------- assignments (module 6)
export const ASSIGN_STATUSES = ["unassigned", "open", "in_progress", "blocked", "resolved"];
export const ASSIGN_LABELS = { unassigned: "Unassigned", open: "Open", in_progress: "In progress", blocked: "Blocked", resolved: "Resolved" };

export const assignStatusOf = (row) => (row.assignment && row.assignment.status) || "unassigned";

export function groupByStatus(rows) {
  const out = Object.fromEntries(ASSIGN_STATUSES.map((s) => [s, []]));
  for (const r of rows) out[assignStatusOf(r)].push(r);
  return out;
}

// What dropping a card in another column means. `me` = { email, role }. The server is the authority; this only offers moves it will accept and says why not.
export function planAssignmentMove(row, toStatus, me) {
  const from = assignStatusOf(row);
  if (!ASSIGN_STATUSES.includes(toStatus)) return { ok: false, reason: "Unknown column." };
  if (from === toStatus) return { ok: false, same: true, reason: "" };
  const email = String((me && me.email) || "").toLowerCase();
  const isAdmin = !!me && me.role === "admin";
  if (toStatus === "unassigned") return { ok: false, reason: isAdmin ? "Use Remove assignment in the card menu: it is recorded as a different action." : "Only an administrator can remove an assignment." };
  if (from === "unassigned") {
    if (!email) return { ok: false, reason: "Sign in to take work." };
    return { ok: true, action: "take", then: toStatus === "open" ? null : toStatus, needs: toStatus === "blocked" ? "note" : null, note: "Assigns it to you first." };
  }
  const assignee = String((row.assignment && row.assignment.assignee_email) || "").toLowerCase();
  if (!isAdmin && assignee !== email) return { ok: false, reason: "Only the assignee or an administrator can change the status." };
  return { ok: true, action: "status", status: toStatus, needs: toStatus === "blocked" ? "note" : null, note: toStatus === "resolved" ? "The finding leaves the queue only when the next scan stops seeing it." : "" };
}

export function assignmentKpis(rows) {
  const g = groupByStatus(rows);
  let breached = 0; let atRisk = 0;
  for (const r of rows) {
    if (assignStatusOf(r) === "resolved") continue;
    const s = r.sla;
    if (s && s.breached) breached += 1; else if (s && s.days_remaining !== null && s.days_remaining !== undefined && s.days_remaining <= 3) atRisk += 1;
  }
  return { total: rows.length, unassigned: g.unassigned.length, open: g.open.length, inProgress: g.in_progress.length, blocked: g.blocked.length, resolved: g.resolved.length, breached, atRisk };
}

export function assignAgeDays(firstSeen, now = Date.now()) {
  const t = new Date(`${String(firstSeen || "").slice(0, 10)}T00:00:00`).getTime();
  return Number.isNaN(t) ? null : Math.max(0, Math.round((now - t) / 86400000));
}

// A short human label for an SLA clock: tone drives the colour, the text always carries the meaning.
export function slaClock(sla) {
  if (!sla || !sla.due_date) return { text: "No SLA date", tone: "none" };
  if (sla.breached) { const d = Math.abs(sla.days_remaining ?? 0); return { text: `Breached ${d}d ago`, tone: "bad" }; }
  if (sla.days_remaining !== null && sla.days_remaining !== undefined && sla.days_remaining <= 3) return { text: sla.days_remaining <= 0 ? "Due today" : `Due in ${sla.days_remaining}d`, tone: "warn" };
  return { text: `Due ${sla.due_date}`, tone: "good" };
}

// ---------------------------------------------------------------- approvals (module 6)
export const APPROVAL_STEPS = ["requested", "staging", "decision", "triggered", "verified"];

// Where an approval is in its life: each step is done / current / skipped / pending, with the actor and date from the stored record.
export function approvalTimeline(a) {
  const status = a.computed_status || a.status;
  const rejected = status === "rejected";
  const steps = [
    { id: "requested", label: "Requested", state: "done", who: a.requested_by, when: a.created_on },
    { id: "staging", label: "Staging validated", state: a.staging_validated_by ? "done" : "pending", who: a.staging_validated_by || null, when: a.staging_validated_at || null, optional: true },
    { id: "decision", label: rejected ? "Rejected" : "Approved", state: rejected || a.approved_by ? "done" : status === "expired" ? "skipped" : "current", who: rejected ? a.rejected_by : a.approved_by, when: rejected ? a.rejected_at : a.approved_at, note: rejected ? a.rejection_reason : null },
  ];
  if (!rejected) {
    steps.push({ id: "triggered", label: "Remediation triggered", state: a.triggered_at ? "done" : a.approved_by ? "current" : "pending", who: a.triggered_by || null, when: a.triggered_at || null });
    const v = a.verification && a.verification.state;
    steps.push({ id: "verified", label: v === "still-present" ? "Still present after fix" : "Verified fixed", state: v === "verified" ? "done" : v === "still-present" ? "failed" : a.triggered_at ? "current" : "pending", who: null, when: null, note: a.verification && v !== "not-triggered" ? a.verification.detail : null });
  }
  return steps;
}

export function approvalBucket(a) {
  const s = a.computed_status || a.status;
  if (s === "pending") return "pending";
  if (s === "approved" || s === "remediation_triggered") return "approved";
  return "closed"; // rejected, expired
}

export function approvalKpis(approvals, metrics) {
  const b = { pending: 0, approved: 0, triggered: 0, rejected: 0, expired: 0, lintFailed: 0, stillPresent: 0 };
  for (const a of approvals) {
    const s = a.computed_status || a.status;
    if (s === "pending") b.pending += 1; else if (s === "approved") b.approved += 1; else if (s === "remediation_triggered") b.triggered += 1; else if (s === "rejected") b.rejected += 1; else if (s === "expired") b.expired += 1;
    if (s === "pending" && a.playbook_lint && !a.playbook_lint.passed) b.lintFailed += 1;
    if (a.verification && a.verification.state === "still-present") b.stillPresent += 1;
  }
  return { ...b, avgDaysToApproval: metrics ? metrics.avg_days_request_to_approval : null, fixHoldRate: metrics ? metrics.fix_hold_rate : null };
}

// Can this person approve it? Mirrors the server's own refusals so the button explains itself; the server still decides.
export function canApprove(a, me) {
  const s = a.computed_status || a.status;
  if (s !== "pending") return { ok: false, reason: `It is ${String(s).replace("_", " ")}, not waiting for a decision.` };
  if (!me || me.role !== "admin") return { ok: false, reason: "Only an administrator can approve." };
  if (String(a.requested_by || "").toLowerCase() === String(me.email || "").toLowerCase()) return { ok: false, reason: "Separation of duties: you requested this change, so a different administrator must approve it." };
  if (a.playbook_lint && !a.playbook_lint.passed) return { ok: false, reason: `The playbook failed the safety lint (${a.playbook_lint.errors} error${a.playbook_lint.errors === 1 ? "" : "s"}). It cannot be approved until it is regenerated.` };
  return { ok: true, reason: "" };
}
export function canReject(a, me) {
  const s = a.computed_status || a.status;
  if (s !== "pending") return { ok: false, reason: `It is ${String(s).replace("_", " ")}.` };
  if (!me || me.role !== "admin") return { ok: false, reason: "Only an administrator can reject." };
  return { ok: true, reason: "" };
}
export function validateReason(text, min = 8) {
  const t = String(text || "").trim();
  return t.length >= min ? "" : `Write a reason of at least ${min} characters.`;
}
// Findings that need an approval request: normal or emergency change type with no request yet. Highest priority first.
export function needsApproval(findings, approvals) {
  const have = new Set(approvals.map((a) => a.finding_id));
  const rank = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  return findings.filter((f) => ["normal", "emergency"].includes((f.remediation_policy || {}).change_type) && !have.has(f.id)).sort((a, b) => (rank[a.priority] ?? 9) - (rank[b.priority] ?? 9) || String(a.id).localeCompare(String(b.id), undefined, { numeric: true }));
}
// Days until a scheduled window (negative = passed).
export function windowDays(w, now = new Date()) {
  if (!w || !w.date) return null;
  const t = new Date(`${w.date}T00:00:00`).getTime();
  if (Number.isNaN(t)) return null;
  return Math.round((t - new Date(now.toDateString()).getTime()) / 86400000);
}

// ---------------------------------------------------------------- exceptions (module 6)
export const EXPIRING_SOON_DAYS = 14;
export function daysUntil(dateStr, now = new Date()) {
  const t = new Date(`${dateStr}T00:00:00`).getTime();
  if (Number.isNaN(t)) return null;
  return Math.round((t - new Date(now.toDateString()).getTime()) / 86400000);
}
export function exceptionState(e, now = new Date()) {
  const status = e.computed_status || e.status;
  if (status !== "active") return { key: status, label: status === "revoked" ? "Revoked" : "Expired", tone: "none", days: null };
  const d = daysUntil(e.expires_on, now);
  if (d === null) return { key: "active", label: "Active", tone: "good", days: null };
  if (d <= EXPIRING_SOON_DAYS) return { key: "expiring", label: d <= 0 ? "Expires today" : `${d}d left`, tone: "warn", days: d };
  return { key: "active", label: `${d}d left`, tone: "good", days: d };
}
export function exceptionKpis(exceptions, now = new Date()) {
  const k = { active: 0, expiring: 0, expired: 0, revoked: 0, total: exceptions.length };
  for (const e of exceptions) { const s = exceptionState(e, now).key; if (s === "expiring") { k.expiring += 1; k.active += 1; } else if (s === "active") k.active += 1; else if (s === "expired") k.expired += 1; else if (s === "revoked") k.revoked += 1; }
  return k;
}
export const MAX_EXCEPTION_DAYS = 365;
// Mirrors the server's checks (store.create_exception + the route): returns the first problem, or "".
export function validateException({ finding_id, reason, requested_by, approved_by, expires_on }, now = new Date()) {
  if (!finding_id) return "Choose the finding.";
  if (String(reason || "").trim().length < 10) return "Write a reason of at least 10 characters: why the risk is accepted and what limits it.";
  if (!/^\d{4}-\d\d-\d\d$/.test(String(expires_on || ""))) return "Pick an expiry date.";
  const d = daysUntil(expires_on, now);
  if (d === null) return "Pick a valid expiry date.";
  if (d <= 0) return "The expiry must be a future date.";
  if (d > MAX_EXCEPTION_DAYS) return `The expiry cannot be more than ${MAX_EXCEPTION_DAYS} days ahead.`;
  if (!approved_by) return "Choose who approves it.";
  if (String(approved_by).toLowerCase() === String(requested_by || "").toLowerCase()) return "Separation of duties: the approver must be a different person from the requester.";
  return "";
}
export function addDaysIso(days, now = new Date()) {
  const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() + Number(days));
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}
// ---------------------------------------------------------------- assignments: filter state in the URL
export const ASSIGN_VIEWS = ["mine", "team", "needs_owner", "unowned", "all"];
export function parseAssignState(search) {
  const p = new URLSearchParams(search || "");
  const view = p.get("view");
  const status = p.get("status") || "";
  return {
    view: ASSIGN_VIEWS.includes(view) ? view : "mine", explicitView: ASSIGN_VIEWS.includes(view),
    team: p.get("team") || "", priority: ["Critical", "High", "Medium", "Low"].includes(p.get("priority")) ? p.get("priority") : "",
    status: ASSIGN_STATUSES.includes(status) ? status : "", includeResolved: p.get("include_resolved") === "true", q: p.get("q") || "",
    mode: p.get("mode") === "table" ? "table" : "board",
  };
}
export function assignStateToSearch(s) {
  const q = new URLSearchParams();
  if (s.view !== "mine") q.set("view", s.view);
  for (const k of ["team", "priority", "status", "q"]) if (s[k]) q.set(k, s[k]);
  if (s.includeResolved) q.set("include_resolved", "true");
  if (s.mode === "table") q.set("mode", "table");
  const t = q.toString();
  return t ? `?${t}` : "";
}

// ---------------------------------------------------------------- posture review (module 7)
// The exact text to put where a recommendation says to change something, by kind of change. A page or a process step has no setting to paste,
// so it returns an empty string and the page offers a link instead.
export function settingText(change) {
  if (!change) return "";
  const v = change.value;
  const val = Array.isArray(v) || (v && typeof v === "object") ? JSON.stringify(v) : String(v ?? "");
  if (change.kind === "env") return `${change.key}=${val}`;
  if (change.kind === "helm") return `--set ${change.key}=${val}`;
  if (change.kind === "yaml") return `# ${change.where}\n${change.key}: ${val}`;
  return "";
}
export const POSTURE_KIND_LABEL = { env: "Environment variable", yaml: "Config file", helm: "Helm value", page: "Quanta page", process: "Process" };
export function actionsMarkdown(actions, generated = "") {
  const lines = [`# Security posture actions${generated ? ` (${generated})` : ""}`, ""];
  actions.forEach((a, i) => {
    lines.push(`${i + 1}. **${a.title}** (${a.framework_title}, ${a.status === "fail" ? "gap" : a.status})`);
    if (a.evidence && a.evidence[0]) lines.push(`   - Recorded: ${a.evidence[0]}`);
    if (a.recommendation) lines.push(`   - Do: ${a.recommendation}`);
    const s = settingText(a.change);
    if (s) lines.push("   - Setting:", "     ```", ...s.split("\n").map((l) => `     ${l}`), "     ```");
    else if (a.change) lines.push(`   - Where: ${a.change.where} > ${a.change.key} (${a.change.value})`);
  });
  return lines.join("\n");
}
// Trend kept in this browser only (the server keeps no history): one reading per 5 minutes, 24 kept. Honest: it needs two readings to say anything.
export const READING_GAP_MS = 5 * 60 * 1000;
export function pushReading(history, reading, now = Date.now()) {
  const list = Array.isArray(history) ? history.filter((r) => r && Number.isFinite(r.t)) : [];
  const last = list[list.length - 1];
  if (last && now - last.t < READING_GAP_MS) return list;
  return [...list, { ...reading, t: now }].slice(-24);
}
// values of one measure across the history (null where a reading had none), the latest, and the one before it
export function readingSeries(history, getter) {
  const vals = (history || []).map((r) => { const v = getter(r); return typeof v === "number" ? v : null; });
  const real = vals.filter((v) => v !== null);
  return { values: real, current: real.length ? real[real.length - 1] : null, previous: real.length > 1 ? real[real.length - 2] : null };
}
export function scoreTone(score) { return score === null || score === undefined ? "none" : score >= 70 ? "good" : score >= 40 ? "warn" : "bad"; }
export function postureTotals(frameworks) {
  const t = { pass: 0, partial: 0, fail: 0, unknown: 0, na: 0 };
  for (const f of frameworks) for (const k of Object.keys(t)) t[k] += (f.counts && f.counts[k]) || 0;
  return t;
}
export function filterChecks(checks, filter, q = "") {
  const words = String(q || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  return checks.filter((c) => (filter === "all" || c.status === filter || (filter === "gaps" && (c.status === "fail" || c.status === "partial")))
    && (!words.length || words.every((w) => `${c.title} ${c.detail || ""} ${c.recommendation || ""}`.toLowerCase().includes(w))));
}

// ---------------------------------------------------------------- risk and compliance (module 7)
// A 5x5 likelihood-by-impact grid of risk counts. rows[0] is impact 5 (top); cell = { likelihood, impact, count, ids }.
export function riskGrid(risks, key = "inherent") {
  const cells = {};
  for (let imp = 5; imp >= 1; imp -= 1) for (let lik = 1; lik <= 5; lik += 1) cells[`${lik}:${imp}`] = { likelihood: lik, impact: imp, count: 0, ids: [] };
  for (const r of risks) {
    const lik = Number(r[`${key}_likelihood`]); const imp = Number(r[`${key}_impact`]);
    const c = cells[`${lik}:${imp}`];
    if (c) { c.count += 1; c.ids.push(r.id); }
  }
  const rows = [];
  for (let imp = 5; imp >= 1; imp -= 1) rows.push(Array.from({ length: 5 }, (_, i) => cells[`${i + 1}:${imp}`]));
  return rows;
}
// severity of a grid cell from its likelihood x impact product, using the same bands as the register (Low <5, Medium <10, High <15, Critical 15+)
export function gridLevel(likelihood, impact) { const s = likelihood * impact; return s >= 15 ? "Critical" : s >= 10 ? "High" : s >= 5 ? "Medium" : "Low"; }
export function resultCounts(tests) {
  const c = { pass: 0, fail: 0, warn: 0, na: 0, error: 0 };
  for (const t of tests) if (t.result in c) c[t.result] += 1;
  return c;
}
export function filterByResult(items, result, getResult = (x) => x.result) { return result === "all" ? items : items.filter((x) => getResult(x) === result); }
// A control's best status for sorting: not-satisfied first (what needs work), then partly, then no evidence, then satisfied.
export const CONTROL_STATUS_ORDER = ["not-satisfied", "partially", "no-evidence", "not-evidenced", "satisfied"];
export function sortControls(controls) { return controls.slice().sort((a, b) => CONTROL_STATUS_ORDER.indexOf(a.status) - CONTROL_STATUS_ORDER.indexOf(b.status) || String(a.control_id).localeCompare(String(b.control_id), undefined, { numeric: true })); }
export function frameworkBar(counts) {
  return [{ label: "Satisfied", value: counts.satisfied || 0, key: "good" }, { label: "Partly", value: counts.partially || 0, key: "warn" }, { label: "Not satisfied", value: counts["not-satisfied"] || 0, key: "bad" },
    { label: "No usable evidence", value: counts["no-evidence"] || 0, key: "none" }, { label: "Not observed by Quanta", value: counts["not-evidenced"] || 0, key: "dim" }];
}

// ---------------------------------------------------------------- application security and release gates (modules 2 and 3)
export const PR_LANES = ["proposed", "approved", "open", "merged", "verified", "stopped"];
export const PR_LANE_LABEL = { proposed: "Proposed", approved: "Approved", open: "Pull request open", merged: "Merged", verified: "Verified by a scan", stopped: "Stopped or failed" };
export function prLane(p) {
  switch (p.status) {
    case "draft": return "proposed";
    case "approved": return "approved";
    case "pr-opened": case "in-review": return "open";
    case "merged": return p.verified_state === "verified" ? "verified" : "merged";
    default: return "stopped"; // failed, closed, discarded
  }
}
export function prGroups(proposals) {
  const g = Object.fromEntries(PR_LANES.map((l) => [l, []]));
  for (const p of proposals) g[prLane(p)].push(p);
  return g;
}
// What needs a person's attention on a proposal, as short reasons (empty when nothing does).
export function prAttention(p) {
  const out = [];
  if (p.status === "failed") out.push("Opening it failed");
  if (p.checks_state === "failing" || p.checks_state === "failure") out.push("Checks are failing");
  if (p.status === "merged" && p.verified_state === "still-present") out.push("Merged, but the finding is still reported");
  if ((p.status === "pr-opened" || p.status === "in-review") && (p.review_state === "changes_requested" || p.review_state === "changes-requested")) out.push("Changes were requested");
  return out;
}
export function prKpis(proposals) {
  const g = prGroups(proposals);
  return { total: proposals.length, proposed: g.proposed.length, approved: g.approved.length, open: g.open.length, merged: g.merged.length, verified: g.verified.length, stopped: g.stopped.length, attention: proposals.filter((p) => prAttention(p).length).length };
}
// Which actions make sense for a proposal, and who may take them (the server stays the authority).
export function prActions(p, admin) {
  if (!admin) return [];
  const a = [];
  if (p.status === "draft") a.push("approve");
  if (p.status === "approved" || p.status === "failed") a.push("preview");
  if (["draft", "approved", "failed"].includes(p.status)) a.push("discard");
  if (["pr-opened", "in-review"].includes(p.status)) a.push("sync");
  return a;
}
// Gate history: share of evaluations by decision, the latest decision per application, and a run of the most recent decisions for a strip.
export function gateStats(history) {
  const c = { pass: 0, warn: 0, fail: 0 };
  for (const h of history) if (h.decision in c) c[h.decision] += 1;
  const n = c.pass + c.warn + c.fail;
  const latest = new Map();
  for (const h of history) { const cur = latest.get(h.application); if (!cur || String(h.evaluated_at) > String(cur.evaluated_at)) latest.set(h.application, h); }
  return { n, ...c, passRate: n ? Math.round((c.pass / n) * 100) : null, latest: [...latest.values()].sort((a, b) => String(b.evaluated_at).localeCompare(String(a.evaluated_at))) };
}
export function groupByDay(items, getTs) {
  const m = new Map();
  for (const it of items) { const day = String(getTs(it) || "").slice(0, 10) || "unknown"; if (!m.has(day)) m.set(day, []); m.get(day).push(it); }
  return [...m.entries()].sort((a, b) => b[0].localeCompare(a[0])).map(([day, list]) => ({ day, items: list }));
}

// ---------------------------------------------------------------- infrastructure and exposure (module 4)
export function assetFacets(assets) {
  const kinds = {}; let owned = 0; let unowned = 0;
  for (const a of assets) { kinds[a.kind] = (kinds[a.kind] || 0) + 1; if (a.owner || a.team) owned += 1; else unowned += 1; }
  return { kinds, owned, unowned };
}
// The exposure map's rows from /api/attack-surface/summary: widest layer first, bars scaled to the biggest layer, risky services flagged on the services row.
export function exposureLevels(summary) {
  const k = summary.assets.by_kind;
  const rows = [
    { kind: "domain", label: "Domains and subdomains", count: (k.domain || 0) + (k.subdomain || 0), flag: "" },
    { kind: "ip", label: "Addresses", count: k.ip || 0, flag: "" },
    { kind: "service", label: "Services", count: k.service || 0, flag: summary.exposed_risky_services ? `${summary.exposed_risky_services} risky exposed` : "", flagCount: summary.exposed_risky_services || 0 },
    { kind: "url", label: "Web endpoints", count: k.url || 0, flag: "" },
  ];
  const max = Math.max(1, ...rows.map((r) => r.count));
  return rows.map((r) => ({ ...r, width: Math.round((r.count / max) * 100), flagWidth: r.flagCount ? Math.max(2, Math.round((Math.min(r.flagCount, r.count) / max) * 100)) : 0 }));
}
export const changeTone = (c) => ({ new: "warn", reappeared: "warn", changed: "info", disappeared: "good" }[c] || "neutral");

// ---------------------------------------------------------------- administration (module 8)
// One word for how a connection is doing, from what the server recorded. "stale" = enabled and scheduled, but its last success is older than twice its schedule
// (a leader tick that stopped, or a source that keeps failing quietly).
export function connectionHealth(c, now = Date.now()) {
  if (!c.enabled) return "disabled";
  if (c.last_status === "running") return "running";
  if (c.last_status === "error") return "failing";
  if (!c.last_status || !c.last_run_at) return "never";
  const t = Date.parse(c.last_run_at);
  if (c.schedule_minutes > 0 && Number.isFinite(t) && now - t > c.schedule_minutes * 60000 * 2) return "stale";
  return "ok";
}
export function nextRun(c, now = Date.now()) {
  if (!c.enabled || !c.schedule_minutes) return { label: c.enabled ? "Manual only" : "Disabled", overdue: false, at: null };
  const t = Date.parse(c.last_run_at || "");
  if (!Number.isFinite(t)) return { label: "Due on the next scheduler tick", overdue: true, at: null };
  const at = t + c.schedule_minutes * 60000;
  return { label: at <= now ? "Overdue: due on the next scheduler tick" : `About ${new Date(at).toISOString().slice(11, 16)} UTC`, overdue: at <= now, at };
}
export function connectionKpis(connections, now = Date.now()) {
  const k = { total: connections.length, ok: 0, failing: 0, stale: 0, never: 0, disabled: 0, running: 0, simulated: 0 };
  for (const c of connections) { k[connectionHealth(c, now)] += 1; if (c.mode === "simulation") k.simulated += 1; }
  return k;
}
export const HEALTH_LABEL = { ok: "Healthy", failing: "Failing", stale: "Not syncing", never: "Never run", disabled: "Disabled", running: "Syncing" };
export const HEALTH_TONE = { ok: "good", failing: "critical", stale: "warn", never: "neutral", disabled: "neutral", running: "info" };
// Activity log: a live tail keeps the newest N entries, merging new ones in by id and keeping order; returns the ids that are new.
export function mergeTail(current, incoming, max = 500) {
  const seen = new Set(current.map((e) => e.id));
  const fresh = incoming.filter((e) => !seen.has(e.id));
  const merged = [...fresh, ...current].sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)) || Number(b.id) - Number(a.id)).slice(0, max);
  return { list: merged, freshIds: new Set(fresh.map((e) => e.id)) };
}
export function activityFilter(entries, { q = "", action = "", actor = "" } = {}) {
  const words = String(q).trim().toLowerCase().split(/\s+/).filter(Boolean);
  return entries.filter((e) => (!action || e.action === action || String(e.action).startsWith(`${action}.`)) && (!actor || e.actor === actor)
    && (!words.length || words.every((w) => `${e.action} ${e.actor} ${e.target || ""} ${JSON.stringify(e.details || {})}`.toLowerCase().includes(w))));
}
export function activityGroups(entries) {
  const m = new Map();
  for (const e of entries) { const a = String(e.action).split(".")[0]; m.set(a, (m.get(a) || 0) + 1); }
  return [...m.entries()].map(([group, count]) => ({ group, count })).sort((a, b) => b.count - a.count || a.group.localeCompare(b.group));
}

export function filterRecords(list, q, getters) {
  const words = String(q || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return list;
  return list.filter((r) => { const h = getters.map((g) => String(g(r) ?? "")).join(" ").toLowerCase(); return words.every((w) => h.includes(w)); });
}
