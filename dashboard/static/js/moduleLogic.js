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

export function filterRecords(list, q, getters) {
  const words = String(q || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return list;
  return list.filter((r) => { const h = getters.map((g) => String(g(r) ?? "")).join(" ").toLowerCase(); return words.every((w) => h.includes(w)); });
}
