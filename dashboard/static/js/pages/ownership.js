// Ownership Analytics: who - and which team - carries how much of the backlog, how much
// of it is breaching SLA, and how much belongs to nobody. Every number is a direct count
// over real findings and real assignment records (see
// remediation/assignments/analytics.py for the exact definitions); nothing is sampled
// or estimated. Non-admins see the same page scoped to their own team.
import { api } from "../api.js";
import { escapeHtml, kpiLink } from "../dom.js";
import { getCurrentUser } from "../auth.js";
import { barChartSvg, pieChartSvg, wireChartLinks } from "../charts.js";
import { openAssignModal } from "../assignModal.js";
import { openFindingById } from "../findingLookup.js";

export const title = "Ownership Analytics";

const n = (v) => (v ?? 0).toLocaleString();

function stackHtml(parts) {
  const total = parts.reduce((s, p) => s + p.value, 0);
  if (!total) return `<div class="stack stack-empty"></div>`;
  return `<div class="stack">${parts.filter((p) => p.value).map((p) => `
    <span class="stack-seg ${p.cls}" style="flex:${p.value}" data-tooltip="${escapeHtml(p.label)}: ${n(p.value)} (${Math.round((100 * p.value) / total)}%)"></span>`).join("")}</div>`;
}

const OWNER_PARTS = (b) => [
  { value: b.assigned, cls: "seg-assigned", label: "Assigned to a person" },
  { value: b.team_only, cls: "seg-team", label: "Team only" },
  { value: b.unowned, cls: "seg-unowned", label: "Unowned" },
];

const legendHtml = () => `
  <div class="stack-legend">
    <span><i class="seg-assigned"></i>Assigned to a person</span>
    <span><i class="seg-team"></i>Team only (no individual)</span>
    <span><i class="seg-unowned"></i>Unowned</span>
  </div>`;

function teamRow(t) {
  const pct = t.open ? Math.round((100 * t.assigned) / t.open) : 0;
  const href = `/assignments?view=all&team=${encodeURIComponent(t.name)}`;
  return `
    <tr>
      <td>${t.name === "(no team)" ? `<span class="muted">(no team)</span>` : `<a href="${href}" data-link>${escapeHtml(t.name)}</a>`}
        ${t.explicit === false && t.name !== "(no team)" ? `<span class="badge badge-outline muted" data-tooltip="Exists only as a name on users/assets - formalize it under Users &amp; Teams">implied</span>` : ""}</td>
      <td>${t.manager_email ? escapeHtml(t.manager_email) : `<span class="muted">-</span>`}</td>
      <td>${n(t.members)}</td>
      <td><strong>${n(t.open)}</strong></td>
      <td>${n(t.critical)}</td><td>${n(t.high)}</td>
      <td>${t.breached ? `<span class="badge badge-critical">${n(t.breached)}</span>` : "0"}</td>
      <td>${t.at_risk ? `<span class="badge badge-medium">${n(t.at_risk)}</span>` : "0"}</td>
      <td>${n(t.in_progress)}</td><td>${n(t.blocked)}</td>
      <td class="own-cell">${stackHtml(OWNER_PARTS(t))}<span class="own-pct">${pct}% person-assigned</span></td>
    </tr>`;
}

function userRow(u, maxOpen) {
  return `
    <tr>
      <td>${escapeHtml(u.name || u.email)}<div class="muted assign-sub">${escapeHtml(u.email)}</div></td>
      <td>${u.team ? escapeHtml(u.team) : `<span class="muted">-</span>`}</td>
      <td><strong>${n(u.open)}</strong>
        <div class="load-track"><div class="load-fill" style="width:${maxOpen ? Math.round((100 * u.open) / maxOpen) : 0}%"></div></div></td>
      <td>${n(u.critical)}</td><td>${n(u.high)}</td>
      <td>${u.breached ? `<span class="badge badge-critical">${n(u.breached)}</span>` : "0"}</td>
      <td>${u.at_risk ? `<span class="badge badge-medium">${n(u.at_risk)}</span>` : "0"}</td>
      <td>${n(u.in_progress)}</td><td>${n(u.blocked)}</td><td>${n(u.resolved)}</td>
      <td>${u.oldest_open_days == null ? `<span class="muted">-</span>` : `${n(u.oldest_open_days)}d`}</td>
    </tr>`;
}

export async function render(container) {
  const me = await getCurrentUser(true);
  if (!me) {
    window.history.pushState({}, "", "/login?redirect=/ownership");
    window.dispatchEvent(new PopStateEvent("popstate"));
    return;
  }
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const d = await api.ownershipAnalytics();
  const t = d.totals;
  const scopeNote = me.role !== "admin" && me.team
    ? `<div class="callout">Scoped to your team, <strong>${escapeHtml(me.team)}</strong>. An admin sees the whole organisation.</div>` : "";

  if (!t.open && !t.resolved) {
    container.innerHTML = `${scopeNote}<div class="empty-state">No findings in scope yet - ownership analytics appear once findings are ingested.</div>`;
    return;
  }

  const users = d.by_user;
  const maxOpen = Math.max(0, ...users.map((u) => u.open));
  const idle = users.filter((u) => u.open === 0 && u.role !== "admin");
  const busiest = users.find((u) => u.open > 0);

  const ageingRows = d.ageing.map((b) => `
    <tr><td>${escapeHtml(b.bucket)}</td>
        <td class="own-cell">${stackHtml(OWNER_PARTS(b))}</td>
        <td>${n(b.assigned + b.team_only + b.unowned)}</td></tr>`).join("");

  const statusData = [
    { label: "Open", value: d.status_counts.open, color: "#6d97f7" },
    { label: "In progress", value: d.status_counts.in_progress, color: "#34d399" },
    { label: "Blocked", value: d.status_counts.blocked, color: "#f59e0b" },
    { label: "Resolved", value: d.status_counts.resolved, color: "#94a3b8" },
  ].filter((x) => x.value);

  const teamBars = d.by_team.filter((x) => x.open).slice(0, 8).map((x) => ({
    label: x.name, value: x.open,
    detail: `${n(x.breached)} breaching SLA, ${n(x.unowned + x.team_only)} without an individual owner`,
    href: x.name === "(no team)" ? "/assignments?view=unowned" : `/assignments?view=all&team=${encodeURIComponent(x.name)}`,
  }));
  const userBars = users.filter((u) => u.open).slice(0, 8).map((u) => ({
    label: (u.name || u.email).split(" ")[0], value: u.open,
    detail: `${n(u.critical)} critical, ${n(u.breached)} breaching SLA`,
  }));

  container.innerHTML = `
    ${scopeNote}
    <p class="subtitle">
      Where the backlog actually sits. A finding is <strong>assigned</strong> when a person owns it,
      <strong>team-only</strong> when a team owns it (by assignment, or because the team owns its asset)
      but nobody has picked it up, and <strong>unowned</strong> when neither is true. Resolved items
      leave the live workload until the next scan confirms the fix.
    </p>

    <div class="kpi-grid">
      ${kpiLink("/assignments?view=all", n(t.open), "Open findings in scope")}
      ${kpiLink("/assignments?view=mine", `${n(t.assigned)} <span class="kpi-sub">${t.assigned_pct}%</span>`, "Assigned to a person", "kpi-good")}
      ${kpiLink("/assignments?view=needs_owner", n(t.team_only), "Team-only, no individual", t.team_only ? "kpi-warn" : "")}
      ${kpiLink("/assignments?view=unowned", n(t.unowned), "Unowned - no person, no team", t.unowned ? "kpi-danger" : "kpi-good")}
      ${kpiLink("/assignments?view=unowned&priority=Critical", n(d.unowned_urgent_total), "Critical/High with no owner", d.unowned_urgent_total ? "kpi-danger" : "kpi-good")}
      ${kpiLink("/assignments?view=all", n(t.breached), "Open and breaching SLA", t.breached ? "kpi-danger" : "kpi-good")}
    </div>

    <div class="chart-block own-coverage">
      <h3>Ownership coverage</h3>
      ${stackHtml(OWNER_PARTS(t))}
      ${legendHtml()}
      <p class="filter-count" style="margin:8px 0 0">
        ${t.owned_pct}% of open findings have at least a team owner; ${t.assigned_pct}% have a named person.
        ${t.unowned ? `<strong>${n(t.unowned)}</strong> belong to no one - run <em>Auto-route</em> on the Assignments page to send them to their asset owners' teams.` : "Every open finding has an owner."}
      </p>
    </div>

    <div class="chart-row">
      <div class="chart-block"><h3>Open findings by team</h3>${teamBars.length ? barChartSvg(teamBars, { width: 420, height: 210 }) : `<p class="muted">No open work.</p>`}</div>
      <div class="chart-block"><h3>Open findings by person</h3>${userBars.length ? barChartSvg(userBars, { width: 420, height: 210, barColor: "#6d97f7" }) : `<p class="muted">Nothing is assigned to a person yet.</p>`}</div>
      <div class="chart-block"><h3>Work status</h3>${statusData.length ? pieChartSvg(statusData) : `<p class="muted">-</p>`}</div>
    </div>

    <div class="chart-block">
      <h3>Ageing by ownership <span class="muted" style="font-weight:400">(days since first seen, open work)</span></h3>
      <table class="data-table ageing-table"><thead><tr><th>Age</th><th>Who owns it</th><th>Findings</th></tr></thead><tbody>${ageingRows}</tbody></table>
      ${legendHtml()}
    </div>

    <h2 style="margin-top:28px">By team</h2>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Team</th><th>Manager</th><th>Members</th><th>Open</th><th>Critical</th><th>High</th>
          <th>Breached</th><th>At risk</th><th>In progress</th><th>Blocked</th><th>Ownership</th></tr></thead>
        <tbody>${d.by_team.map(teamRow).join("")}</tbody>
      </table>
    </div>

    <h2 style="margin-top:28px">By person</h2>
    ${busiest ? `<p class="filter-count" style="margin:-4px 0 8px">
      ${escapeHtml(busiest.name || busiest.email)} carries the most open work (${n(busiest.open)})${idle.length
        ? `; ${n(idle.length)} ${idle.length === 1 ? "person has" : "people have"} none - a candidate pool for rebalancing.` : "."}</p>` : ""}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Person</th><th>Team</th><th>Open</th><th>Critical</th><th>High</th><th>Breached</th>
          <th>At risk</th><th>In progress</th><th>Blocked</th><th>Resolved</th><th>Oldest open</th></tr></thead>
        <tbody>${users.length ? users.map((u) => userRow(u, maxOpen)).join("") : `<tr><td colspan="11" class="empty-state">No users.</td></tr>`}</tbody>
      </table>
    </div>

    <h2 style="margin-top:28px">Most urgent findings with no owner
      <span class="muted" style="font-weight:400">(${n(d.unowned_urgent_total)} Critical/High)</span></h2>
    ${d.unowned_urgent.length ? `
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Priority</th><th>Finding</th><th>Asset</th><th>SLA</th><th></th></tr></thead>
        <tbody>${d.unowned_urgent.map((f) => `
          <tr>
            <td><span class="badge badge-priority-${escapeHtml((f.priority || "").toLowerCase())}">${escapeHtml(f.priority)}</span></td>
            <td><button type="button" class="link-button" data-open="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button>
              <div class="assign-finding-title" title="${escapeHtml(f.title)}">${escapeHtml(f.title)}</div></td>
            <td>${escapeHtml(f.asset)}</td>
            <td>${f.breached ? `<span class="badge badge-critical">Breached</span>` : `<span class="muted">${escapeHtml(f.due_date || "-")}</span>`}</td>
            <td><button type="button" class="secondary-button compact" data-assign="${escapeHtml(f.id)}">Assign</button></td>
          </tr>`).join("")}</tbody>
      </table>
    </div>` : `<div class="callout">No Critical or High finding is without an owner.</div>`}`;

  wireChartLinks(container);
  const rows = new Map(d.unowned_urgent.map((f) => [f.id, f]));
  if (container._ownClick) container.removeEventListener("click", container._ownClick);
  container._ownClick = (e) => {
    const open = e.target.closest("[data-open]");
    if (open) return openFindingById(open.dataset.open);
    const assign = e.target.closest("[data-assign]");
    if (assign) {
      return openAssignModal({
        findingId: assign.dataset.assign, title: (rows.get(assign.dataset.assign) || {}).title,
        onSaved: () => render(container),
      });
    }
  };
  container.addEventListener("click", container._ownClick);
}
