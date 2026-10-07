// One incident, as the already-investigated report an analyst opens: verdict, summary, history, entities, ATT&CK, attack flow, timeline, root cause, IOCs, tool actions, actions,
// references, follow-ups. Drawing only; the report itself is assembled by the server from stored data (docs/INVESTIGATION_REPORTS.md).
import { api } from "./api.js";
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";
import { chip, severityChip, toast, onCleanup, tipAttr } from "./ui.js";
import { slaRing, attackFlowLayout, filterTimeline, timelineIcon, evidenceMarks, verdictText, verdictTone, confidenceText, STATUS_LABEL, VERDICTS, killChainDots } from "./socLogic.js";
import { modal, popMenu, avatar, ringSvg, copyText, downloadText, fmtWhen, relTime } from "./sxKit.js";

const SEV_VAR = { Critical: "var(--sx-crit)", High: "var(--sx-high)", Medium: "var(--sx-med)", Low: "var(--sx-low)", Informational: "var(--sx-info)" };
const WORKING = ["new", "triaging", "investigating", "contained"];
const go = (path) => { window.history.pushState({}, "", path); window.dispatchEvent(new PopStateEvent("popstate")); };

export async function renderIncident(container, id, { me }) {
  const email = (me && me.email) || "";
  let alive = true;
  onCleanup(() => { alive = false; });
  const S = { inc: null, rep: null, open: [], versions: [], roster: [], evidence: false, node: null };

  container.innerHTML = `<div class="sx-page"><a class="sx-back" href="/soc" data-link>&larr; All incidents</a><div class="ui-skel ui-skel-card"><span class="ui-skel-line tall w50"></span><span class="ui-skel-line w80"></span><span class="ui-skel-line w60"></span></div><div class="ui-skel ui-skel-table"></div></div>`;
  try {
    const [inc, rep, ros] = await Promise.all([api.socIncident(id), api.socIncidentReport(id), api.socAnalysts().catch(() => ({ analysts: [] }))]);
    S.inc = inc; S.rep = rep.report; S.open = rep.open_followups || []; S.versions = rep.versions || []; S.roster = ros.analysts || [];
  } catch (e) {
    container.innerHTML = `<div class="sx-page"><a class="sx-back" href="/soc" data-link>All incidents</a><div class="ui-error" role="alert"><div><h2>Incident ${id} could not be opened</h2><p>${escapeHtml(e.message)}</p></div></div></div>`;
    return;
  }
  const refreshInc = async () => { S.inc = await api.socIncident(id); };

  // ------------------------------------------------------------------ pieces
  const stmts = (list, key = "text") => `<ul class="sx-stmts">${(list || []).map((s) => {
    const m = evidenceMarks(s, S.rep.evidence);
    return `<li class="${m.evidenced ? "" : "noev"}">${escapeHtml(s[key] || s.text)}<div class="sx-ev">${m.evidenced ? m.items.map((e) => `<span class="sx-evref" ${tipAttr(`${e.source}${e.at ? " at " + e.at : ""}: ${e.detail || ""}`)}>${escapeHtml(e.ref)}</span><span>${escapeHtml(e.source)}</span>`).join(" ") : '<span class="sx-noev">Not evidenced</span>'}${m.missing.length ? `<span class="sx-noev">Missing reference ${escapeHtml(m.missing.join(", "))}</span>` : ""}</div></li>`;
  }).join("") || '<li class="noev">Nothing recorded.</li>'}</ul>`;

  const header = () => {
    const i = S.inc; const r = S.rep; const v = r.verdict || {}; const ring = slaRing(i.sla);
    const working = WORKING.includes(i.status);
    return `<div class="sx-inc-head" data-sev="${escapeHtml(i.severity)}">
      <div class="sx-meta"><span>#${i.id}</span>${severityChip(i.severity)}${i.severity !== i.base_severity ? `<span class="ui-muted">raised from ${escapeHtml(i.base_severity)}</span>` : ""}${chip(STATUS_LABEL[i.status] || i.status, { tone: "info" })}<span class="sx-tier">L${i.tier}</span><span class="sx-tier">${escapeHtml(i.priority)}</span>
        <span class="sx-who">${avatar(i.assignee, { size: 24 })}${escapeHtml(i.assignee || (i.queue || "") + " queue")}</span><span class="sx-sla">${ringSvg(ring)}${escapeHtml(ring.label)}</span><span class="ui-muted">opened ${escapeHtml(relTime(i.created_at))}</span></div>
      <h2>${escapeHtml(i.title)}</h2>
      <div class="sx-verdict-banner v-${escapeHtml(v.label || "")}"><span class="sx-verdict-big">${escapeHtml(verdictText(v.label))}</span><span>${escapeHtml(v.statement || "")} <span class="ui-muted">(${escapeHtml(v.basis === "analyst-resolved" ? "analyst verdict" : "automated recommendation")}, ${escapeHtml(confidenceText(v.confidence))}). A person validates it.</span></span></div>
      <div class="sx-actions">
        ${working ? `<button type="button" class="ui-btn sx-btn-sm" data-act="accept" ${i.status === "new" ? "" : "hidden"}>Accept</button>
          <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="advance">Set status</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="reassign">Reassign</button>
          <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="escalate" ${i.tier >= 3 ? "disabled" : ""}>Escalate</button><button type="button" class="ui-btn sx-btn-sm" data-act="resolve">Resolve with verdict</button>` : ""}
        ${i.status === "resolved" ? '<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="reopen">Reopen</button>' : ""}
        ${i.status === "auto_closed" ? '<button type="button" class="ui-btn sx-btn-sm" data-act="undo">Undo auto-close</button>' : ""}
        <span class="sx-pop-host"><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="more" aria-haspopup="menu" aria-expanded="false">More ${icon("chevronDown", 12)}</button></span>
        <label class="sx-row ui-muted" style="font-size:.84rem"><input type="checkbox" id="ev-toggle" ${S.evidence ? "checked" : ""}> Show evidence</label></div>
      <div class="sx-modeline">Report v${r.version}, built ${escapeHtml(relTime(r.generated_at))} · ${r.mode.stored_data_only ? "stored data only" : "includes a confirmed live lookup"} · SIEM ${escapeHtml(r.mode.siem)} · reputation ${escapeHtml(r.mode.reputation)} · ${r.dropped_statements} unevidenced statement(s) dropped</div></div>`;
  };

  const sections = () => {
    const r = S.rep; const i = S.inc;
    const flow = attackFlowLayout(r.attack_flow);
    const tl = filterTimeline(r.timeline, S.node);
    const kc = killChainDots(i.kill_chain);
    return `
    <nav class="sx-anchor" aria-label="Report sections">${[["verdict", "Verdict"], ["history", "History"], ["entities", "Entities"], ["attack", "ATT&CK"], ["flow", "Attack flow"], ["timeline", "Timeline"], ["root", "Root cause"], ["iocs", "IOCs"], ["tools", "Tools"], ["actions", "Actions"], ["refs", "References"], ["followup", "Follow-up"]].map(([k, l]) => `<button type="button" data-jump="${k}">${l}</button>`).join("")}</nav>
    <section class="sx-sec" id="sec-verdict"><h3>Verdict rationale and summary</h3><h4 class="hx-sub">Why this verdict</h4>${stmts(r.verdict.rationale)}<h4 class="hx-sub" style="margin-top:12px">Investigation summary</h4>${stmts(r.summary)}
      <div class="sx-callout" style="margin-top:10px"><b>Why it was routed here.</b> ${escapeHtml((i.routing_reason || []).join(" ") || "Not recorded.")}</div>
      ${kc.count ? `<p class="ui-muted" style="margin:8px 0 0">Kill chain reached: ${escapeHtml(kc.dots.filter((d) => d.reached).map((d) => d.tactic).join(" > "))}</p>` : ""}</section>
    <section class="sx-sec" id="sec-history"><h3>Historical correlation <span class="ui-muted">last ${r.look_back_days} days of stored alerts</span></h3><div class="sx-hist">${(r.history || []).map((h) => `<div class="sx-hist-item"><span class="sx-hist-n${h.alerts ? "" : " zero"}">${h.alerts || 0}</span><div>${escapeHtml(h.text)}<div class="sx-ev">${(h.evidence || []).map((x) => `<span class="sx-evref">${escapeHtml(x)}</span>`).join(" ")}</div></div></div>`).join("") || '<p class="ui-muted">No entities to correlate.</p>'}</div></section>
    <section class="sx-sec" id="sec-entities"><h3>Associated entities</h3><div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Kind</th><th>Value</th><th>Detail</th></tr></thead><tbody>${(r.entities || []).map((e) => `<tr><td>${escapeHtml(e.kind)}</td><td class="sx-mono">${escapeHtml(e.value)}</td><td>${entityDetail(e)}</td></tr>`).join("") || '<tr><td colspan="3" class="ui-muted">None recorded.</td></tr>'}</tbody></table></div></section>
    <section class="sx-sec" id="sec-attack"><h3>ATT&amp;CK mapping and next steps</h3><div class="sx-att">${(r.attack || []).map((a) => `<div class="sx-att-card"><h4>${escapeHtml(a.technique)} ${escapeHtml(a.name)}</h4><div class="sx-chips">${chip(a.tactic || "Unmapped", { tone: "info" })}${(a.alerts || []).map((x) => chip("alert #" + x)).join("")}</div>
      ${a.next_step ? `<p class="sx-next">${escapeHtml(a.next_step)}</p>` : '<p class="ui-muted">No next-step hint for this technique.</p>'}${(a.look_in || []).length ? `<div class="ui-muted">Look in: ${escapeHtml(a.look_in.join(", "))}</div>` : ""}${(a.mitigations || []).length ? `<div class="ui-muted">Mitigations: ${escapeHtml(a.mitigations.join(", "))}</div>` : ""}
      ${a.runbook ? `<details><summary class="sx-link-btn">Runbook: ${escapeHtml(a.runbook.title || a.runbook.id)}</summary><ol>${(a.runbook.steps || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol></details>` : ""}</div>`).join("") || '<p class="ui-muted">No technique is tagged on these alerts.</p>'}</div></section>
    <section class="sx-sec" id="sec-flow"><h3>Attack flow <span class="ui-muted">click a step to filter the timeline</span></h3>${flowSvg(flow, r.attack_flow)}<p class="ui-muted" style="font-size:.78rem">${escapeHtml((r.attack_flow && r.attack_flow.note) || "")}</p></section>
    <section class="sx-sec" id="sec-timeline"><h3>Behaviour timeline ${S.node ? `<button type="button" class="sx-link-btn" data-clear-node>Showing: ${escapeHtml(S.node.label)} (clear)</button>` : ""}</h3><ul class="sx-tl">${tl.map((e) => `<li class="sx-tl-${timelineIcon(e.event)}"><span class="sx-tl-ico" aria-hidden="true">${{ alert: "!", check: "✓", search: "?", shield: "◆", up: "↑", dot: "•" }[timelineIcon(e.event)]}</span><div><div class="when">${escapeHtml(fmtWhen(e.at))}</div><div class="what">${escapeHtml(e.event)}</div><div class="sx-ev">${(e.evidence || []).map((x) => `<span class="sx-evref">${escapeHtml(x)}</span>`).join(" ")}</div></div></li>`).join("") || '<li><span></span><span class="ui-muted">No events for this selection.</span></li>'}</ul></section>
    <section class="sx-sec" id="sec-root"><h3>Root cause ${chip(r.root_cause.is_hypothesis ? "Hypothesis" : "Corroborated", { tone: r.root_cause.is_hypothesis ? "warn" : "good" })}</h3><div class="sx-callout${r.root_cause.is_hypothesis ? " hyp" : ""}">${escapeHtml(r.root_cause.text)}</div>${(r.root_cause.gaps || []).length ? `<ul class="sx-gaps">${r.root_cause.gaps.map((g) => `<li>${escapeHtml(g)}</li>`).join("")}</ul>` : ""}</section>
    <section class="sx-sec" id="sec-iocs"><h3>Indicators of compromise <span class="ui-muted">reputation, context and blast radius</span></h3>${iocTable(r.iocs)}</section>
    <section class="sx-sec" id="sec-tools"><h3>What the tools did</h3><div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Alert</th><th>Tool</th><th>Action</th><th>Advice</th></tr></thead><tbody>${(r.tool_actions || []).map((t) => `<tr><td>#${t.alert_id}</td><td>${escapeHtml(t.technology)}</td><td>${chip(t.action, { tone: t.state === "blocked" ? "good" : t.state === "allowed" ? "critical" : "neutral" })}</td><td>${escapeHtml(t.advice || "")}</td></tr>`).join("") || '<tr><td colspan="4" class="ui-muted">No tool action recorded.</td></tr>'}</tbody></table></div></section>
    <section class="sx-sec" id="sec-actions"><h3>Recommended actions</h3><ul class="sx-stmts">${(r.recommended_actions || []).map((a) => `<li>${escapeHtml(a.action)} ${a.needs_second_person ? chip("needs a second person", { tone: "warn" }) : ""}<div class="ui-muted" style="font-size:.8rem">${escapeHtml(a.why || "")} · ${escapeHtml(a.source || "")}</div></li>`).join("") || '<li class="noev">No recommended action.</li>'}</ul>
      ${(r.gaps || []).length ? `<div class="sx-callout warn" style="margin-top:10px"><b>What is not known.</b><ul class="sx-gaps">${r.gaps.map((g) => `<li>${escapeHtml(g)}</li>`).join("")}</ul></div>` : ""}</section>
    <section class="sx-sec" id="sec-refs"><h3>References <span class="ui-muted">the searches and lookups behind this report</span></h3>${refs(r)}
      <div class="sx-row" style="margin-top:10px"><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="live">${icon("search", 14)} Run live searches…</button><span class="ui-muted" style="font-size:.8rem">Shows the planned searches and look-back first, and runs nothing until you confirm.</span></div></section>
    <section class="sx-sec" id="sec-followup"><h3>Follow-up questions</h3><div class="sx-fu">${followups()}</div>
      <form class="sx-fu-form" id="fu-form" style="margin-top:10px"><input class="sx-field" id="fu-q" required placeholder="Ask about this incident, e.g. Has 185.220.101.9 been seen before?" aria-label="Follow-up question"><button class="ui-btn sx-btn-sm" type="submit">Ask</button></form>
      <div class="sx-row" style="margin-top:10px"><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="merge" ${S.open.length ? "" : "disabled"}>Merge ticked answers into the report</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-act="ticket">Post to ticket…</button></div></section>
    ${related()}`;
  };

  const entityDetail = (e) => {
    const bits = [];
    if (e.owner && e.owner !== "unknown") bits.push(`owner ${e.owner}`); else if (e.kind === "host" || e.kind === "user") bits.push("owner unknown");
    for (const k of ["team", "criticality", "asset_type"]) if (e[k]) bits.push(`${k.replace("_", " ")} ${e[k]}`);
    if (e.open_findings !== undefined) bits.push(`${e.open_findings} open finding(s)${e.kev_findings ? `, ${e.kev_findings} known-exploited` : ""}`);
    if (e.privilege) bits.push(e.privilege === "unknown" ? "privilege unknown" : e.privilege_detail || e.privilege);
    if (e.scope) bits.push(e.scope);
    return escapeHtml(bits.join(" · ") || "no further detail held");
  };
  const iocTable = (iocs) => !(iocs || []).length ? '<p class="ui-muted">No indicators on these alerts.</p>' : `<div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Indicator</th><th>Reputation</th><th>Context</th><th>Blast radius</th></tr></thead><tbody>${iocs.map((x) => {
    const rp = x.reputation || {}; const b = x.blast_radius || {};
    return `<tr><td><span class="sx-mono">${escapeHtml(x.value)}</span><div class="ui-muted">${escapeHtml(x.type)}</div></td><td>${chip(x.verdict, { tone: x.verdict === "malicious" ? "critical" : x.verdict === "suspicious" ? "warn" : x.verdict === "no-detections" ? "info" : "neutral" })}<div class="ui-muted" style="font-size:.76rem">${escapeHtml(rp.status || "")}${rp.total ? ` · ${rp.malicious}/${rp.total} engines` : ""}${rp.at ? ` · ${escapeHtml(relTime(rp.at))}` : ""}</div></td>
      <td>${(x.context || []).map(escapeHtml).join("<br>")}</td><td><div class="sx-blast"><span><b>${b.alerts || 0}</b> alerts</span><span><b>${b.hosts || 0}</b> hosts</span><span><b>${b.users || 0}</b> users</span><span><b>${b.incidents || 0}</b> incidents</span></div><div class="ui-muted" style="font-size:.74rem">${escapeHtml((b.host_names || []).join(", "))}</div></td></tr>`;
  }).join("")}</tbody></table></div>`;
  const refs = (r) => {
    const live = r.live_search || {};
    const notRun = live.ran ? `<p class="ui-muted" style="font-size:.82rem">Live search ran ${live.queries_run} query(ies), ${live.rows_seen} row(s), stopped: ${escapeHtml(live.stop_reason)}.</p>` : `<p class="ui-muted" style="font-size:.82rem">${escapeHtml(live.note || "No live search was run. Everything here comes from stored data.")}</p>`;
    return notRun + `<div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Kind</th><th>Name and query</th><th>Source</th><th>Result</th></tr></thead><tbody>${(r.references || []).map((x) => `<tr><td>${escapeHtml(x.kind)}</td><td>${escapeHtml(x.name)}${x.query ? `<pre class="sx-code">${escapeHtml(x.query)}</pre>` : ""}</td><td>${escapeHtml(x.source || "")}<div class="ui-muted">${escapeHtml(fmtWhen(x.at))}${x.look_back_days ? ` · ${x.look_back_days} d` : ""}</div></td><td>${escapeHtml(x.result || "")}</td></tr>`).join("") || '<tr><td colspan="4" class="ui-muted">No references.</td></tr>'}</tbody></table></div>`;
  };
  const followups = () => {
    const merged = S.rep.followups || [];
    const rows = [...S.open.map((f) => ({ ...f, merged: false })), ...merged.map((f) => ({ ...f, merged: true }))];
    return rows.map((f) => `<div class="sx-fu-item"><div class="sx-fu-q">${f.merged ? "" : `<label class="sx-row" style="flex-direction:row"><input type="checkbox" data-fu="${f.id}"> `}${escapeHtml(f.question)}${f.merged ? "" : "</label>"}</div><div>${escapeHtml(f.answer || "")}</div><div class="sx-ev" style="display:flex">${f.merged ? chip("in the report", { tone: "good" }) : chip("not merged yet")}${(f.evidence || []).map((x) => `<span class="sx-evref">${escapeHtml(typeof x === "string" ? x : x.source || "")}</span>`).join(" ")}</div></div>`).join("") || '<p class="ui-muted">No questions yet. Ask one: it is answered from stored data with its evidence, then you choose whether it joins the report.</p>';
  };
  const related = () => (S.inc.related_incidents || []).length ? `<section class="sx-sec" id="sec-related"><h3>Related incidents</h3><div class="sx-table-wrap"><table class="sx-table"><tbody>${S.inc.related_incidents.map((x) => `<tr><td><a href="/soc?incident=${x.id}" data-link>#${x.id}</a></td><td>${escapeHtml(x.title)}</td><td>${severityChip(x.severity)}</td><td>${escapeHtml(STATUS_LABEL[x.status] || x.status)}</td><td class="ui-muted">shares ${escapeHtml(Object.entries(x.shared || {}).map(([k, v]) => `${k} ${[].concat(v).join(", ")}`).join("; "))}</td></tr>`).join("")}</tbody></table></div></section>` : "";

  function flowSvg(L, flow) {
    if (!L.nodes.length) return '<p class="ui-muted">No alerts with a mapped stage yet, so there is nothing to draw.</p>';
    const W = L.width; const H = L.height;
    const lanes = L.lanes.map((l) => `<rect class="sx-lane-bg" x="${l.x + 3}" y="2" width="${l.w - 6}" height="${L.laneHeight}" rx="8"/><text class="sx-lane-t" x="${l.x + 12}" y="20">${escapeHtml(l.stage)}</text>`).join("");
    const edges = L.edges.map((e) => `<path class="sx-fedge ${escapeHtml(e.kind)}" d="${e.path}"/>`).join("");
    const nodes = L.nodes.map((n) => {
      const sev = SEV_VAR[n.severity] || "var(--text-muted)";
      const label = String(n.label || "").length > 24 ? `${String(n.label).slice(0, 23)}…` : n.label;
      const sub = n.kind === "alert" ? `${n.technique || "no technique"} · ${n.host || ""}` : n.entity_kind;
      return `<g class="sx-fnode${n.kind === "entity" ? " entity" : ""}${S.node && S.node.id === n.id ? " sel" : ""}" data-node="${escapeHtml(n.id)}" tabindex="0" role="button" aria-label="${escapeHtml(n.label)}, ${escapeHtml(sub)}" style="--sevc:${sev}" transform="translate(${n.x},${n.y})">
        <title>${escapeHtml(n.label)} (${escapeHtml(sub)})</title><rect class="b" width="${n.w}" height="${n.h}" rx="7"/>${n.kind === "alert" ? `<rect class="sev" width="5" height="${n.h}" rx="2"/>` : ""}
        <text x="12" y="${n.kind === "alert" ? 22 : 21}">${escapeHtml(label)}</text>${n.kind === "alert" ? `<text class="sub" x="12" y="40">${escapeHtml(String(sub).slice(0, 28))}</text>` : ""}</g>`;
    }).join("");
    return `<div class="sx-flow-wrap"><svg class="sx-flow" viewBox="0 0 ${W} ${H}" width="${Math.max(W, 560)}" height="${H}" role="group" aria-label="Attack flow: ${L.lanes.length} stages, ${L.nodes.length} nodes">${lanes}${edges}${nodes}</svg></div>
      <div class="sx-legend"><span><i style="background:var(--sx-crit)"></i>Critical</span><span><i style="background:var(--sx-high)"></i>High</span><span><i style="background:var(--sx-med)"></i>Medium</span><span><i style="background:var(--sx-low)"></i>Low</span><span>Dashed line: involves</span><span>Moving dashes: next stage</span></div>`;
  }

  // ------------------------------------------------------------------ painting and events
  const root = container;
  function paint(keepScroll = true) {
    const y = window.scrollY;
    root.innerHTML = `<div class="sx-page${S.evidence ? " sx-evidence-on" : ""}"><a class="sx-back" href="/soc" data-link>&larr; All incidents</a>${header()}${sections()}</div>`;
    if (keepScroll) window.scrollTo(0, y);
  }
  paint(false);

  async function reloadReport(r) { S.rep = r.report || r; if (r.open_followups) S.open = r.open_followups; paint(); }
  const act = {
    accept: async () => { await api.socIncidentAct(id, "accept", {}); },
    advance: async () => {
      const out = await modal({ title: "Set status", confirmLabel: "Set", body: `<label>Status<select id="m-st">${["triaging", "investigating", "contained"].map((s) => `<option value="${s}" ${s === S.inc.status ? "selected" : ""}>${STATUS_LABEL[s]}</option>`).join("")}</select></label><label>Note<input type="text" id="m-n"></label>`, collect: (d) => ({ status: d.querySelector("#m-st").value, note: d.querySelector("#m-n").value.trim() || null }) });
      if (out) await api.socIncidentAct(id, "advance", out); else return false;
    },
    reassign: async () => {
      const out = await modal({ title: "Reassign", confirmLabel: "Reassign", body: `<label>Assign to<select id="m-who">${S.roster.filter((a) => a.email !== S.inc.assignee).map((a) => `<option value="${escapeHtml(a.email)}">${escapeHtml(a.email)} (L${a.tier}, ${a.open_incidents || 0} open${a.available ? "" : ", unavailable"})</option>`).join("")}</select></label><label>Reason<input type="text" id="m-r"></label>`, collect: (d) => ({ assignee: d.querySelector("#m-who").value, reason: d.querySelector("#m-r").value.trim() || null }) });
      if (out) await api.socIncidentAct(id, "reassign", out); else return false;
    },
    escalate: async () => {
      const out = await modal({ title: "Escalate", confirmLabel: "Escalate", description: "The incident leaves your queue and is routed up.", body: `<label>Hand-off summary<textarea id="m-s" placeholder="20+ characters"></textarea></label>`, validate: (d) => (d.querySelector("#m-s").value.trim().length < 20 ? "A hand-off summary of at least 20 characters is required." : ""), collect: (d) => ({ summary: d.querySelector("#m-s").value.trim() }) });
      if (out) await api.socIncidentAct(id, "escalate", out); else return false;
    },
    resolve: async () => {
      const out = await modal({ title: "Resolve with a verdict", confirmLabel: "Resolve", description: "The verdict judges the first-look recommendation for each alert.", body: `<label>Verdict<select id="m-v">${VERDICTS.map((v) => `<option value="${v}" ${v === ({ "true-positive": "true-positive", "false-positive": "false-positive" }[S.rep.verdict.label] || "") ? "selected" : ""}>${escapeHtml(verdictText(v))}</option>`).join("")}</select></label><label>Summary<textarea id="m-s" placeholder="20+ characters"></textarea></label>`, validate: (d) => (d.querySelector("#m-s").value.trim().length < 20 ? "Write a summary of at least 20 characters." : ""), collect: (d) => ({ verdict: d.querySelector("#m-v").value, summary: d.querySelector("#m-s").value.trim() }) });
      if (out) await api.socIncidentAct(id, "resolve", out); else return false;
    },
    reopen: async () => {
      const out = await modal({ title: "Reopen", confirmLabel: "Reopen", body: `<label>Why?<textarea id="m-r"></textarea></label>`, validate: (d) => (d.querySelector("#m-r").value.trim().length < 5 ? "Say why." : ""), collect: (d) => ({ reason: d.querySelector("#m-r").value.trim() }) });
      if (out) await api.socIncidentAct(id, "reopen", out); else return false;
    },
    undo: async () => { await api.socIncidentAct(id, "undo-auto-close", {}); },
  };
  async function runAct(name) {
    try {
      const r = await act[name]();
      if (r === false) return;
      await refreshInc(); const rep = await api.socIncidentReport(id); S.rep = rep.report; paint();
      toast("Done.", { tone: "good", ms: 2500 });
    } catch (e) { toast(`Not done: ${e.message}`, { tone: "bad", ms: 7000 }); }
  }
  async function note() {
    const out = await modal({ title: "Add a note", confirmLabel: "Add", body: `<label>Note<textarea id="m-n"></textarea></label>`, validate: (d) => (d.querySelector("#m-n").value.trim() ? "" : "A note cannot be empty."), collect: (d) => d.querySelector("#m-n").value.trim() });
    if (out) try { await api.socIncidentAct(id, "note", { note: out }); toast("Note added.", { tone: "good" }); } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  async function mergeInc() {
    const rel = S.inc.related_incidents || [];
    const out = await modal({ title: "Merge another incident into this one", confirmLabel: "Merge", description: "The other incident becomes Merged and its alerts move here.", body: `<label>Incident to merge<select id="m-src">${rel.map((x) => `<option value="${x.id}">#${x.id} ${escapeHtml(x.title)}</option>`).join("")}</select></label>`, validate: () => (rel.length ? "" : "No related incident to merge."), collect: (d) => Number(d.querySelector("#m-src").value) });
    if (out) try { await api.socIncidentAct(id, "merge", { source_id: out }); await refreshInc(); const rep = await api.socIncidentReport(id); S.rep = rep.report; paint(); toast("Merged.", { tone: "good" }); } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  async function splitInc() {
    const al = S.inc.alerts || [];
    const out = await modal({ title: "Split alerts into a new incident", confirmLabel: "Split", description: "Tick the alerts to move. At least one must stay here.", body: `<div class="sx-checks">${al.map((a) => `<label><input type="checkbox" value="${a.id}"> #${a.id} ${escapeHtml(a.title)}</label>`).join("")}</div>`, validate: (d) => { const n = d.querySelectorAll("input:checked").length; return n && n < al.length ? "" : "Tick at least one alert and leave at least one behind."; }, collect: (d) => [...d.querySelectorAll("input:checked")].map((x) => Number(x.value)) });
    if (out) try { const r = await api.socIncidentAct(id, "split", { alert_ids: out }); toast(`New incident #${r.new.id} created.`, { tone: "good", href: `/soc?incident=${r.new.id}`, action: "Open" }); await refreshInc(); paint(); } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  async function exportMd(copy) {
    try { const md = await api.socIncidentReportMd(id); if (copy) copyText(md, "Report copied as Markdown"); else downloadText(`incident-${id}-report.md`, md); } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  async function liveSearch() {
    try {
      const pre = await api.socIncidentReportRefresh(id, { reputation: true, siem: true, confirm: false });
      const body = `<p>${escapeHtml(pre.message || "")}</p><h4 class="hx-sub">Look-back</h4><p>Up to ${pre.look_back_cap_days} days. Past the default needs a written justification.</p>
        <h4 class="hx-sub">Indicators that would be sent for reputation (public only) via ${escapeHtml(pre.reputation_connection || "the reputation connection")}</h4><ul>${(pre.indicators_that_would_be_sent || []).map((x) => `<li class="sx-mono">${escapeHtml(x)}</li>`).join("") || "<li>None</li>"}</ul>
        <h4 class="hx-sub">Read-only searches in ${escapeHtml(pre.siem_connection || "your SIEM")}</h4><ul>${(pre.searches_that_would_run || []).map((q) => `<li>${escapeHtml(q.name)} (${q.look_back_days} d)<pre class="sx-code">${escapeHtml(q.query)}</pre></li>`).join("") || "<li>None planned</li>"}</ul>
        <p class="ui-muted">Budget: ${pre.budget.max_queries} queries, ${pre.budget.max_rows} rows, ${pre.budget.time_budget_seconds} s. It stops at the first limit and records why.${pre.planned_but_over_budget ? ` ${pre.planned_but_over_budget} planned search(es) are over budget and will not run.` : ""}</p>`;
      const ok = await modal({ title: "Run live searches?", confirmLabel: "Confirm and run", wide: true, body, collect: () => true });
      if (!ok) return;
      const done = await api.socIncidentReportRefresh(id, { reputation: true, siem: true, confirm: true });
      await reloadReport(done);
      toast(`Report v${done.report.version} built. Live search: ${done.report.live_search.stop_reason || "done"}.`, { tone: "good", ms: 6000 });
    } catch (e) { toast(e.status === 400 ? `${e.message}` : `Not run: ${e.message}`, { tone: "warn", ms: 8000 }); }
  }
  async function postTicket() {
    try {
      const pre = await api.socIncidentPostToTicket(id, { confirm: false });
      const ok = await modal({ title: "Post to the ITSM ticket (preview)", confirmLabel: "Post comment", wide: true, description: "Nothing has been sent. This is the exact comment and where it would go.",
        body: `<pre>${escapeHtml(pre.comment)}</pre><ul>${(pre.results || []).map((r) => `<li>${escapeHtml(r.system)} ${escapeHtml(r.ticket)}: ${escapeHtml(r.status)}</li>`).join("")}</ul>`, collect: () => true });
      if (!ok) return;
      const done = await api.socIncidentPostToTicket(id, { confirm: true });
      toast(`Posted: ${done.results.map((r) => `${r.ticket} ${r.status}`).join(", ")}`, { tone: "good", ms: 6000 });
    } catch (e) { toast(e.message, { tone: "warn", ms: 8000 }); }
  }

  root.addEventListener("click", async (e) => {
    const jump = e.target.closest("[data-jump]");
    if (jump) { const el = root.querySelector(`#sec-${jump.dataset.jump}`); if (el) el.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" }); root.querySelectorAll("[data-jump]").forEach((b) => b.removeAttribute("aria-current")); jump.setAttribute("aria-current", "true"); return; }
    if (e.target.closest("[data-clear-node]")) { S.node = null; paint(); return; }
    const node = e.target.closest("[data-node]");
    if (node) { toggleNode(node.dataset.node); return; }
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const name = b.dataset.act;
    if (act[name]) return runAct(name);
    if (name === "live") return liveSearch();
    if (name === "ticket") return postTicket();
    if (name === "merge") {
      const ids = [...root.querySelectorAll("[data-fu]:checked")].map((x) => Number(x.dataset.fu));
      if (!ids.length) { toast("Tick the answers to merge first.", { tone: "warn" }); return; }
      try { const r = await api.socIncidentMergeFollowups(id, { followup_ids: ids, merged: true }); await reloadReport(r); toast("Merged into the report.", { tone: "good" }); } catch (er) { toast(er.message, { tone: "bad" }); }
      return;
    }
    if (name === "more") {
      popMenu(b, [{ label: "Add a note…", run: note }, { label: "Merge another incident…", run: mergeInc }, { label: "Split alerts out…", run: splitInc }, { sep: true },
        { label: "Rebuild report from stored data", run: async () => { try { const r = await api.socIncidentReportRefresh(id, {}); await reloadReport(r); toast(`Report v${r.report.version} built.`, { tone: "good" }); } catch (er) { toast(er.message, { tone: "bad" }); } } },
        { label: "Download report (Markdown)", run: () => exportMd(false) }, { label: "Copy report as Markdown", run: () => exportMd(true) },
        { label: "Copy link", run: () => copyText(window.location.href, "Link copied") }, ...(S.inc.case_id ? [{ label: "Open its case tools", run: () => go(`/soc?case=${S.inc.case_id}`) }] : [])]);
    }
  });
  root.addEventListener("keydown", (e) => { const node = e.target.closest && e.target.closest("[data-node]"); if (node && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggleNode(node.dataset.node); } });
  root.addEventListener("change", (e) => { if (e.target.id === "ev-toggle") { S.evidence = e.target.checked; root.querySelector(".sx-page").classList.toggle("sx-evidence-on", S.evidence); } });
  root.addEventListener("submit", async (e) => {
    if (e.target.id !== "fu-form") return;
    e.preventDefault();
    const q = root.querySelector("#fu-q").value.trim();
    if (!q) return;
    try { const r = await api.socIncidentFollowUp(id, { question: q }); S.open = [r.followup, ...S.open].filter((f, i, a) => a.findIndex((x) => x.id === f.id) === i); paint(); toast(r.message, { tone: r.followup.answerable ? "good" : "warn", ms: 6000 }); } catch (er) { toast(er.message, { tone: "bad" }); }
  });
  function toggleNode(nid) {
    const L = attackFlowLayout(S.rep.attack_flow);
    const n = L.nodes.find((x) => x.id === nid);
    S.node = S.node && S.node.id === nid ? null : n ? { id: n.id, kind: n.kind, label: n.label } : null;
    paint();
    const t = root.querySelector("#sec-timeline"); if (t && S.node) t.scrollIntoView({ block: "nearest" });
  }
}
