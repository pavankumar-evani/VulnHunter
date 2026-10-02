import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Threat Models";

const RATING = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
const CTL = { verified: ["badge-auto_approvable", "verified"], claimed: ["badge-outline", "recorded"], absent: ["badge-critical", "absent"], unknown: ["badge-outline", "unknown"] };
const SAMPLE = {
  components: [
    { id: "users", name: "Customers", type: "external", trust_zone: "internet" },
    { id: "web", name: "Web portal", type: "process", internet_facing: true, trust_zone: "dmz", authn: true, input_validated: false, logging: true, rate_limited: false, assets: ["WEB-*"], handles: ["pii"] },
    { id: "db", name: "Customer database", type: "datastore", trust_zone: "internal", handles: ["pii", "payment"], encrypted_at_rest: false, logging: true, assets: ["DB-*"] },
  ],
  data_flows: [
    { from: "users", to: "web", protocol: "https", encrypted: true, authenticated: true, data: ["pii"] },
    { from: "web", to: "db", protocol: "sql", encrypted: false, authenticated: true, data: ["pii", "payment"] },
  ],
  trust_zones: [{ id: "internet", name: "Internet", trust: 0 }, { id: "dmz", name: "DMZ", trust: 1 }, { id: "internal", name: "Internal", trust: 2 }],
};

function diagram(model) {
  const comps = model.components;
  if (!comps.length) return `<p class="muted">No components yet.</p>`;
  const trust = Object.fromEntries((model.trust_zones || []).map((z) => [z.id, z.trust]));
  const colOf = (c) => (c.trust_zone && trust[c.trust_zone] !== undefined ? trust[c.trust_zone] : c.internet_facing ? 0 : 1);
  const cols = [...new Set(comps.map(colOf))].sort((a, b) => a - b);
  const pos = {};
  const stack = {};
  comps.forEach((c) => {
    const ci = cols.indexOf(colOf(c));
    const row = (stack[ci] = (stack[ci] || 0) + 1) - 1;
    pos[c.id] = { x: 30 + ci * 270, y: 30 + row * 78 };
  });
  const w = 30 + cols.length * 270, h = 30 + Math.max(...Object.values(stack)) * 78;
  const zoneName = (t) => (model.trust_zones.find((z) => z.trust === t) || {}).name || "";
  const lines = model.data_flows.map((f) => {
    const a = pos[f.from], b = pos[f.to];
    if (!a || !b) return "";
    const same = a.x === b.x;
    const x1 = same ? a.x + 100 : (a.x < b.x ? a.x + 200 : a.x), x2 = same ? b.x + 100 : (a.x < b.x ? b.x : b.x + 200);
    const y1 = a.y + (same ? (a.y < b.y ? 50 : 0) : 25), y2 = b.y + (same ? (a.y < b.y ? 0 : 50) : 25);
    const colour = f.encrypted === false ? "#f06a6a" : f.encrypted === true ? "#3fd0b6" : "#f0b44c";
    return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${colour}" stroke-width="2"${f.encrypted === false ? ' stroke-dasharray="6 4"' : ""} marker-end="url(#arr)"><title>${escapeHtml(f.name)}${f.encrypted === false ? " (not encrypted)" : f.encrypted === undefined ? " (encryption not recorded)" : ""}</title></line>`;
  }).join("");
  const boxes = comps.map((c) => `<g><rect x="${pos[c.id].x}" y="${pos[c.id].y}" width="200" height="50" rx="6" fill="#111a30" stroke="${c.internet_facing ? "#f0b44c" : "#2a3860"}" stroke-width="1.5"/>
    <text x="${pos[c.id].x + 10}" y="${pos[c.id].y + 21}" fill="#eef1fb" font-size="13" font-weight="600">${escapeHtml(c.name).slice(0, 26)}</text>
    <text x="${pos[c.id].x + 10}" y="${pos[c.id].y + 39}" fill="#8e9bc0" font-size="11">${escapeHtml(c.type)}${c.inferred ? " (inferred)" : ""}</text></g>`).join("");
  const heads = cols.map((t, i) => `<text x="${30 + i * 270}" y="16" fill="#6d97f7" font-size="11" letter-spacing="1.5">${escapeHtml(zoneName(t).toUpperCase() || `ZONE ${t}`)}</text>`).join("");
  return `<div class="table-scroll"><svg width="${w}" height="${h}" role="img" aria-label="Data flow diagram"><defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="#8e9bc0"/></marker></defs>${heads}${lines}${boxes}</svg></div>
    <p class="muted">Red dashed: not encrypted. Green: encrypted. Amber: not recorded. Amber outline: internet-facing.</p>`;
}

export async function render(container) {
  const id = new URLSearchParams(window.location.search).get("id");
  if (!id) return renderList(container);
  return renderModel(container, Number(id));
}

async function renderList(container) {
  async function load() {
    const { models } = await api.threatModels();
    container.innerHTML = `
      <p class="subtitle">Describe a system (its components, how data flows between them, and the trust zones they sit in) and Quanta raises the threats a STRIDE review would,
      from explicit rules you can read. Each threat is joined to the live findings on its assets and the security controls recorded for them, so a known-exploited flaw
      or a missing control moves its risk. Scores are for ranking and discussion, not a measurement.</p>
      <h2>Models</h2>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Name</th><th>Components</th><th>Flows</th><th>Updated</th><th></th></tr></thead><tbody>
      ${models.length ? models.map((m) => `<tr><td><a href="/threat-models?id=${m.id}" data-link>${escapeHtml(m.name)}</a><br><span class="muted">${escapeHtml(m.description || "")}</span></td>
        <td>${m.components}</td><td>${m.flows}</td><td>${escapeHtml(m.updated_at)}</td><td><button type="button" class="link-button danger-link" data-del="${m.id}">Delete</button></td></tr>`).join("")
        : `<tr><td colspan="5" class="empty-state">No threat models yet.</td></tr>`}</tbody></table></div>
      <h2>New model</h2>
      <form id="tm-form" class="run-form">
        <label>Name <input name="name" required maxlength="120" placeholder="Customer portal"></label>
        <label>Description <input name="description" maxlength="1000"></label>
        <label>Start from <select name="start"><option value="sample">An example system I can edit</option><option value="assets">My assets (drafted from the findings)</option><option value="empty">Empty</option></select></label>
        <div><button type="submit">Create</button></div>
      </form>`;
    container.querySelector("#tm-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      try {
        const r = await api.createThreatModel({ name: f.name.value, description: f.description.value, model: f.start.value === "sample" ? SAMPLE : null });
        if (f.start.value === "assets") await api.seedThreatModel(r.id, []);
        window.history.pushState({}, "", `/threat-models?id=${r.id}`);
        window.dispatchEvent(new PopStateEvent("popstate"));
      } catch (err) { flash(err.message, "error"); }
    });
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
      if (!window.confirm("Delete this threat model and its reviews?")) return;
      try { await api.deleteThreatModel(Number(b.dataset.del)); load(); } catch (err) { flash(err.message, "error"); }
    }));
  }
  await load();
}

async function renderModel(container, id) {
  async function load() {
    const r = await api.threatModel(id);
    const s = r.summary;
    container.innerHTML = `
      <p><a href="/threat-models" data-link>&larr; All models</a></p>
      <h2>${escapeHtml(r.name)}</h2>
      <p class="muted">${escapeHtml(r.description || "")} Last changed ${escapeHtml(r.updated_at)} by ${escapeHtml(r.updated_by || "")}.</p>
      <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">threats</div><div class="kpi-value">${s.total}</div></div>
        <div class="kpi-card kpi-danger"><div class="kpi-label">critical or high (before controls)</div><div class="kpi-value">${s.by_rating.Critical + s.by_rating.High}</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-label">with live findings that could realise them</div><div class="kpi-value">${s.with_live_findings}</div></div>
        <div class="kpi-card"><div class="kpi-label">still open</div><div class="kpi-value">${s.open}</div></div>
      </div>
      ${s.unconfirmed ? `<p class="muted">${s.unconfirmed} threat(s) are <em>unconfirmed</em>: the model does not say whether the weakness exists, so they are questions to answer, scored one step lower. ` +
        `${s.controls_unknown} have no recorded controls on their assets, so their residual risk equals the inherent risk. <a href="/controls" data-link>Record controls</a>.</p>` : ""}
      <h3>System</h3>${diagram(r.model)}
      <h3>Threats</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Risk</th><th>Threat</th><th>Live findings</th><th>Mitigating controls</th><th>Residual</th><th>Decision</th></tr></thead><tbody>
      ${r.threats.map((t) => `<tr>
        <td><span class="badge ${RATING[t.rating]}">${escapeHtml(t.rating)}</span><br><span class="muted">${t.likelihood} x ${t.impact} = ${t.inherent_score}</span></td>
        <td class="wrap-cell"><strong>${escapeHtml(t.title)}</strong> <span class="muted">${escapeHtml(t.stride_name)} &middot; ${escapeHtml(t.rule_id)}</span>
          ${t.confidence === "unconfirmed" ? `<span class="badge badge-outline">unconfirmed</span>` : ""}<br>${escapeHtml(t.description)}<br>
          <span class="muted">${escapeHtml(t.element.name)}${t.techniques.length ? ` &middot; ATT&amp;CK ${t.techniques.map(escapeHtml).join(", ")}` : ""}${t.cwe.length ? ` &middot; ${t.cwe.map(escapeHtml).join(", ")}` : ""}</span></td>
        <td class="wrap-cell">${t.findings.length ? t.findings.map((f) => `<a href="/queue?title=${encodeURIComponent(f.title || "")}" data-link>${escapeHtml(f.id)}</a>${f.kev ? ' <span class="badge badge-critical">KEV</span>' : ""}`).join(", ") + (t.findings_total > t.findings.length ? ` +${t.findings_total - t.findings.length} more` : "") : '<span class="muted">none</span>'}</td>
        <td class="wrap-cell">${t.controls.map((c) => `<span class="badge ${CTL[c.status][0]}" title="${escapeHtml(c.label)}: ${CTL[c.status][1]}">${escapeHtml(c.label)}: ${CTL[c.status][1]}</span>`).join(" ")}</td>
        <td><span class="badge ${RATING[t.residual_rating]}">${escapeHtml(t.residual_rating)}</span><br><span class="muted">${t.residual_score}${t.controls_known ? "" : " (controls unknown)"}</span></td>
        <td><select data-review="${escapeHtml(t.key)}">${["open", "accepted", "mitigated", "not-applicable"].map((st) => `<option value="${st}"${t.review.status === st ? " selected" : ""}>${st}</option>`).join("")}</select>
          ${t.review.note ? `<br><span class="muted">${escapeHtml(t.review.note)}</span>` : ""}</td></tr>`).join("") || `<tr><td colspan="6" class="empty-state">No threats raised. Add components and flows, or check the properties the rules look at.</td></tr>`}
      </tbody></table></div>
      <h3>Edit the model</h3>
      <p class="muted">JSON: components (<code>id, name, type, internet_facing, trust_zone, authn, input_validated, logging, rate_limited, encrypted_at_rest, privileged, secrets_management, third_party, sbom, handles, assets</code>),
      data flows (<code>from, to, encrypted, authenticated, data</code>) and trust zones. A property left out is treated as not recorded. <code>assets</code> are the asset names or patterns that join the component to findings and controls.</p>
      <textarea id="model-json" rows="14" style="width:100%;font-family:monospace">${escapeHtml(JSON.stringify({ components: r.model.components.map(({ id, name, type, ...rest }) => ({ id, name, type, ...rest })), data_flows: r.model.data_flows.map(({ name, from_type, to_type, crosses_zones, ...rest }) => rest), trust_zones: r.model.trust_zones }, null, 2))}</textarea>
      <p><button type="button" id="save-model">Save model</button></p>
      <form id="seed-form" class="run-form"><label>Add draft components from my assets (names or patterns, comma separated; empty means the most-affected assets)
        <input name="patterns" placeholder="WEB-*, DB-*"></label><div><button type="submit">Add drafted components</button></div></form>`;
    container.querySelector("#save-model").addEventListener("click", async () => {
      let model;
      try { model = JSON.parse(container.querySelector("#model-json").value); } catch { flash("That is not valid JSON.", "error"); return; }
      try { await api.updateThreatModel(id, { model }); flash("Saved.", "success"); load(); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelector("#seed-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const patterns = e.target.patterns.value.split(",").map((x) => x.trim()).filter(Boolean);
      try { const out = await api.seedThreatModel(id, patterns); flash(`${out.added} component(s) added, marked as inferred. Check them.`, "success"); load(); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelectorAll("[data-review]").forEach((sel) => sel.addEventListener("change", async () => {
      let note = null;
      if (sel.value === "accepted" || sel.value === "not-applicable") {
        note = window.prompt("Why? (required)");
        if (!note) { load(); return; }
      }
      try { await api.reviewThreat(id, { key: sel.dataset.review, status: sel.value, note }); load(); } catch (err) { flash(err.message, "error"); load(); }
    }));
  }
  await load();
}
