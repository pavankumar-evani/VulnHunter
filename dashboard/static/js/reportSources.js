// Report sources: the threat-intelligence report watcher's admin panel on the Threat Intelligence page. Add, test, poll, disable and remove the feeds
// (RSS, Atom, JSON) and TAXII 2.1 collections Quanta reads reports from; see each source's last poll, how many reports it has given and its last error.
// The watcher only READS. A relevant report creates a hunt (and a hunt-engine suggestion); nothing is ever run on a SIEM without a person confirming it.
// Admin only: for anyone else the API answers 403 and the panel is not shown.
import { api } from "./api.js";
import { escapeHtml, flash } from "./dom.js";

function rowHtml(s) {
  const status = s.last_status === "error" ? `<span class="badge badge-high" title="${escapeHtml(s.last_error || "")}">error</span>` : s.last_status ? `<span class="badge badge-low">${escapeHtml(s.last_status)}</span>` : `<span class="muted">never polled</span>`;
  const where = s.kind === "feed" ? escapeHtml(s.url || "") : `TAXII connection #${s.connection_id}, collection ${escapeHtml(s.collection_id || "")}`;
  return `<tr data-id="${s.id}">
    <td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.kind)}</td><td class="wrap-cell">${where}</td>
    <td>${s.enabled ? "on" : "off"}</td><td>${escapeHtml(s.last_poll_at || "-")}</td><td>${status}${s.last_error ? `<div class="muted" style="font-size:.8rem">${escapeHtml(s.last_error)}</div>` : ""}</td>
    <td>${s.last_new ?? 0} new / ${s.total_reports} total</td>
    <td><button type="button" data-act="test">Test</button> <button type="button" data-act="poll">Poll now</button> <button type="button" data-act="toggle">${s.enabled ? "Disable" : "Enable"}</button> <button type="button" data-act="delete">Remove</button></td>
  </tr>`;
}

export async function mountReportSources(container) {
  let data;
  try {
    data = await api.intelSources();
  } catch {
    return; // not an administrator, or the feature is not licensed: show nothing
  }
  const host = document.createElement("section");
  host.className = "sx-panel";
  host.id = "report-sources";
  container.appendChild(host);

  async function draw() {
    data = await api.intelSources();
    host.innerHTML = `
      <h2>Report sources</h2>
      <p class="subtitle">New reports from the feeds below are stored once, scored against your estate, and (at or above the "${escapeHtml(data.hunt_threshold || "none")}" threshold) turned into a hunt and a hunt-engine suggestion,
        with the reason shown on the report. The watcher is ${data.watch_enabled ? `on, polling every ${data.interval_minutes} minutes` : "switched off (QUANTA_INTEL_WATCH=false)"}; with no source added it does nothing. ${escapeHtml(data.note)}</p>
      ${data.sources.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>Kind</th><th>Address</th><th>Polling</th><th>Last poll</th><th>Status</th><th>Reports</th><th></th></tr></thead><tbody>${data.sources.map(rowHtml).join("")}</tbody></table></div>`
        : `<p class="muted">No report source yet. Add a public feed address (https) or a TAXII collection.</p>`}
      <form id="rs-add" class="run-form">
        <label>Name <input name="name" required maxlength="80" placeholder="CISA advisories"></label>
        <label>Kind <select name="kind"><option value="feed">RSS, Atom or JSON feed</option><option value="taxii">TAXII 2.1 collection</option></select></label>
        <label class="rs-feed">Feed address <input name="url" size="44" placeholder="https://example.com/feed.xml"></label>
        <label class="rs-taxii" hidden>TAXII connection id <input name="connection_id" size="6" placeholder="from Connections"></label>
        <label class="rs-taxii" hidden>Collection id <input name="collection_id" size="30"></label>
        <button type="submit">Add source</button>
      </form>
      <div id="rs-result" class="muted"></div>`;
    const kind = host.querySelector("select[name=kind]");
    kind.addEventListener("change", () => {
      host.querySelectorAll(".rs-feed").forEach((e) => { e.hidden = kind.value !== "feed"; });
      host.querySelectorAll(".rs-taxii").forEach((e) => { e.hidden = kind.value !== "taxii"; });
    });
    host.querySelector("#rs-add").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const f = ev.target;
      try {
        await api.intelSourceAdd({ name: f.name.value, kind: f.kind.value, url: f.url.value || null, connection_id: f.connection_id.value ? Number(f.connection_id.value) : null, collection_id: f.collection_id.value || null });
        flash("Source added", "success");
        await draw();
      } catch (err) {
        host.querySelector("#rs-result").textContent = err.message;
      }
    });
    host.querySelectorAll("tr[data-id] button").forEach((btn) => btn.addEventListener("click", async () => {
      const id = Number(btn.closest("tr").dataset.id);
      const out = host.querySelector("#rs-result");
      try {
        if (btn.dataset.act === "test") {
          const r = await api.intelSourceTest(id);
          out.textContent = r.collections ? `Reachable. Collections: ${r.collections.map((c) => `${c.title || c.id} (${c.id})`).join("; ") || "none readable"}` : `Reachable: ${r.format}, ${r.items} item(s); newest: ${r.newest || "none"}`;
        } else if (btn.dataset.act === "poll") {
          const pre = await api.intelSourcePoll(id, false);
          if (!window.confirm(pre.message)) return;
          const r = await api.intelSourcePoll(id, true);
          out.textContent = r.status === "error" ? `Poll failed: ${r.error}` : `Polled: ${r.new} new report(s), ${r.hunts_created} hunt(s) created, ${r.seen} already known.`;
          await draw();
        } else if (btn.dataset.act === "toggle") {
          const row = data.sources.find((s) => s.id === id);
          await api.intelSourceEnabled(id, !row.enabled);
          await draw();
        } else if (btn.dataset.act === "delete") {
          if (!window.confirm("Remove this source? Reports it already stored are kept.")) return;
          await api.intelSourceDelete(id);
          await draw();
        }
      } catch (err) {
        out.textContent = err.message;
      }
    }));
  }
  await draw();
}
