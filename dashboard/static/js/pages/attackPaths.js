// Attack Chains: groups findings that share an asset into entry -> pivot -> impact
// chains, using each finding's already-tagged MITRE ATT&CK tactic
// (remediation/enrichment/attack_chains.py, built on attack_mapping.py's existing
// tagging - see that module's own docstring for the heuristic, not-runtime-validated
// caveat this page inherits). The point: a pivot finding is worth prioritizing
// specifically because remediating it breaks every chain it sits in, even when the
// chain's entry and impact findings both stay open.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { openFindingDetail } from "../findingDetail.js";
import { paginate, paginationHtml, wirePagination, DEFAULT_PAGE_SIZE } from "../pagination.js";

export const title = "Attack Chains";

function stageChipsHtml(stageFindings, stageClass) {
  if (!stageFindings.length) return `<span class="muted">—</span>`;
  return stageFindings.map((f) => `
    <button type="button" class="link-button finding-id-link attack-stage-chip attack-stage-${stageClass}" data-finding-id="${escapeHtml(f.id)}">
      <span class="badge badge-priority-medium">${escapeHtml(f.technique_id || "?")}</span>
      ${escapeHtml(f.title)}
    </button>`).join("<br>");
}

function chainCardHtml(chain) {
  return `
    <div class="card attack-chain-card" style="margin-bottom:14px">
      <h4 style="margin:0 0 10px">${escapeHtml(chain.asset_name)}</h4>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th style="width:33%">Entry</th><th style="width:34%">Pivot — fix this to break the chain</th><th style="width:33%">Impact</th></tr></thead>
          <tbody>
            <tr>
              <td class="wrap-cell">${stageChipsHtml(chain.entry, "entry")}</td>
              <td class="wrap-cell">${stageChipsHtml(chain.pivots, "pivot")}</td>
              <td class="wrap-cell">${stageChipsHtml(chain.impact, "impact")}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [{ chains }, queue] = await Promise.all([api.attackPaths(), api.queue()]);
  const findingById = new Map(queue.findings.map((f) => [f.id, f]));

  const totalPivots = chains.reduce((sum, c) => sum + c.pivots.length, 0);

  let page = 1;

  function renderCards() {
    const paged = paginate(chains, page, DEFAULT_PAGE_SIZE);
    page = paged.page;
    const body = container.querySelector("#attack-paths-body");
    body.innerHTML = paged.rows.length
      ? paged.rows.map(chainCardHtml).join("")
      : `<div class="empty-state">No attack chains found — no asset currently has both an entry-stage and an impact-stage finding tagged.</div>`;
    const paginationEl = container.querySelector("#attack-paths-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
  }

  container.innerHTML = `
    <p class="subtitle">
      Findings that share an asset, chained by their already-tagged MITRE ATT&amp;CK tactic into
      entry &rarr; pivot &rarr; impact - a heuristic correlation across this asset's own findings
      (built on the same tactic tagging shown on every finding's "MITRE ATT&amp;CK" row), not a
      runtime-validated or exploit-proven attack path. An asset only appears here once it has both
      an entry-stage and an impact-stage finding tagged.
    </p>

    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-value">${chains.length}</div><div class="kpi-label">Attack chains found</div></div>
      <div class="kpi-card kpi-warn"><div class="kpi-value">${totalPivots}</div><div class="kpi-label">Pivot findings — fix these first</div></div>
    </div>

    <div id="attack-paths-body"></div>
    <div id="attack-paths-pagination"></div>`;

  renderCards();

  wirePagination(container, (p) => { page = p; renderCards(); });

  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".finding-id-link");
    if (!btn) return;
    const f = findingById.get(btn.dataset.findingId);
    if (f) openFindingDetail(f);
  });
}
