// "Ask VulnHunter" - a free, real, deterministic "ask your data" search over the
// live queue, code-scan findings, and asset inventory (POST /api/search/ask, see
// remediation/search/query_engine.py). Deliberately NOT a chatbot and not an LLM: no
// external API call, no signup, no cost, no data leaves this machine, and - the real
// payoff of that - it can never hallucinate an answer. A pattern it doesn't recognize
// gets an honest "no confident match," never a guessed one. This is a different,
// complementary tool from the topbar's global search (search.js, a live type-ahead
// substring finder) - this one understands counts/filters ("how many critical KEV
// findings are breached") and chains real lookups (resolve a team/asset name, then
// filter by it), not just a flat ID/title match.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Ask VulnHunter";

const EXAMPLES = [
  "how many critical KEV findings are breached",
  "FIND-12",
  "CVE-2021-44228",
  "findings owned by team Platform",
  "WIN-DC01",
];

const INTENT_LABELS = {
  finding_lookup: "Finding lookup", cve_lookup: "CVE lookup", count: "Count",
  list: "List", asset_lookup: "Asset lookup", faq: "Documentation match",
  no_match: "No match", empty: "—",
};

function resultRowHtml(r) {
  // Results are either real finding-shaped records (id/title/severity) or a real
  // asset-shaped record (name/finding_count/risk_tier) - render whichever shape it is.
  if (r.id !== undefined && r.title !== undefined) {
    return `<tr>
      <td>${escapeHtml(r.id)}</td>
      <td class="wrap-cell">${escapeHtml(r.title || "")}</td>
      <td>${r.severity ? `<span class="badge badge-${String(r.severity).toLowerCase()}">${escapeHtml(r.severity)}</span>` : ""}</td>
    </tr>`;
  }
  if (r.name !== undefined) {
    return `<tr>
      <td>${escapeHtml(r.name)}</td>
      <td>${escapeHtml(r.highest_severity || "")}</td>
      <td>${r.risk_score ?? ""}</td>
    </tr>`;
  }
  return "";
}

function resultTableHtml(results) {
  if (!results || !results.length) return "";
  const isAssetShaped = results[0].name !== undefined && results[0].id === undefined;
  return `
    <div class="table-scroll" style="margin-top:10px">
      <table class="data-table">
        <thead><tr>
          ${isAssetShaped ? "<th>Asset</th><th>Highest Severity</th><th>Risk Score</th>" : "<th>ID</th><th>Title</th><th>Severity</th>"}
        </tr></thead>
        <tbody>${results.map(resultRowHtml).join("")}</tbody>
      </table>
    </div>`;
}

function answerHtml(result) {
  const intentBadge = `<span class="badge badge-outline">${escapeHtml(INTENT_LABELS[result.intent] || result.intent)}</span>`;
  const linkHtml = result.link
    ? `<p style="margin-top:10px"><a href="${escapeHtml(result.link)}" data-link>View in the app →</a></p>` : "";
  const faqHtml = result.matched_faq
    ? `<p class="filter-count" style="margin-top:6px">Closest matching FAQ entry: <a href="/faq" data-link>${escapeHtml(result.matched_faq.question)}</a></p>`
    : "";
  return `
    <div class="callout" id="ask-answer">
      ${intentBadge}
      <p style="margin:8px 0 0">${escapeHtml(result.answer)}</p>
      ${faqHtml}
      ${linkHtml}
      ${resultTableHtml(result.results)}
    </div>`;
}

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">
      Real, pattern-based search over this app's own live data - not a chatbot, not an
      LLM, no external API call, no cost. It answers by actually querying the live
      queue, code-scan findings, and asset inventory (or, for a general question, the
      real FAQ documentation) - a query it doesn't recognize gets an honest "no
      confident match," never a guessed answer.
    </p>

    <form class="run-form" id="ask-form">
      <label>Ask about a finding ID, CVE, asset, team, or a real count
        <input type="text" name="query" id="ask-input" placeholder="e.g. how many critical KEV findings are breached" autocomplete="off">
      </label>
      <button type="submit">Ask</button>
    </form>

    <p class="filter-count" style="margin:10px 0 4px">Try:</p>
    <div class="ask-examples">
      ${EXAMPLES.map((ex) => `<button type="button" class="link-button" data-example="${escapeHtml(ex)}">${escapeHtml(ex)}</button>`).join("")}
    </div>

    <div id="ask-result" style="margin-top:16px"></div>`;

  const form = container.querySelector("#ask-form");
  const input = container.querySelector("#ask-input");
  const resultEl = container.querySelector("#ask-result");

  async function runQuery(query) {
    input.value = query;
    resultEl.innerHTML = `<div class="empty-state">Searching real data…</div>`;
    try {
      const result = await api.searchAsk(query);
      resultEl.innerHTML = answerHtml(result);
    } catch (err) {
      resultEl.innerHTML = "";
      flash(err.message, "error");
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const query = input.value.trim();
    if (!query) return;
    runQuery(query);
  });

  container.querySelectorAll("[data-example]").forEach((btn) => {
    btn.addEventListener("click", () => runQuery(btn.dataset.example));
  });
}
