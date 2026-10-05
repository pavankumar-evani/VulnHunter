// Secure design assistant: answer a few questions about a system you are about to build and get the security requirements, the pipeline controls that
// enforce them and the threat questions to ask. A starting list for a design review, not a threat model.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Secure Design";

export async function render(container) {
  let qs;
  try { qs = (await api.designQuestions()).questions; } catch (err) { container.innerHTML = `<p class="callout callout-warn">${escapeHtml(err.message)}</p>`; return; }
  container.innerHTML = `<p class="subtitle">Describe what you are about to build. Each answer that applies raises the security requirements a reviewer would ask for, names the DevSecOps controls that enforce them, and lists the threat questions to take into the design review. It is rule-based, so the same answers always give the same list, and every requirement shows the standard it draws on. Leave a question unanswered if you do not know: it is then not counted as "no".</p>
    <form id="df" class="run-form" style="max-width:none"><label>System name<input name="name" value="" placeholder="orders-service" maxlength="100"></label>
    <div class="form-grid">${qs.map((q) => `<label>${escapeHtml(q.label)}<select name="${escapeHtml(q.id)}"><option value="">Do not know</option>${(q.type === "yesno" ? ["yes", "no"] : q.options).map((o) => `<option>${escapeHtml(o)}</option>`).join("")}</select></label>`).join("")}</div>
    <p><button type="submit" class="btn-primary">Get the requirements</button></p></form><div id="out"></div>`;
  container.querySelector("#df").addEventListener("submit", async (e) => {
    e.preventDefault();
    const answers = {};
    qs.forEach((q) => { const v = e.target.elements[q.id].value; if (v) answers[q.id] = v; });
    const name = e.target.elements.name.value.trim() || "the system";
    try {
      const r = await api.designAssess({ answers, name });
      const group = (pr, label) => {
        const rs = r.requirements.filter((x) => x.priority === pr);
        return rs.length ? `<h3>${label}</h3>${rs.map((x) => `<div class="card" style="border:1px solid var(--border);border-radius:8px;padding:8px 14px;margin:8px 0"><strong>${escapeHtml(x.requirement)}</strong><br><span class="muted">${escapeHtml(x.why)}</span>
          <br>${x.asvs ? `<span class="badge badge-outline">OWASP ASVS 4.0 ${escapeHtml(x.asvs)}</span> ` : ""}${x.controls.map((c) => `<span class="badge badge-outline">${escapeHtml(c.title)}</span>`).join(" ")}</div>`).join("")}` : "";
      };
      container.querySelector("#out").innerHTML = r.requirements.length ? `${group("must", "Required")}${group("should", "Recommended")}
        <h3>Questions for the threat model</h3><ul class="guidance-list">${r.threat_prompts.map((t) => `<li><strong>${escapeHtml(t.name)}</strong>: ${escapeHtml(t.prompt)}</li>`).join("")}</ul>
        <h3>Pipeline controls to put in place</h3><p>${r.controls.map((c) => `<span class="badge badge-outline">${escapeHtml(c.title)} <span class="muted">(${escapeHtml(c.stage)})</span></span>`).join(" ")}</p>
        <p class="muted">See where a repository stands against these controls on the <a href="/devsecops" data-link>DevSecOps</a> page, and model the design on <a href="/threat-models" data-link>Threat Models</a>. ${r.unanswered.length ? `${r.unanswered.length} question(s) were not answered. ` : ""}${escapeHtml(r.note)}</p>
        <p><button type="button" class="btn-primary" id="md">Download as Markdown</button></p>` : '<p class="callout">None of the rules apply to those answers. Answer more questions, or answer "yes" where the system does that.</p>';
      const md = container.querySelector("#md");
      if (md) md.addEventListener("click", async () => {
        const res = await fetch("/api/secure-design/assess?format=markdown", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ answers, name }) });
        const blob = new Blob([await res.text()], { type: "text/markdown" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `security-requirements-${name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.md`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
    } catch (err) { flash(err.message, "error"); }
  });
}
