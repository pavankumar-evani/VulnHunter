// A persistent footer shown at the bottom of every page's scrollable content (shell's
// #page-footer, a sibling of #app - same "survives client-side navigation" pattern as
// flash-container/threat-tip-banner). Real, live-computed counts (from /api/status),
// not decorative filler, plus quick links to the pages that answer "is this real /
// what does this actually cover" - the FAQ, Support, and the README's scope section.
import { api } from "./api.js";
import { getCurrentUser } from "./auth.js";

export function initPageFooter() {
  const root = document.getElementById("page-footer");
  if (!root) return;

  async function render() {
    root.innerHTML = "";
    if (!(await getCurrentUser())) return; // keep the login page clean

    let status;
    try {
      status = await api.status();
    } catch {
      root.innerHTML = "";
      return;
    }

    root.innerHTML = `
      <div class="page-footer-inner">
        <span>
          Tracking <strong>${status.vulnhunt_findings}</strong> code finding(s) and
          <strong>${status.remediation_findings}</strong> infra/app finding(s) ·
          <strong>${status.remediation_playbooks}</strong> playbook(s) generated
        </span>
        <span class="page-footer-links">
          <a href="/faq" data-link>FAQ</a>
          <a href="/support" data-link>Support</a>
          <a href="/priority-rules" data-link>Priority Rules</a>
          <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/dashboard/README.md" target="_blank" rel="noopener">Scope &amp; limitations &#8599;</a>
        </span>
      </div>`;
  }

  render();
  window.addEventListener("vulnhunter-auth-changed", render);
}
