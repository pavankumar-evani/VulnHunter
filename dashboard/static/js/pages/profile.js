import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { getCurrentUser, setCurrentUser } from "../auth.js";

export const title = "Profile";

export async function render(container) {
  const user = await getCurrentUser(true);
  if (!user) {
    window.history.pushState({}, "", "/login?redirect=/profile");
    window.dispatchEvent(new PopStateEvent("popstate"));
    return;
  }

  container.innerHTML = `
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-value" style="font-size:1.1rem">${escapeHtml(user.name || user.email)}</div>
        <div class="kpi-label">Name</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="font-size:1.1rem">${escapeHtml(user.email)}</div>
        <div class="kpi-label">Email</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="font-size:1.1rem;text-transform:capitalize">${escapeHtml(user.role)}</div>
        <div class="kpi-label">Role</div>
      </div>
    </div>

    <div class="callout">
      Role determines which mutation actions the server actually allows - <strong>admin</strong>
      can send real ServiceNow/Jira/Splunk requests, run a real (paid) pipeline, ask AI for
      real (paid) responses, edit priority rules, and revoke exceptions. Both roles can
      create exceptions and edit asset owner/facing metadata. Every read-only page (Queue,
      Code Scan, Reports, etc.) stays open regardless of login - see the FAQ for the full
      scope note on what this MVP does and doesn't gate.
    </div>

    <h2>Change password</h2>
    <form class="run-form" id="password-form">
      <label>New password (min. 8 characters)<input type="password" name="new_password" minlength="8" required></label>
      <button type="submit">Change password</button>
    </form>

    <button type="button" class="secondary-button" id="logout-button" style="margin-top:20px">Log out</button>`;

  container.querySelector("#password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;
    try {
      await api.authChangePassword(form.new_password.value);
      flash("Password changed.", "success");
      form.reset();
    } catch (err) {
      flash(err.message || "Could not change password", "error");
    }
  });

  container.querySelector("#logout-button").addEventListener("click", async () => {
    await api.authLogout();
    setCurrentUser(null);
    window.dispatchEvent(new CustomEvent("vulnhunter-auth-changed"));
    window.history.pushState({}, "", "/login");
    window.dispatchEvent(new PopStateEvent("popstate"));
  });
}
