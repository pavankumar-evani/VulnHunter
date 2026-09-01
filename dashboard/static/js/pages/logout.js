// The dedicated "you've been signed out" screen - previously, logging out (from the
// account dropdown, /profile, or an idle-session timeout - see ../idleTimeout.js)
// dropped straight back onto the bare /login form with no confirmation that anything
// had actually happened. The real logout API call already happened by the time this
// page renders (see auth.js's initAccountChip()/profile.js/idleTimeout.js) - this page
// only ever displays that fact and offers a way back in, it never calls
// api.authLogout() itself.
import { authHeroHtml } from "../authHero.js";

export const title = "Signed out";

export async function render(container) {
  const reason = new URLSearchParams(window.location.search).get("reason");
  const isIdle = reason === "idle";

  container.innerHTML = `
    <div class="auth-shell">
      ${authHeroHtml()}
      <div class="auth-form-panel">
        <div class="login-card">
          <div class="logout-icon">
            <svg viewBox="0 0 24 24" width="44" height="44" xmlns="http://www.w3.org/2000/svg">
              <circle cx="12" cy="12" r="11" fill="none" stroke="#2f6fed" stroke-width="1.6"/>
              <path d="M7.5 12.5 L10.3 15.3 L16.5 9" fill="none" stroke="#2f6fed" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <div class="login-brand" style="justify-content:center">
            <span>You've been signed out</span>
          </div>
          <p class="subtitle" style="text-align:center">
            ${isIdle
              ? "You were signed out automatically after a period of inactivity, for your security."
              : "Your session has ended. Any unsaved changes on the page you left were not submitted."}
          </p>
          <a class="secondary-button" style="display:block;text-align:center;text-decoration:none;margin-top:8px" href="/login" data-link>Sign in again</a>
        </div>
      </div>
    </div>`;
}
