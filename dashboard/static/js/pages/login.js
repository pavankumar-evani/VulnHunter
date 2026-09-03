import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { setCurrentUser } from "../auth.js";
import { authHeroBackgroundHtml, authHeroHtml } from "../authHero.js";

export const title = "Sign in";

function goHome() {
  const redirect = new URLSearchParams(window.location.search).get("redirect") || "/";
  window.history.pushState({}, "", redirect);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export async function render(container) {
  let oidc = { enabled: false, provider_name: null };
  try {
    oidc = await api.authOidcConfig();
  } catch {
    // If this call fails for any reason, fail closed - just hide the SSO button.
  }

  container.innerHTML = `
    <div class="auth-shell">
      <div class="auth-hero-background" aria-hidden="true">${authHeroBackgroundHtml()}</div>
      <div class="auth-hero">${authHeroHtml()}</div>
      <div class="auth-form-panel">
        <div class="login-card">
          <div class="login-brand">
            <svg viewBox="0 0 64 64" width="40" height="40" xmlns="http://www.w3.org/2000/svg">
              <path d="M32 4 L56.5 18 L56.5 46 L32 60 L7.5 46 L7.5 18 Z" fill="#2f6fed"/>
              <circle cx="32" cy="32" r="11" fill="none" stroke="#ffffff" stroke-width="3.6"/>
              <path d="M32 20V16M32 44V48M20 32H16M44 32H48" fill="none" stroke="#ffffff" stroke-width="4" stroke-linecap="round"/>
            </svg>
            <span>VulnHunter</span>
          </div>
          <p class="subtitle" style="margin:-16px 0 22px">Sign in to your account</p>

          ${oidc.enabled ? `
            <a class="secondary-button sso-button" style="display:flex;align-items:center;justify-content:center;gap:8px;text-decoration:none" href="/api/auth/oidc/login">
              Continue with ${escapeHtml(oidc.provider_name)}
            </a>
            <div class="auth-divider"><span>or sign in with email</span></div>
          ` : ``}

          <form class="run-form" id="login-form">
            <label>Email<input type="email" name="email" required autocomplete="username"></label>
            <label>Password<input type="password" name="password" required autocomplete="current-password"></label>
            <button type="submit">Sign in</button>
          </form>

          <div class="callout" style="margin-top:18px">
            This is a local demo build. Seed credentials are documented in
            <code>dashboard/README.md</code> — replace them before any real deployment.
          </div>
        </div>
      </div>
    </div>`;

  const form = container.querySelector("#login-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api.authLogin(form.email.value.trim(), form.password.value);
      setCurrentUser(result.user);
      window.dispatchEvent(new CustomEvent("vulnhunter-auth-changed"));
      goHome();
    } catch (err) {
      flash(err.message || "Login failed", "error");
    }
  });
}
