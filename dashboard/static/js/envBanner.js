// The environment banner. DEV and TEST show a persistent coloured strip with the environment name and version, so nobody
// mistakes a build-and-try instance for production. PROD shows nothing here (the version is in the footer), except a clear
// strip when simulated data has been enabled on purpose.
import { api } from "./api.js";

// Pure: what, if anything, to show for the `environment` object of /api/status.
export function bannerFor(env) {
  if (!env || !env.environment) return null;
  const v = env.version ? ` v${env.version}` : "";
  if (env.environment === "invalid") return { cls: "env-banner-invalid", text: "INVALID QUANTA_ENV" };
  if (env.environment === "dev") return { cls: "env-banner-dev", text: `DEV${v} - development build, not for real data` };
  if (env.environment === "test") return { cls: "env-banner-test", text: `TEST${v} - verification environment` };
  if (env.environment === "prod" && env.simulation_allowed) return { cls: "env-banner-sim", text: "SIMULATED DATA ENABLED - the connectors on this site replay recorded responses" };
  return null;
}

export function initEnvBanner() {
  async function render() {
    let el = document.getElementById("env-banner");
    let env = null;
    try { env = (await api.status()).environment; } catch { env = null; }
    const b = bannerFor(env);
    if (!b) { if (el) el.remove(); return; }
    if (!el) {
      el = document.createElement("div");
      el.id = "env-banner";
      el.setAttribute("role", "status");
      document.body.prepend(el);
    }
    el.className = `env-banner ${b.cls}`;
    el.textContent = b.text;
  }
  render();
  window.addEventListener("quanta-auth-changed", render);
}
