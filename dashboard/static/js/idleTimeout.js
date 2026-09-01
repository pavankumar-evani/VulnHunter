// Idle-session timeout - NIST SP 800-53 AC-11 ("Session Lock") and PCI-DSS
// Requirement 8.2.8 both call for automatically ending an idle authenticated session
// rather than leaving one open indefinitely on an unattended screen. 15 real minutes of
// no mouse/keyboard/scroll/touch activity anywhere in the app calls the same real
// api.authLogout() the account menu's "Log out" button calls, then lands on the
// dedicated /logout screen (see pages/logout.js) - a 60-second warning with a live
// countdown gives the user a chance to stay signed in first. This is a fixed default,
// not yet admin-configurable (that belongs with the still-to-be-built Admin Settings
// page) - 15 minutes sits in the middle of the range (15-30 min) common enterprise idle
// policies use.
import { api } from "./api.js";
import { getCurrentUser, setCurrentUser } from "./auth.js";
import { openModal, closeModal } from "./dom.js";

const IDLE_WARNING_MS = 14 * 60 * 1000;
const IDLE_LOGOUT_MS = 15 * 60 * 1000;
const CHECK_INTERVAL_MS = 5000;
const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"];

let lastActivityAt = Date.now();
let warningOpen = false;
let countdownIntervalId = null;

function dismissWarning() {
  warningOpen = false;
  if (countdownIntervalId) {
    clearInterval(countdownIntervalId);
    countdownIntervalId = null;
  }
  closeModal();
}

function markActive() {
  lastActivityAt = Date.now();
  if (warningOpen) dismissWarning();
}

async function doIdleLogout() {
  dismissWarning();
  await api.authLogout().catch(() => {});
  setCurrentUser(null);
  window.dispatchEvent(new CustomEvent("vulnhunter-auth-changed"));
  window.history.pushState({}, "", "/logout?reason=idle");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function showWarning() {
  warningOpen = true;
  const body = openModal(`
    <h2>Still there?</h2>
    <p class="subtitle">
      You've been idle for a while - for your security, you'll be signed out in
      <strong id="idle-countdown">60</strong> seconds.
    </p>
    <button type="button" class="secondary-button" id="idle-stay-button">Stay signed in</button>`);
  body.querySelector("#idle-stay-button").addEventListener("click", markActive);
  const countdownEl = body.querySelector("#idle-countdown");
  countdownIntervalId = setInterval(() => {
    const remainingMs = IDLE_LOGOUT_MS - (Date.now() - lastActivityAt);
    if (remainingMs <= 0) {
      doIdleLogout();
      return;
    }
    countdownEl.textContent = Math.ceil(remainingMs / 1000);
  }, 1000);
}

async function checkIdle() {
  if (window.location.pathname === "/login" || window.location.pathname === "/logout") return;
  const user = await getCurrentUser();
  if (!user) return;
  const idleMs = Date.now() - lastActivityAt;
  if (idleMs >= IDLE_LOGOUT_MS) {
    await doIdleLogout();
  } else if (idleMs >= IDLE_WARNING_MS && !warningOpen) {
    showWarning();
  }
}

export function initIdleTimeout() {
  ACTIVITY_EVENTS.forEach((evt) => window.addEventListener(evt, markActive, { passive: true }));
  setInterval(checkIdle, CHECK_INTERVAL_MS);
}
