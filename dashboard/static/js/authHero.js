// Shared branded illustration + tagline for the login and logout screens (the only two
// pages that render inside `.auth-page` - see style.css's `.auth-shell`/`.auth-hero`
// rules) - one definition so both pages stay visually identical instead of two
// independently-drifting copies of the same inline SVG.
export function authHeroHtml() {
  return `
    <div class="auth-hero">
      <svg class="auth-hero-art" viewBox="0 0 480 460" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <defs>
          <radialGradient id="auth-hero-glow" cx="50%" cy="42%" r="60%">
            <stop offset="0%" stop-color="#2f6fed" stop-opacity="0.35"/>
            <stop offset="100%" stop-color="#2f6fed" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <rect x="0" y="0" width="480" height="460" fill="url(#auth-hero-glow)"/>

        <g stroke="#4d84f0" stroke-opacity="0.35" fill="none">
          <circle cx="240" cy="230" r="90"/>
          <circle cx="240" cy="230" r="140"/>
          <circle cx="240" cy="230" r="190"/>
        </g>
        <g class="auth-hero-sweep" stroke="#7ea6f5" stroke-width="2" fill="none" stroke-opacity="0.8">
          <path d="M 240 230 L 240 40" stroke-dasharray="4 10"/>
        </g>

        <g class="auth-hero-nodes" fill="#7ea6f5">
          <circle class="auth-hero-node" cx="95" cy="120" r="4"/>
          <circle class="auth-hero-node" cx="380" cy="95" r="4"/>
          <circle class="auth-hero-node" cx="415" cy="270" r="4"/>
          <circle class="auth-hero-node" cx="70" cy="340" r="4"/>
          <circle class="auth-hero-node" cx="150" cy="410" r="4"/>
          <circle class="auth-hero-node" cx="360" cy="400" r="4"/>
        </g>
        <g stroke="#4d84f0" stroke-opacity="0.4">
          <line x1="95" y1="120" x2="240" y2="230"/>
          <line x1="380" y1="95" x2="240" y2="230"/>
          <line x1="415" y1="270" x2="240" y2="230"/>
          <line x1="70" y1="340" x2="240" y2="230"/>
          <line x1="150" y1="410" x2="240" y2="230"/>
          <line x1="360" y1="400" x2="240" y2="230"/>
        </g>

        <g transform="translate(190, 165) scale(1.55)">
          <path d="M32 3.5 L57 13.5 V31 C57 46.5 46.5 57.5 32 61 C17.5 57.5 7 46.5 7 31 V13.5 Z" fill="#2f6fed"/>
          <circle cx="27" cy="27" r="11" fill="none" stroke="#ffffff" stroke-width="3.6"/>
          <line x1="35.2" y1="35.2" x2="45" y2="45" stroke="#ffffff" stroke-width="4" stroke-linecap="round"/>
        </g>
      </svg>

      <div class="auth-hero-copy">
        <div class="auth-hero-brand">VulnHunter</div>
        <p class="auth-hero-tagline">Real-time vulnerability intelligence — from first scan to verified fix.</p>
        <ul class="auth-hero-points">
          <li>Live CISA KEV + FIRST.org EPSS threat intel</li>
          <li>Human-approved, change-managed remediation</li>
          <li>Real, live-trained ML insights - not keyword heuristics</li>
        </ul>
      </div>
    </div>`;
}
