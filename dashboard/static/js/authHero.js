// Shared branded background + tagline for the login and logout screens (the only two
// pages that render inside `.auth-page` - see style.css's `.auth-shell`/`.auth-hero`
// rules) - one definition so both pages stay visually identical instead of two
// independently-drifting copies of the same inline SVG.
//
// Two independent layers, deliberately: authHeroBackgroundHtml() is a full-bleed,
// absolutely-positioned network/scan-line graphic meant to sit behind BOTH the
// illustration half and the form half (see .auth-shell's own ::before aurora-gradient
// layer for the color underneath it) - this is what makes the page read as one
// continuous animated scene rather than "a nice graphic on the left, a plain card on
// the right" (the literal complaint this redesign responds to). authHeroHtml() is just
// the copy block (brand/tagline/points), unchanged in content, now with no background
// of its own since the shell provides one shared background for everything.
export function authHeroBackgroundHtml() {
  return `
    <svg class="auth-hero-art" viewBox="0 0 1000 700" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <g class="auth-hero-sweep" stroke="#7ea6f5" stroke-width="1.5" fill="none" stroke-opacity="0.55">
        <circle cx="330" cy="330" r="80"/>
        <circle cx="330" cy="330" r="140"/>
        <circle cx="330" cy="330" r="205"/>
        <circle cx="330" cy="330" r="275"/>
        <path d="M 330 330 L 330 55" stroke-dasharray="3 9"/>
      </g>

      <g class="auth-hero-nodes" fill="#7ea6f5">
        <circle class="auth-hero-node" cx="150" cy="180" r="3.5"/>
        <circle class="auth-hero-node" cx="480" cy="120" r="3.5"/>
        <circle class="auth-hero-node" cx="600" cy="300" r="3.5"/>
        <circle class="auth-hero-node" cx="130" cy="420" r="3.5"/>
        <circle class="auth-hero-node" cx="260" cy="560" r="3.5"/>
        <circle class="auth-hero-node" cx="500" cy="530" r="3.5"/>
        <circle class="auth-hero-node" cx="760" cy="180" r="3.5"/>
        <circle class="auth-hero-node" cx="820" cy="420" r="3.5"/>
        <circle class="auth-hero-node" cx="650" cy="560" r="3.5"/>
        <circle class="auth-hero-node" cx="900" cy="280" r="3.5"/>
      </g>
      <g stroke="#4d84f0" stroke-opacity="0.32">
        <line x1="150" y1="180" x2="330" y2="330"/>
        <line x1="480" y1="120" x2="330" y2="330"/>
        <line x1="600" y1="300" x2="330" y2="330"/>
        <line x1="130" y1="420" x2="330" y2="330"/>
        <line x1="260" y1="560" x2="330" y2="330"/>
        <line x1="500" y1="530" x2="330" y2="330"/>
        <line x1="600" y1="300" x2="760" y2="180"/>
        <line x1="600" y1="300" x2="820" y2="420"/>
        <line x1="500" y1="530" x2="650" y2="560"/>
        <line x1="760" y1="180" x2="900" y2="280"/>
        <line x1="820" y1="420" x2="900" y2="280"/>
      </g>
      <g class="auth-hero-pulse-line">
        <circle class="auth-hero-pulse-dot" r="4" fill="#bcd2fb">
          <animateMotion dur="3.2s" repeatCount="indefinite"
            path="M 330 330 L 600 300 L 760 180 L 900 280" />
        </circle>
      </g>

      <g transform="translate(280, 120) scale(1.55)" filter="url(#auth-hero-mark-glow)">
        <path d="M32 3.5 L57 13.5 V31 C57 46.5 46.5 57.5 32 61 C17.5 57.5 7 46.5 7 31 V13.5 Z" fill="#2f6fed" fill-opacity="0.9"/>
        <circle cx="27" cy="27" r="11" fill="none" stroke="#ffffff" stroke-width="3.6"/>
        <line x1="35.2" y1="35.2" x2="45" y2="45" stroke="#ffffff" stroke-width="4" stroke-linecap="round"/>
      </g>
      <defs>
        <filter id="auth-hero-mark-glow" x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="7" result="blur"/>
          <feColorMatrix in="blur" type="matrix"
            values="0 0 0 0 0.18  0 0 0 0 0.43  0 0 0 0 0.96  0 0 0 0.55 0"/>
          <feMerge>
            <feMergeNode/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
    </svg>`;
}

export function authHeroHtml() {
  return `
    <div class="auth-hero-copy">
      <div class="auth-hero-brand">VulnHunter</div>
      <p class="auth-hero-tagline">Vulnerability management that closes the loop — from first scan to a verified fix.</p>
      <ul class="auth-hero-points">
        <li>Findings ranked by real-world exploitability, using live CISA KEV and FIRST.org EPSS data</li>
        <li>Every remediation reviewed and approved by a human before it ships</li>
        <li>Anomaly detection that surfaces what a severity score alone would miss</li>
      </ul>
    </div>`;
}
