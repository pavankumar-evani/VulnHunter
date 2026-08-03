// A small, consistent stroke-icon set (20x20, currentColor) used across the nav and
// KPI cards - replaces the earlier unicode-glyph placeholders with real vector icons.
// Hand-drawn simple shapes, no external icon library / CDN dependency.

const ICONS = {
  dashboard: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  scan: '<circle cx="10" cy="10" r="6.5"/><line x1="14.8" y1="14.8" x2="20" y2="20"/>',
  queue: '<line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="14" y2="18"/>',
  plan: '<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 2.5h6a1 1 0 011 1V5H8V3.5a1 1 0 011-1z"/><path d="M8.5 12l2.2 2.2L15.5 10"/>',
  rules: '<line x1="4" y1="6" x2="20" y2="6"/><circle cx="9" cy="6" r="2"/><line x1="4" y1="12" x2="20" y2="12"/><circle cx="15" cy="12" r="2"/><line x1="4" y1="18" x2="20" y2="18"/><circle cx="11" cy="18" r="2"/>',
  servicenow: '<path d="M8 16a5 5 0 010-10h1"/><path d="M16 8a5 5 0 010 10h-1"/><polyline points="6 3.5 8.5 6 6 8.5"/><polyline points="18 15.5 15.5 18 18 20.5"/>',
  run: '<circle cx="12" cy="12" r="9"/><polygon points="10 8.5 16 12 10 15.5"/>',
  reports: '<rect x="4" y="3" width="16" height="18" rx="2"/><line x1="8" y1="17" x2="8" y2="13"/><line x1="12" y1="17" x2="12" y2="9"/><line x1="16" y1="17" x2="16" y2="11"/>',
  ai: '<path d="M12 3l1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6z"/><path d="M18.5 15l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8z"/>',
  support: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.2"/><line x1="5.2" y1="5.2" x2="9.3" y2="9.3"/><line x1="18.8" y1="5.2" x2="14.7" y2="9.3"/><line x1="5.2" y1="18.8" x2="9.3" y2="14.7"/><line x1="18.8" y1="18.8" x2="14.7" y2="14.7"/>',
  faq: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.2a2.5 2.5 0 014.9.6c0 1.7-2.4 1.9-2.4 3.5"/><circle cx="12" cy="16.6" r="0.6" fill="currentColor" stroke="none"/>',
  tenant: '<path d="M4 21V6l6-3 6 3v15"/><path d="M16 21v-9l4 2v7"/><line x1="8" y1="9" x2="8" y2="9.01"/><line x1="8" y1="13" x2="8" y2="13.01"/><line x1="8" y1="17" x2="8" y2="17.01"/>',
  clock: '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15.5 14"/>',
  exception: '<path d="M12 3l8 4v5c0 5-3.4 7.8-8 9-4.6-1.2-8-4-8-9V7z"/><line x1="12" y1="8" x2="12" y2="13"/><circle cx="12" cy="16" r="0.6" fill="currentColor" stroke="none"/>',
  assets: '<rect x="3" y="4" width="18" height="5" rx="1.2"/><rect x="3" y="10.5" width="18" height="5" rx="1.2"/><rect x="3" y="17" width="18" height="3.5" rx="1.2"/><line x1="6.5" y1="6.5" x2="6.5" y2="6.5"/><line x1="6.5" y1="13" x2="6.5" y2="13"/>',
  infra: '<rect x="4" y="3.5" width="16" height="5" rx="1"/><rect x="4" y="10" width="16" height="5" rx="1"/><rect x="4" y="16.5" width="16" height="4" rx="1"/><circle cx="7.3" cy="6" r="0.6" fill="currentColor" stroke="none"/><circle cx="7.3" cy="12.5" r="0.6" fill="currentColor" stroke="none"/>',
  appsec: '<path d="M12 3l7 3v5.5c0 5-3.3 7.7-7 8.7-3.7-1-7-3.7-7-8.7V6z"/><path d="M8.7 12l2.3 2.3 4.3-4.6"/>',
  sca: '<polygon points="12 4 20 8.3 12 12.6 4 8.3"/><polyline points="4 13.8 12 18 20 13.8"/>',
  certmgmt: '<circle cx="12" cy="9.3" r="5.3"/><path d="M8.6 13.7L7 21l5-2.6 5 2.6-1.6-7.3"/>',
  secrets: '<circle cx="7.8" cy="8.2" r="3.8"/><line x1="10.6" y1="11" x2="20" y2="20.4"/><line x1="15.3" y1="15.7" x2="18" y2="13"/><line x1="17.3" y1="17.7" x2="20" y2="15"/>',
  dast: '<line x1="12" y1="19" x2="12" y2="8.5"/><path d="M6.5 19a5.5 5.5 0 0111 0"/><path d="M3 19a9 9 0 0118 0"/><circle cx="12" cy="19" r="1.1" fill="currentColor" stroke="none"/>',
  search: '<circle cx="10.5" cy="10.5" r="7"/><line x1="15.5" y1="15.5" x2="20.5" y2="20.5"/>',
  bell: '<path d="M6 10.5a6 6 0 0112 0v4.2l1.6 2.6H4.4L6 14.7z"/><path d="M9.6 19a2.4 2.4 0 004.8 0"/>',
  jira: '<rect x="4" y="4" width="7" height="7" rx="1.3"/><rect x="13" y="4" width="7" height="7" rx="1.3"/><rect x="8.5" y="13" width="7" height="7" rx="1.3"/>',
  splunk: '<path d="M4 19V9M9.5 19V5M15 19v-8M20 19v-4"/>',
  xdr: '<path d="M4 12h4l2-6 4 12 2-6h4"/>',
  risk: '<path d="M12 3l9 16H3z"/><line x1="12" y1="9.5" x2="12" y2="14"/><circle cx="12" cy="17" r="0.6" fill="currentColor" stroke="none"/>',
  infoblox: '<circle cx="12" cy="12" r="8.5"/><line x1="3.5" y1="12" x2="20.5" y2="12"/><path d="M12 3.5c3 3 3 14 0 17M12 3.5c-3 3-3 14 0 17"/>',
  axonius: '<circle cx="12" cy="12" r="2.4"/><circle cx="4.5" cy="4.5" r="1.7"/><circle cx="19.5" cy="4.5" r="1.7"/><circle cx="4.5" cy="19.5" r="1.7"/><circle cx="19.5" cy="19.5" r="1.7"/><line x1="5.8" y1="5.8" x2="10.1" y2="10.1"/><line x1="18.2" y1="5.8" x2="13.9" y2="10.1"/><line x1="5.8" y1="18.2" x2="10.1" y2="13.9"/><line x1="18.2" y1="18.2" x2="13.9" y2="13.9"/>',
  adaptor: '<rect x="3" y="9" width="6.5" height="6" rx="1.2"/><rect x="14.5" y="9" width="6.5" height="6" rx="1.2"/><line x1="9.5" y1="12" x2="14.5" y2="12"/><line x1="6" y1="9" x2="6" y2="5.5"/><line x1="18" y1="9" x2="18" y2="5.5"/>',
  sidebarPanel: '<rect x="3" y="4" width="18" height="16" rx="2"/><line x1="9.5" y1="4" x2="9.5" y2="20"/>',
  pin: '<path d="M12 21s7-7.2 7-12.2A7 7 0 105 8.8C5 13.8 12 21 12 21z"/><circle cx="12" cy="8.8" r="2.4"/>',
  container: '<rect x="3" y="7" width="18" height="12" rx="1"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="8" y1="7" x2="8" y2="19"/><line x1="16" y1="7" x2="16" y2="19"/>',
  api: '<polyline points="8 6 3 12 8 18"/><polyline points="16 6 21 12 16 18"/>',
};

export function icon(name, size = 18) {
  const body = ICONS[name] || ICONS.dashboard;
  return `<svg class="icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" ` +
    `stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" ` +
    `xmlns="http://www.w3.org/2000/svg">${body}</svg>`;
}
