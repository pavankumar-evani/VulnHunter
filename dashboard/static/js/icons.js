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
};

export function icon(name, size = 18) {
  const body = ICONS[name] || ICONS.dashboard;
  return `<svg class="icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" ` +
    `stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" ` +
    `xmlns="http://www.w3.org/2000/svg">${body}</svg>`;
}
