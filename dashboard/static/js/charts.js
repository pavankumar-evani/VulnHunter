// Lightweight, hand-rolled SVG bar/pie charts - zero new dependency, matching this
// repo's existing "no build step" constraint (there is no charting library anywhere
// in this codebase, and the only prior "chart-like" visual, the MITRE heat map in
// risk.js/aiVulnerabilities.js, is itself hand-rolled CSS/HTML, not a library). Colors
// come from the app's existing CSS custom properties (var(--brand-accent) etc.) so
// these charts theme with the rest of the app automatically, light or dark.
import { escapeHtml } from "./dom.js";

// 8-hue, fixed-order, CVD-validated categorical palette for NOMINAL data (team names,
// asset types, months, sub-categories - series with no inherent order). Defined as CSS
// custom properties in style.css (--chart-1..8, with dark-mode steps) so this
// automatically re-validates against whichever surface is active - see style.css's
// :root comment for the actual validator numbers. Never reorder these slots.
const PALETTE = [
  "var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)",
  "var(--chart-5)", "var(--chart-6)", "var(--chart-7)", "var(--chart-8)",
];

// Severity/priority tiers are ORDINAL/status data (a fixed, meaningful order), not
// nominal categories - they get the same reserved colors as this app's own
// badge-critical/high/medium/low classes (style.css) instead of a categorical hue, so a
// chart's "Critical" bar/slice always matches every Critical badge elsewhere on the same
// page. Deliberately not theme-switched (the badges themselves aren't either, today).
const STATUS_COLORS = { Critical: "#991b1b", High: "#9a3412", Medium: "#92400e", Low: "#1e40af" };

function colorFor(label, index) {
  return STATUS_COLORS[label] || PALETTE[index % PALETTE.length];
}

// data: [{label, value, detail?, href?, color?}, ...]. Renders vertical bars scaled to
// the max value, with the label and value printed below/above each bar - a plain,
// readable severity/category-count chart, not a general-purpose charting engine. Each
// bar gets its own color by default (Critical/High/Medium/Low via the shared status
// palette, anything else via the validated 8-hue categorical PALETTE, both defined
// above) - pass a per-item `color` to override one bar, or `barColor` to force every bar
// to one flat color (e.g. a single real series with no category meaning to encode).
// `detail` (optional extra text) feeds the app's existing shared JS tooltip
// (tooltip.js's document-level [data-tooltip] listener - NOT a CSS ::after, so this
// works fine on SVG shapes too) for a richer hover than the plain "label: value" a
// native <title> alone would give; `href` (optional) makes the bar navigate there on
// click via wireChartLinks() below - callers must call wireChartLinks(container) once
// after inserting this markup for click-to-navigate to actually wire up.
export function barChartSvg(data, { width = 420, height = 200, barColor = null } = {}) {
  const padding = { top: 20, right: 10, bottom: 34, left: 10 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;
  const max = Math.max(1, ...data.map((d) => d.value));
  const barGap = 10;
  const barW = data.length ? Math.max(8, (chartW - barGap * (data.length - 1)) / data.length) : chartW;

  const bars = data.map((d, i) => {
    const barH = (d.value / max) * chartH;
    const x = padding.left + i * (barW + barGap);
    const y = padding.top + (chartH - barH);
    const tooltipText = d.detail ? `${d.label}: ${d.value} - ${d.detail}` : `${d.label}: ${d.value}`;
    const clickable = d.href ? ` data-chart-href="${escapeHtml(d.href)}" tabindex="0"` : "";
    return `
      <g class="${d.href ? "chart-bar-group chart-bar-clickable" : "chart-bar-group"}" data-tooltip="${escapeHtml(tooltipText)}"${clickable}>
        <rect x="${x}" y="${y}" width="${barW}" height="${Math.max(barH, 1)}" rx="3" fill="${d.color || barColor || colorFor(d.label, i)}"></rect>
        <text x="${x + barW / 2}" y="${y - 5}" text-anchor="middle" class="chart-bar-value">${d.value}</text>
        <text x="${x + barW / 2}" y="${height - 12}" text-anchor="middle" class="chart-bar-label">${escapeHtml(truncateLabel(d.label))}</text>
      </g>`;
  }).join("");

  return `<svg class="chart-svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" role="img"
      aria-label="Bar chart of ${escapeHtml(data.map((d) => `${d.label} (${d.value})`).join(", "))}">${bars}</svg>`;
}

// Wires click-to-navigate for any chart element (bar/slice/legend row) carrying
// data-chart-href, produced by barChartSvg/pieChartSvg above - call once after
// inserting a chart's HTML into the DOM (same "wire after insert" convention as
// wireExportButtons/wireTopRankings/wirePagination elsewhere in this app). Uses
// pushState + a synthetic popstate (app.js's own router already listens for real
// popstate events) rather than a plain <a data-link> because SVGAElement.href
// returns an SVGAnimatedString, not a plain string - app.js's own [data-link] click
// delegation (new URL(link.href, ...)) would silently break on an SVG anchor.
export function wireChartLinks(root) {
  root.querySelectorAll("[data-chart-href]").forEach((el) => {
    const go = () => {
      const href = el.getAttribute("data-chart-href");
      window.history.pushState({}, "", href);
      window.dispatchEvent(new PopStateEvent("popstate"));
    };
    el.addEventListener("click", go);
    el.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
  });
}

function truncateLabel(label, max = 14) {
  const s = String(label);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

// data: [{label, value, detail?, href?, color?}, ...]. Simple donut/pie with a side
// legend - arcs computed via basic trig, no library. Slices below a visibility
// threshold still get a legend row (so small-but-real categories aren't silently
// dropped), just a thin sliver on the chart itself. `detail`/`href` behave exactly like
// barChartSvg's own (see its comment) - same shared tooltip.js hover, same
// wireChartLinks() click-to-navigate, on both the slice and its legend row.
export function pieChartSvg(data, { size = 180 } = {}) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 4;
  let angle = -Math.PI / 2; // start at 12 o'clock

  const slices = total > 0 ? data.map((d, i) => {
    const fraction = d.value / total;
    const startAngle = angle;
    const endAngle = angle + fraction * 2 * Math.PI;
    angle = endAngle;
    const color = d.color || colorFor(d.label, i);
    const tooltipText = d.detail ? `${d.label}: ${d.value} - ${d.detail}` : `${d.label}: ${d.value}`;
    const clickAttrs = d.href ? ` data-chart-href="${escapeHtml(d.href)}" tabindex="0"` : "";
    const cls = d.href ? "chart-slice-clickable" : "";
    if (fraction >= 0.9995) {
      // A single category holding ~100% renders as a full circle - an arc path with
      // an identical start/end point draws nothing, so this is a real edge case, not
      // a cosmetic one.
      return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${color}" class="${cls}" data-tooltip="${escapeHtml(tooltipText)}"${clickAttrs}></circle>`;
    }
    const x1 = cx + r * Math.cos(startAngle);
    const y1 = cy + r * Math.sin(startAngle);
    const x2 = cx + r * Math.cos(endAngle);
    const y2 = cy + r * Math.sin(endAngle);
    const largeArc = fraction > 0.5 ? 1 : 0;
    return `<path d="M${cx},${cy} L${x1},${y1} A${r},${r} 0 ${largeArc} 1 ${x2},${y2} Z" fill="${color}" class="${cls}" data-tooltip="${escapeHtml(tooltipText)}"${clickAttrs}></path>`;
  }).join("") : "";

  const legend = data.map((d, i) => {
    const tooltipText = d.detail ? `${d.label}: ${d.value} - ${d.detail}` : "";
    const clickAttrs = d.href ? ` data-chart-href="${escapeHtml(d.href)}" tabindex="0"` : "";
    const cls = d.href ? "chart-legend-row chart-legend-row-clickable" : "chart-legend-row";
    return `
    <div class="${cls}"${tooltipText ? ` data-tooltip="${escapeHtml(tooltipText)}"` : ""}${clickAttrs}>
      <span class="chart-legend-swatch" style="background:${d.color || colorFor(d.label, i)}"></span>
      ${escapeHtml(d.label)} <span class="muted">(${d.value})</span>
    </div>`;
  }).join("");

  return `
    <div class="chart-pie-wrap">
      <svg class="chart-svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg"
        role="img" aria-label="Pie chart of ${escapeHtml(data.map((d) => `${d.label} (${d.value})`).join(", "))}">${slices}</svg>
      <div class="chart-legend">${legend}</div>
    </div>`;
}

// Groups an array of items by a key function into [{label, value}, ...] pairs sorted
// by value descending - the common shape both chart functions above expect.
export function countBy(items, keyFn) {
  const counts = new Map();
  for (const item of items) {
    const key = keyFn(item) || "Unknown";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value);
}
