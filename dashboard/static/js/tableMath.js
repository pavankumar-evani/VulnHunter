// The arithmetic behind the shared table (ui.js dataTable): sorting, virtual-window maths, CSV, sparkline geometry.
// Pure (no DOM) so it is tested under Node (tests/test_ui_kit_js.py).

const collator = typeof Intl !== "undefined" ? new Intl.Collator(undefined, { numeric: true, sensitivity: "base" }) : null;
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Compare two cell values of a given type: "number" | "date" | "severity" | "text" (default). Empty values always sort last.
export function compareValues(a, b, type = "text") {
  const empty = (v) => v === null || v === undefined || v === "";
  if (empty(a) && empty(b)) return 0;
  if (empty(a)) return 1;
  if (empty(b)) return -1;
  if (type === "number") return Number(a) - Number(b);
  if (type === "date") return new Date(a).getTime() - new Date(b).getTime();
  if (type === "severity") return (SEVERITY_RANK[String(a).toLowerCase()] ?? -1) - (SEVERITY_RANK[String(b).toLowerCase()] ?? -1);
  return collator ? collator.compare(String(a), String(b)) : String(a).localeCompare(String(b));
}

// Stable sort of rows by one column. Rows with empty values stay last in BOTH directions. Does not change the input.
export function sortRows(rows, getValue, type = "text", dir = "asc") {
  const sign = dir === "desc" ? -1 : 1;
  const decorated = rows.map((row, i) => ({ row, i, v: getValue(row) }));
  decorated.sort((x, y) => {
    const xe = x.v === null || x.v === undefined || x.v === "";
    const ye = y.v === null || y.v === undefined || y.v === "";
    if (xe || ye) return (xe ? 1 : 0) - (ye ? 1 : 0) || x.i - y.i;
    return compareValues(x.v, y.v, type) * sign || x.i - y.i;
  });
  return decorated.map((d) => d.row);
}

// Which rows to actually draw for a long list. Fixed row height; `overscan` extra rows above and below the viewport.
// Returns the slice [start, end) plus the spacer heights that keep the scrollbar honest.
export function virtualWindow({ total, rowHeight, viewportHeight, scrollTop, overscan = 8 }) {
  if (total <= 0 || rowHeight <= 0) return { start: 0, end: 0, padTop: 0, padBottom: 0 };
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const visible = Math.ceil(viewportHeight / rowHeight) + overscan * 2;
  const end = Math.min(total, first + visible);
  const start = Math.max(0, Math.min(first, end - 1));
  return { start, end, padTop: start * rowHeight, padBottom: (total - end) * rowHeight };
}

// RFC 4180 CSV. Cells that start with = + - @ are prefixed with ' so a spreadsheet never runs them as a formula.
export function csvCell(value) {
  let s = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
export function toCsv(columns, rows, getCell) {
  const head = columns.map((c) => csvCell(c.label)).join(",");
  const body = rows.map((r) => columns.map((c) => csvCell(getCell(r, c))).join(","));
  return [head, ...body].join("\r\n");
}

// Clamp a dragged column width.
export function clampWidth(px, min = 60, max = 640) {
  return Math.max(min, Math.min(max, Math.round(px)));
}

// Sparkline geometry: points for an SVG polyline in a width x height box, padded by `pad`. Flat series draw a centred line.
export function sparkPoints(values, width = 80, height = 24, pad = 2) {
  const v = (values || []).map(Number).filter((n) => Number.isFinite(n));
  if (v.length < 2) return [];
  const min = Math.min(...v);
  const max = Math.max(...v);
  const span = max - min;
  return v.map((n, i) => [
    +(pad + (i * (width - pad * 2)) / (v.length - 1)).toFixed(2),
    +(span === 0 ? height / 2 : height - pad - ((n - min) * (height - pad * 2)) / span).toFixed(2),
  ]);
}

// Change between two numbers as { pct, dir } where dir is "up" | "down" | "flat"; null when there is nothing to compare with.
export function delta(current, previous) {
  const c = Number(current);
  const p = Number(previous);
  if (!Number.isFinite(c) || !Number.isFinite(p)) return null;
  if (p === 0) return c === 0 ? { pct: 0, dir: "flat" } : { pct: null, dir: c > 0 ? "up" : "down" };
  const pct = ((c - p) / Math.abs(p)) * 100;
  return { pct: Math.round(pct * 10) / 10, dir: Math.abs(pct) < 0.05 ? "flat" : pct > 0 ? "up" : "down" };
}

// Value of an animated counter at progress t in [0,1] (ease-out cubic), rounded to `decimals`.
export function easeCount(from, to, t, decimals = 0) {
  const k = 1 - Math.pow(1 - Math.min(1, Math.max(0, t)), 3);
  const v = from + (to - from) * k;
  const f = Math.pow(10, decimals);
  return Math.round(v * f) / f;
}

// "5s ago", "3m ago", "2h ago", "4d ago"; "just now" under 5 seconds.
export function ageLabel(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// How stale data is: "fresh" under `fresh` ms, "aging" under `stale` ms, otherwise "stale".
export function ageState(ms, fresh = 60000, stale = 600000) {
  return ms < fresh ? "fresh" : ms < stale ? "aging" : "stale";
}
