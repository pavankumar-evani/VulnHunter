// SIEM-style date-range filter: rolling-window presets (last 7/30/60/90 days),
// completed-calendar-period presets (last week/last 2 weeks/last month - distinct from
// the rolling windows, same "last week" vs "last 7 days" distinction Splunk's own time
// picker makes), and a custom from/to range. Zero new dependency - two native
// <input type="date"> fields for "custom," not a calendar-widget library (none exists
// anywhere in this repo, and adding one would break the no-build-step pattern).
//
// IMPORTANT honesty constraint (see dateRangeDisclaimerHtml below): this dashboard has
// no historical snapshot storage - remediation/output/normalized-findings.json is
// always just the current, single point-in-time state. This filter works by checking
// each finding's own real `first_seen`/`last_seen` date fields against the selected
// window - it can honestly answer "which of today's findings originated or were last
// confirmed in this window," but it can NOT reconstruct "what did total counts look
// like on a past date" (that would require snapshot history that doesn't exist).
import { escapeHtml } from "./dom.js";

export const PRESETS = [
  { id: "7d", label: "Last 7 days" },
  { id: "30d", label: "Last 30 days" },
  { id: "60d", label: "Last 60 days" },
  { id: "90d", label: "Last 90 days" },
  { id: "last-week", label: "Last week" },
  { id: "last-2-weeks", label: "Last 2 weeks" },
  { id: "last-month", label: "Last month" },
  { id: "custom", label: "Custom range…" },
];

function toIso(d) {
  return d.toISOString().slice(0, 10);
}

function daysAgo(n, today) {
  const d = new Date(today);
  d.setDate(d.getDate() - n);
  return d;
}

// Monday-start week boundary of the week containing `d` (day 0 = the Monday on/before
// `d`), used to find "last week"/"last 2 weeks" as completed calendar weeks rather
// than a rolling day-count - the same distinction a real SIEM time picker makes
// between "last 7 days" (rolling) and "last week" (the previous Mon-Sun week).
function startOfWeek(d) {
  const day = d.getDay(); // 0 = Sunday
  const diff = (day === 0 ? -6 : 1) - day; // days back to this week's Monday
  const monday = new Date(d);
  monday.setDate(monday.getDate() + diff);
  return monday;
}

export function computeRange(preset, customFrom, customTo, today = new Date()) {
  const t = new Date(today.toISOString().slice(0, 10)); // normalize to midnight UTC
  switch (preset) {
    case "7d": return { from: toIso(daysAgo(7, t)), to: toIso(t) };
    case "30d": return { from: toIso(daysAgo(30, t)), to: toIso(t) };
    case "60d": return { from: toIso(daysAgo(60, t)), to: toIso(t) };
    case "90d": return { from: toIso(daysAgo(90, t)), to: toIso(t) };
    case "last-week": {
      const thisWeekStart = startOfWeek(t);
      const lastWeekStart = daysAgo(7, thisWeekStart);
      const lastWeekEnd = daysAgo(1, thisWeekStart);
      return { from: toIso(lastWeekStart), to: toIso(lastWeekEnd) };
    }
    case "last-2-weeks": {
      const thisWeekStart = startOfWeek(t);
      const twoWeeksStart = daysAgo(14, thisWeekStart);
      const lastWeekEnd = daysAgo(1, thisWeekStart);
      return { from: toIso(twoWeeksStart), to: toIso(lastWeekEnd) };
    }
    case "last-month": {
      const firstOfThisMonth = new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), 1));
      const firstOfLastMonth = new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth() - 1, 1));
      const lastOfLastMonth = daysAgo(1, firstOfThisMonth);
      return { from: toIso(firstOfLastMonth), to: toIso(lastOfLastMonth) };
    }
    case "custom":
      return { from: customFrom || null, to: customTo || null };
    default:
      return { from: null, to: null };
  }
}

export function dateRangeHtml(idPrefix, current) {
  const preset = (current && current.preset) || "";
  const isCustom = preset === "custom";
  return `
    <label>Date range
      <select id="${idPrefix}-preset">
        <option value="">All time</option>
        ${PRESETS.map((p) => `<option value="${p.id}" ${p.id === preset ? "selected" : ""}>${escapeHtml(p.label)}</option>`).join("")}
      </select>
    </label>
    <label id="${idPrefix}-custom-from-label" ${isCustom ? "" : "hidden"}>From
      <input type="date" id="${idPrefix}-custom-from" value="${escapeHtml((current && current.customFrom) || "")}">
    </label>
    <label id="${idPrefix}-custom-to-label" ${isCustom ? "" : "hidden"}>To
      <input type="date" id="${idPrefix}-custom-to" value="${escapeHtml((current && current.customTo) || "")}">
    </label>`;
}

// Wires the preset <select> + custom date inputs rendered by dateRangeHtml() above.
// `onChange({preset, customFrom, customTo})` fires whenever the effective range
// changes (a plain preset selection, or either custom date field once both preset is
// "custom" and a value is present).
export function wireDateRange(container, idPrefix, onChange) {
  const presetEl = container.querySelector(`#${idPrefix}-preset`);
  const fromLabel = container.querySelector(`#${idPrefix}-custom-from-label`);
  const toLabel = container.querySelector(`#${idPrefix}-custom-to-label`);
  const fromEl = container.querySelector(`#${idPrefix}-custom-from`);
  const toEl = container.querySelector(`#${idPrefix}-custom-to`);
  if (!presetEl) return;

  function fire() {
    onChange({ preset: presetEl.value, customFrom: fromEl.value, customTo: toEl.value });
  }
  presetEl.addEventListener("change", () => {
    const isCustom = presetEl.value === "custom";
    fromLabel.hidden = !isCustom;
    toLabel.hidden = !isCustom;
    fire();
  });
  fromEl.addEventListener("change", fire);
  toEl.addEventListener("change", fire);
}

// `field` is "first_seen", "last_seen", or "either" (matches if EITHER real date field
// falls in the window - useful when a page doesn't want to force a single choice).
// A finding missing the relevant date field(s) entirely is excluded once a range is
// active (there's nothing to honestly compare against "no date" other than "doesn't
// match"), but passes through unfiltered when no range is selected at all.
export function filterByDateRange(findings, range, field = "last_seen") {
  if (!range || (!range.from && !range.to)) return findings;
  return findings.filter((f) => {
    const candidates = field === "either" ? [f.first_seen, f.last_seen] : [f[field]];
    return candidates.some((d) => {
      if (!d) return false;
      if (range.from && d < range.from) return false;
      if (range.to && d > range.to) return false;
      return true;
    });
  });
}

export function dateRangeDisclaimerHtml() {
  return `
    <p class="filter-count" style="margin:-4px 0 8px">
      Filters by each finding's real first-seen date (when it originated). This
      dashboard has no historical snapshot storage, so it shows which of today's
      findings originated within the selected window - not what total counts looked
      like at a past date (see the FAQ).
    </p>`;
}
