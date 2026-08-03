// Client-side export utilities - CSV, JSON, and Markdown-table downloads for any table
// already rendered in the browser. Pure client-side (a Blob + a temporary <a download>),
// no server round-trip, no new dependency. "Excel" is offered as CSV - Excel opens CSV
// natively, and generating a real binary .xlsx would need a new library this project
// doesn't otherwise need; CSV is the honest, dependency-free equivalent, not a
// downgrade dressed up as one.
//
// Every page wires this the same way: a `columns` array of {label, value(row)} plus a
// `getRows()` callback returning whatever's *currently visible* (respecting active
// filters/sort) - exporting the filtered view, not always the full unfiltered dataset,
// since that's what the person looking at the screen actually means by "this data."

function csvEscape(value) {
  let s = value === null || value === undefined ? "" : String(value);
  // CSV/formula-injection mitigation (CWE-1236): a cell starting with =, +, -, @, or a
  // tab/CR is interpreted as a formula by Excel/Sheets/LibreOffice when the file is
  // opened, not as literal text. Several exported columns are free text a logged-in
  // user (or a CMDB CSV they uploaded) controls - asset owner/team, exception reason/
  // requester/approver - so this isn't hypothetical: a crafted "owner" name could
  // execute a formula for whoever opens the export next. Prefixing with a single quote
  // is the standard mitigation (OWASP's CSV Injection guidance) - every spreadsheet
  // app treats a leading `'` as "read the rest of this cell as text."
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  if (/[",\n]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

export function toCSV(rows, columns) {
  const header = columns.map((c) => csvEscape(c.label)).join(",");
  const lines = rows.map((row) => columns.map((c) => csvEscape(c.value(row))).join(","));
  return [header, ...lines].join("\r\n");
}

export function toJSONExport(rows, columns) {
  return JSON.stringify(rows.map((row) => {
    const obj = {};
    columns.forEach((c) => { obj[c.label] = c.value(row); });
    return obj;
  }), null, 2);
}

export function toMarkdownTable(rows, columns) {
  const header = `| ${columns.map((c) => c.label).join(" | ")} |`;
  const divider = `| ${columns.map(() => "---").join(" | ")} |`;
  const lines = rows.map((row) =>
    `| ${columns.map((c) => String(c.value(row) ?? "").replaceAll("|", "\\|").replaceAll("\n", " ")).join(" | ")} |`);
  return [header, divider, ...lines].join("\n");
}

export function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function exportButtonsHtml(groupId) {
  return `
    <div class="export-buttons" data-export-group="${groupId}">
      <button type="button" class="secondary-button" data-export="csv">Export CSV</button>
      <button type="button" class="secondary-button" data-export="json">Export JSON</button>
      <button type="button" class="secondary-button" data-export="md">Export MD</button>
    </div>`;
}

// Call once after the group's HTML is in the DOM. getRows() is called fresh on every
// click (not once at wire-time) so an export always reflects the current filter/sort
// state, not whatever it was when the page first loaded.
export function wireExportButtons(container, groupId, { getRows, columns, filenameBase }) {
  const group = container.querySelector(`[data-export-group="${groupId}"]`);
  if (!group) return;
  group.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-export]");
    if (!btn) return;
    const rows = getRows();
    if (btn.dataset.export === "csv") downloadFile(`${filenameBase}.csv`, toCSV(rows, columns), "text/csv");
    else if (btn.dataset.export === "json") downloadFile(`${filenameBase}.json`, toJSONExport(rows, columns), "application/json");
    else if (btn.dataset.export === "md") downloadFile(`${filenameBase}.md`, toMarkdownTable(rows, columns), "text/markdown");
  });
}
