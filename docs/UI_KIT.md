# Quanta UI kit

The application shell and design-system layer: command palette, live updates, a small set of shared components, a page lifecycle contract and a living style guide. Vanilla JavaScript and CSS, no bundler, no new runtime dependency, nothing loaded from outside the app, so the same-origin Content-Security-Policy stays valid. The live examples are at **`/design-system`** (Help menu, and Administration in the module catalog).

| File | What it is |
|---|---|
| `dashboard/static/ui.css` | Kit styles, loaded after `style.css`. Uses its theme variables, so light/dark follow the rest of the app. Also the phone-width rules for the shell's top bar and the `data-theme` override. |
| `dashboard/static/js/ui.js` | Components and the page lifecycle (below). |
| `dashboard/static/js/tableMath.js` | Pure maths for the table, sparkline, delta chip, counters and data age. Tested under Node. |
| `dashboard/static/js/fuzzy.js` | The palette's fuzzy matcher. Tested under Node. |
| `dashboard/static/js/live.js` | One shared live stream with a polling fallback. Tested under Node. |
| `dashboard/static/js/commandPalette.js` | Ctrl/Cmd+K palette, theme, recent pages. |
| `dashboard/static/js/pages/designSystem.js` | The style guide page. |
| `dashboard/events.py` | The in-process pub/sub behind `GET /api/events`. |

## Command palette

`Ctrl/Cmd+K` anywhere, `/` focuses the search box (outside a text field), `?` shows the shortcut cheat sheet, `g h` / `g m` / `g q` go to Home / all modules / the queue.

The palette searches, fuzzily and with the matched letters highlighted: every page in `nav.js` the signed-in user may open (a module the licence does not cover is not offered, a feature-flagged page is not offered when its flag is off, and a page whose tip starts with "Admin" is not offered to a non-admin), recent pages, actions (switch module, toggle theme, copy link, shortcuts), and findings and assets through the same data as the top search bar (`search.js`, `lookupData`). Matching: every word of the query must match; a plain substring beats a subsequence; a subsequence must be compact (within three times the word) or be the initials of words (`rq` finds Remediation Queue); secondary text (group name, tip) matches by substring only, so `hunt` does not find unrelated pages.

Not built, because the API does not exist in this build: natural-language rows from `/api/ask/structured`. Incident and hunt lookup (administrators) is in `commandPalette.js` (`loadSocItems()`), from the real list APIs; see `docs/SOC_HUNT_UI.md`.

**Theme.** "Toggle theme" cycles auto (follow the system) / dark / light and remembers it in `localStorage` (`quanta.theme`). It redefines the colour variables only; the few rules in `style.css` that are hard-coded for dark inside `prefers-color-scheme` still follow the system, so a forced light theme on a dark system is approximate.

## Live updates

`live.js` exports `live` (and `subscribe(topic, cb)`, which returns an unsubscribe function).

* **Transport.** It opens one `EventSource("/api/events")` when the browser has one. Any refusal (401 before sign-in, 404, 503) or three failures in a row closes it and the app polls instead. After sign-in the router calls `live.retrySSE()`.
* **Polling.** `live.poll(topic, fn, { every })` registers a fallback source for a topic. While nothing changes the wait doubles (jitter up to +25%, capped at two minutes); a change emits the topic and resets it; a hidden tab pauses it and resumes on becoming visible. While the stream is healthy the poller only runs as a rare safety net.
* **Topics in use.** `activity` (any audit-logged action; `{ action }` only), `notifications`, `live.mode` (`sse` | `poll` | `idle`). `soc.incident` is listened for already so a later incident stream needs no change here. A dotted topic also reaches subscribers of its parent on the server.
* **Notification bell.** Grouped by category, unread first, "Mark all read", a toast for each new `danger` notification (the first load is a silent baseline), and a re-check as soon as an `activity` event arrives.

### `GET /api/events`

Sign-in required (`require_login`), read only. Query: `topics` (comma separated, up to 10; empty means all), `once=true` (send the hello frame and close; used by tests and as an availability check). `Last-Event-ID` resumes from the last 50 events. A stream is recycled after 15 minutes (the browser reconnects), heartbeat comment every 15 seconds, `X-Accel-Buffering: no` so a proxy does not hold frames back.

Frames: `event: <topic>` and `data: {"topic","data","ts"[,"dropped"]}`. The first frame is `hello`.

Server code publishes with `from events import publish; publish("topic", {...small dict...})` (or `events.hub.publish`), from any thread. Keep the payload to names and counters; the page re-reads the real data through the normal routes. The activity log publishes `activity` with the action name only (`remediation/audit/activity_log.listener`, set in `dashboard/app.py`).

Bounds: each subscriber has its own queue of 100 events; when it is full the oldest event is dropped and the next frame carries `dropped: n`, so a slow client never slows a publisher or grows memory. At most 200 open streams per process (the 201st gets 503 and the page polls). State is per process: with several replicas a client sees only the events published on the replica it is connected to, which is why nothing depends on delivery. Licensing: `/api/events` is core.

## Components (`ui.js`)

Functions that return markup return a string and escape every value; arguments named `html` are trusted markup. Behaviour is attached with a function that returns `destroy()`.

| Call | Notes |
|---|---|
| `kpiTile({ label, value, previous, spark, href, tone, goodWhen, hint, decimals, suffix })` | A numeric `value` counts up (`mountCounters(root)`, skipped under reduced motion). `previous` adds a change chip; `goodWhen` says which direction is good news ("down" for vulnerabilities). Pass `previous` and `spark` only when you really have history. |
| `deltaChip(current, previous, opts)`, `sparkline(values, opts)` | Standalone. The chip has an arrow as well as a colour. |
| `chip(label, { tone })`, `severityChip(severity)` | Severity colours come from `SEVERITY_COLORS` in `charts.js`, the same palette the charts use. |
| `dataAgeBadge(ts)` + `mountDataAge(root)` | "Updated 12s ago", amber then red as it ages; one shared timer. |
| `skeleton(kind, n)`, `pageSkeleton()` | `kpi`, `card`, `table`, `text`. The router shows `pageSkeleton()` while a page loads. |
| `emptyState({ title, body, actionLabel, actionHref })` | Say what is missing and the next step. |
| `dataTable(host, { columns, rows, rowKey, onRowClick, storageKey, csvName, virtualAt, rowHeight, maxHeight, caption })` | Sort (click a header), resize (drag, or arrow keys on the handle), column chooser, debounced filter, CSV of the filtered, sorted, visible view (cells starting with `= + - @` are prefixed so a spreadsheet does not run them). `storageKey` remembers sort, widths and hidden columns. Above `virtualAt` (500) rows only the rows in view exist in the page; `rowHeight` is fixed. |
| `openDrawer({ title, html, width })` | Side panel for detail in context. Esc closes, focus is trapped and returned. |
| `toast(message, { tone, href, action, ms })` | Polite `role=status`; `bad`/`critical` use `role=alert`. At most four. |
| `showShortcuts()`, `registerShortcutHelp(keys, text)`, `initShortcuts()` | The `?` cheat sheet. |
| `card({ title, subtitle, body, actions })`, `tipAttr(text)`, `debounce(fn, ms)` | Small helpers. Tooltips are the existing `data-tooltip` mechanism (`tooltip.js`). |

CSS classes are prefixed `ui-` (kit), `pal-` (palette) and `mod-` (module picker).

## Page contract

```js
export const title = "Name";                       // or a function of the route params
export async function render(container, ...params) {
  const off = live.subscribe("activity", refresh);
  onCleanup(off);                                  // anything that outlives the render
  const t = setInterval(refresh, 20000);
  return () => clearInterval(t);                   // returning a cleanup function still works
}
```

* The router (`app.js`) calls the returned cleanup and everything registered with `onCleanup()` before the next page, so navigation does not leak timers, listeners or live subscriptions. `dataTable`, `mountCounters` and `openDrawer` register themselves.
* A page that throws, or whose module fails to load, shows the error boundary (`errorBoundaryHtml`) with a "Try again" button; the shell, the sidebar and the other pages are unaffected.
* While a page loads the router shows `pageSkeleton()` (no blank flash), and the new page fades in (`#app.ui-page-enter`, off under `prefers-reduced-motion`).
* Lazy loading is unchanged: each page is a dynamic `import()`.

## Reference implementations

* **Home** (`pages/overview.js`): four headline tiles. There is no server-side history, so the change chips and sparklines come from what this browser saw on earlier visits (`localStorage` `quanta.home.history`, at most one reading per five minutes, 24 kept). Until there are two readings the tile shows the number only; the tile hint says so. It refreshes straight away on an `activity` event as well as on its existing 20-second timer, and counts up only on the first paint.
* **Module picker** (`pages/capabilities.js`): tiles with an in-use meter and counters, a debounced filter over the chosen module's capabilities, empty states, a data-age badge. Behaviour (remembered module, `?area=` link, licence banner) is unchanged.
* **SOC and Hunting pages** were rebuilt on this kit: see `docs/SOC_HUNT_UI.md`.

## Accessibility

Every control is a real `button` or `a` with a visible focus ring (`ui.css`). The palette follows the combobox/listbox pattern (`aria-activedescendant`); table headers carry `aria-sort`; the table has a `caption`, resize handles are focusable separators; toasts and the row count are live regions; drawers are `role=dialog aria-modal`. Motion (skeleton shimmer, counters, page and drawer transitions, the data-age pulse) is removed under `prefers-reduced-motion`. The shell's top bar wraps at 640px and below so nothing scrolls sideways down to 360px.

## Tests

`tests/test_ui_kit_js.py` (fuzzy matching, table sort/virtual-window/CSV/sparkline/delta/counter maths, live.js backoff, SSE delivery, fallback, hidden-tab pause, stop; needs Node and is skipped without it) and `tests/test_events.py` (hub bounds, replay, thread safety, route auth, framing, read-only). The DOM parts (`ui.js`, the palette, the pages) have no automated test: they were checked in a browser.

## Limits

* No server-side metric history, so trends are per browser.
* `/api/events` is per process; behind several replicas the stream is best effort and the polling fallback is what guarantees freshness.
* Pre-existing pages are not converted to the kit; some of them (for example the Home charts) are still wider than a 390px screen inside their own scroll area.
* Forced light/dark theme changes colour variables only.
