# UI revamp: the most-used module pages

The second pass of the UI work. Home, the module picker, the SOC command center and Hunting were rebuilt first (`docs/UI_KIT.md`, `docs/SOC_HUNT_UI.md`). This pass rebuilds fifteen of the most-used pages in the other modules on the same kit, and leaves the rest as they were. It is a presentation and interaction upgrade: route paths, nav entries, API calls and engines are unchanged, and no new server endpoint was needed.

Dark navy, Chakra Petch, vanilla JavaScript and CSS, same-origin only (the CSP stays valid), no new runtime dependency, every page keeps `title` and `render(container)` and cleans up after itself on a route change.

## What was rebuilt

| Page | Route | What changed |
|---|---|---|
| Remediation queue | `/queue` | KPI tiles that are filters (Critical, SLA breached, due in 3 days, KEV, EPSS 50%+, unowned) beside a "in this view" tile with a priority-mix bar and a breakdown popover. **Every filter and the sort live in the URL** (old deep links such as `?category=`, `?kevOnly=true`, `?asset=` still work), shown as removable chips. A virtualised, sortable, resizable table with a column chooser (the old columns are all still there) and CSV. Shift-click range select, `j`/`k`/`x`/`Enter` keys. Bulk **assign** and bulk **request exception** with optimistic updates that roll back with the server's reason. A "why this priority" popover per row. SLA ring, KEV chip, EPSS bar. Saved views (built-in and your own, kept in this browser). Live refresh and a data-age badge. |
| Finding detail | drawer from any page | `findingDetail.js` now opens a side drawer for every page that lists findings (queue, hubs, attack chains, assignments...). Tabs: Overview (priority reasons, SLA ring, facts), How to fix (guidance), Context (compensating controls, network reachability, attack path entry/pivot/impact, similar findings), Ownership (state, history, tickets, assign). |
| Assignments | `/assignments` | A live **board** (Unassigned, Open, In progress, Blocked, Resolved) or a table, with counts per view, KPI tiles that filter, SLA rings, drag a card (or use its menu) to change status; blocking needs a note; taking unassigned work assigns it to you first. Bulk assign in table mode. Auto-route keeps its preview-then-confirm. |
| Remediation approvals | `/remediation-approvals` | Cards with the safety lint, rollback plan, staging check, an approval timeline (requested, staging, decision, triggered, verified) and the closed-loop outcome. Review opens the **evidence pack** (finding, lint errors and warnings, rollback, playbook, copy). Reject needs a reason; approve needs the reviewer's confirmation; the button explains why it is disabled (separation of duties, failed lint). Approve and reject are optimistic. |
| Exceptions | `/exceptions` | Counts that filter (active, expiring in 14 days, expired, revoked), expiry countdown meters, a request dialog that applies the server's rules first (a real reason, a different approver, a future date within a year), finding search, suggested controls to insert, revoke with confirmation. `?finding_id=&reason=` still pre-fills it. |
| Security posture review | `/posture` | Overall and per-framework scorecards, radar, trend delta and sparkline (per browser), framework drill-down with filters, an action list whose "exact setting" has a **copy** button (environment variable, config file key, Helm value; pages and processes link instead), and the action list as Markdown to copy or download. |
| Risk and compliance | `/grc` | Overview KPIs with trends, framework status bars, controls and evidence tables with filters, **attest and add-risk in dialogs** (no more browser prompts), a clickable 5x5 likelihood-by-impact risk grid, policies with acknowledgement progress. |
| Cyber risk | `/cyber-risk` | Cyber health score with trend, domains on a radar, the exceedance curve with the tolerance line, KPI tiles; the scenario builder is unchanged apart from a dialog for delete. |
| Risk management | `/risk` | New header, KPI strip with trends, risk-tier bar, data-age badge. The charts, heat map and tables below are the existing ones. |
| Applications and SBOM | `/applications` | Filterable table (environment, criticality, exposure, SBOM) with KPI tiles; the detail page gets kit tabs and tiles. The dependency graph and tab bodies are unchanged. |
| Fix pull requests | `/fix-prs` | A **lifecycle board** (Proposed, Approved, Pull request open, Merged, Verified by a scan, Stopped or failed) with review and check chips and "needs attention" reasons; timing and process tabs; the detail page has a timeline and dialogs for discard and for the preview-then-confirm "open the pull request". Cards are deliberately not draggable: opening a PR writes to a repository. |
| Pipeline gates | `/pipeline-gates` | A verdict banner (PASS/WARN/FAIL) with rule-by-rule reasons, pass-rate KPIs, the policy as a matrix, copy buttons on the pipeline step, and the history as a day-grouped timeline. |
| Attack surface | `/attack-surface` | Data-age banner that escalates, an **exposure map** that opens the asset list for a layer, a faceted asset table (kind, scope, state, ownership), a change feed that refreshes itself and flashes what is new, dialogs instead of confirms, copy buttons on the example commands. |
| AI security | `/ai-security` | Scorecard (assets by risk, OWASP categories, severity mix), register and findings as tables, modal confirm before publishing. The long asset form is unchanged. |
| Connections | `/connections` | Health cards (Healthy, Failing, Not syncing, Never run, Syncing, Disabled) with last sync age, schedule, next run, and **Test** and **Sync now** per card; health chips filter; API keys as a table. The editors are the existing ones. |
| Activity log | `/activity-log` | A **live tail** (merges new entries as they happen, flashes them, can be paused), filters by action group, actor and text, virtualised table with CSV, unusual-activity cards. The Integrity tab (administrators) is on the kit too: KPI tiles, checks by level, repair preview and a confirm dialog. |

Every rebuilt page also has: a data-age badge or banner where data can be stale, skeleton loaders while it loads, an empty state that says what is missing and the next step, `registerShortcutHelp` entries where it has keys, and **command-palette actions** for its key actions (they appear only while the page is open: `registerPaletteActions` in `commandPalette.js`, wrapped by `pageActions()` in `mxKit.js`).

## What was not rebuilt

About sixty pages still look as they did: Asset inventory, the Infrastructure and Application hubs, Users and teams (People), Ownership analytics, Support, Reports, Priority rules and the other policy editors, the connector pages, SOAR and the SOC sub-pages outside `/soc`, Threat models, API security, DevSecOps (control library), Secure design, Firewall rules, Access governance, Dark web, ML insights, and so on. Some of them benefit indirectly: every page that opens a finding now opens the new drawer. The Risk management page only has a new header and KPI strip.

## The shared pieces

| File | What it is |
|---|---|
| `dashboard/static/js/mxKit.js` | `selectableTable` (virtualised, sortable by the page, column chooser, shift-range select, keyboard rows, CSV), `kpiStrip` (tiles that are filter buttons), `popover`, `radarSvg`, `stackedBar`, `meter`, `tabBar`/`wireTabBar`, `copyButton`, `autoRefresh` (live event or timer, stops on route change), `pageActions` (palette entries), `replaceSearch` (URL state without a history entry). |
| `dashboard/static/js/queueLogic.js` | Pure logic for the queue: URL state, filters, sort, SLA ring maths, priority breakdown, bulk selection rules, optimistic apply and undo, saved views. |
| `dashboard/static/js/moduleLogic.js` | Pure logic for the other pages: assignment board move rules, approval timeline and rules, exception states and validation, posture settings text and trend history, risk grid, connection health, activity tail merge, fix-PR lanes, gate statistics, exposure levels. |
| `dashboard/static/js/findingDrawer.js` | The finding drawer. |
| `dashboard/static/modules.css` | Styles (`mx-` prefix), loaded after `soc.css`. Reuses `sx-` and `ui-` classes and the theme variables. |
| `tests/test_modules_ui_js.py` | The Node tests (below). |

Two small changes outside the pages, found while testing live:

* `app.js` numbers each navigation. A slow page that finished loading after the person had already moved on used to install its cleanup, and its error, over the page now showing (seen as "This page failed to load" on the wrong page). It no longer can.
* `notifications.js` coalesces its re-check. A stream that reconnects replays up to 50 events at once and each used to cost a `/api/notifications` request and a server-side recompute; on a large estate that could keep the server busy for minutes.

## Honest limits

* **Trends are per browser.** The server keeps no history, so deltas and sparklines (posture, compliance, cyber risk, risk management, attack surface, AI security) come from earlier readings this browser took (one per five minutes, 24 kept) and show nothing until there are two. They say so.
* **Optimistic updates.** The queue, assignments, approvals and exceptions change the screen at once and put it back with the server's reason when a call is refused. They do not guess what the server will compute (an assignment is not shown as "resolved" because someone moved it).
* **Slow endpoints are still slow.** Any write changes the database file, which invalidates the server's live-queue cache, so the next read recomputes it (20 to 40 seconds on the 9,500-finding sample estate, including `/api/posture`). The pages show skeletons and keep working; the cache invalidation itself is untouched.
* **Phones.** The shell's icon rail still takes about 64 px at 360 to 375 px wide, so content is narrow; tables scroll inside their own region and no page scrolls sideways.
* **Not exercised**: Safari and Firefox, a real Git host or live scanner behind any page, several server replicas behind the live stream, a screen reader pass (labels, roles and `aria-sort`/`aria-pressed` were written for it; it has not been run with one).

## How it was verified

Against a throwaway server (sqlite in a temp file, a throwaway session secret, simulated connectors loaded with `seed-demo`, the demo application from `seed-appsec-demo`, and approvals, exceptions, a risk, a scenario, an AI asset, attack-surface imports and six fix proposals created through the real routes):

* Every rebuilt page was loaded in a browser pane at 800 px and 375 px wide with the console watched. Measured: no page scrolls sideways, no uncaught errors except the `401` the app makes before sign-in.
* Queue: filters write the URL and chips remove them; KPI tiles filter; the table virtualises (32 rows in the DOM for 204; 21 for 9,542); shift-select; the drawer's four tabs load; bulk assign persisted; bulk exception persisted with the optimistic row; the priority-mix and why popovers; saved view saved to storage.
* Assignments: board counts, "Take it" moved a card at once and the server confirmed; "Blocked" refused an empty note and then moved. Approvals: the evidence pack loaded; approve was refused for the requester with the reason shown; a second administrator approved through the dialog (confirmation required), and the card moved optimistically.
* Pipeline gates: an evaluation recorded a FAIL with reasons and it appeared in the timeline. Activity log: a failed login arrived as a live row and flashed (the live tail only refreshes while the tab is visible; the test pane reports itself hidden, so the page's visibility check was overridden for that one test). Risk and compliance: collected evidence (14 tests), added a risk and saw it on the grid. Cyber risk: a saved scenario's analysis drew the curve.
* Not driven by a pointer: drag and drop on the assignments board (the card menu performs the same moves and was used); column resizing by drag.

Tests (`python -m unittest tests.test_modules_ui_js`, plus `tests.test_capabilities`, `tests.test_licensing`, `tests.test_ui_kit_js`, `tests.test_soc_hunt_ui_js`; Node is needed and the tests are skipped without it) cover the pure logic: URL state round trips and legacy deep links, filtering and sorting (empty values last in both directions), SLA ring maths, selection and range rules, optimistic apply and exact undo, saved views, assignment move rules, approval timeline and the rules that mirror the server's refusals, exception validation, posture setting text and history throttling, risk grid, connection health and next run, activity tail merge, fix-PR lanes, gate statistics, exposure levels, and a contract check that every rebuilt page keeps `title` and `render(container)`, registers cleanup and uses no `window.confirm`/`prompt`. The DOM parts have no automated test: they were checked in the browser as described above.

An observation that could not be reproduced: once, a bulk "request exception" dialog opened with "0 findings" although the bulk bar said one was selected; repeating the same steps showed the right number and recorded the exception. If it recurs, the place to look is `queue.js` `bulkException` and the selection copy handed to `S.selected`.
