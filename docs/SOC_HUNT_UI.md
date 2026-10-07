# SOC command center and Threat Hunting pages

The Threat Detection and Response module's two main pages, rebuilt on the UI kit (`docs/UI_KIT.md`) over the existing backends (`docs/SOC_INCIDENTS.md`, `docs/INVESTIGATION_REPORTS.md`, `docs/HUNT_ENGINE.md`). Route paths and nav entries are unchanged: `/soc`, `/soc?incident=ID`, `/hunting`, `/hunting?tab=...`, `/hunting?hunt=ID`.

The workflow the pages make obvious: an analyst does not create a case. Work arrives routed to them, already investigated, and they open it to see a verdict with its reasons, what Quanta found and what it could not see. Hunts start from a ranked board of suggestions, and each hunt ends in a report.

## Files

| File | What it is |
|---|---|
| `dashboard/static/js/pages/soc.js` | The command center. |
| `dashboard/static/js/socIncident.js` | The incident report page (`/soc?incident=ID`). |
| `dashboard/static/js/pages/hunting.js` | Suggested hunts, ATT&CK coverage matrix, active hunts. |
| `dashboard/static/js/huntReport.js` | The hunt report view (`/hunting?hunt=ID`) and the shared query tabs. |
| `dashboard/static/js/socLogic.js`, `huntLogic.js` | Pure logic (move rules, filters in the URL, SLA ring maths, kill-chain dots, attack-flow layout, live feed with polling fallback, matrix aggregation, score bars). No DOM, tested under Node. |
| `dashboard/static/js/sxKit.js` | Modal with a focus trap, pop-up menu, avatar, SLA ring, segmented control, copy and download helpers. |
| `dashboard/static/soc.css` | Styles (`sx-` shared and SOC, `hx-` hunting). Theme variables only, so light and dark follow the app. |
| `dashboard/static/js/pages/socMore.js`, `huntingMore.js` | The older tabs that still earn their place, folded under "More" (metrics, log and technique analysis, decision calibration, the case view; alert triage, intel intake, detection engineering, proposals, hunts, overview). |
| `remediation/hunting/matrix.py` | The one new backend piece: the ATT&CK matrix join. |

## /soc, the command center

* **KPI strip**: open incidents (with a per-day sparkline), my queue, unassigned, SLA at risk, SLA breached, auto-closed today, time to acknowledge, time to resolve (with a sparkline). The first five are filters; click again to clear. A figure with no history says "Not enough history yet" (the time tiles are `n/a` until cases have been acknowledged or resolved) instead of showing a made-up zero.
* **Board or list.** Columns New, Triaging, Investigating, Contained, Resolved. Each card shows severity, tier, title, the first-look verdict chip with its confidence (an analyst verdict once resolved), 12 kill-chain dots, entity chips, the owner's avatar or the queue, an SLA ring for the clock that matters now (first running of acknowledge, pick-up, resolve) and a "why routed here" hint. Filters (queue, tier, severity, status, service level, text) and the view are kept in the URL.
* **Moving work.** Drag a card to a column, or use the card's actions menu (the keyboard and touch route to the same moves). New to Triaging accepts; working states advance in either direction; Resolved asks for a verdict and a 20+ character summary; a resolved incident reopens with a reason; an auto-closed one can only be undone; "back to New" is refused with the reason. Drop a card on an analyst in the roster to reassign. Updates are optimistic and roll back with the server's message when the call fails (`planMove` in `socLogic.js` decides what is allowed).
* **Keys**: `j`/`k` move between cards, `Enter` opens, `a` accepts, `e` escalates (summary dialog), `r` resolves (verdict dialog), `n` advances. They are listed in the `?` cheat sheet.
* **Live.** One `EventSource` on `/api/soc/incidents/stream` (administrator session). Any refusal or three errors in a row switch to polling every 20 s; the badge says Live, Reconnecting or "Refreshing every 20 s". A changed card is highlighted briefly; a new Critical incident raises a toast with a link. The page stops its stream, listeners and timers when you leave it.
* **Auto-closed lane** with Undo, and the **analyst roster**: availability switch, specialties, shift, on-call, capacity and a load bar; Edit changes the routing profile (`PUT /api/soc/analysts`). Under **More**: add an analyst, create an incident by hand (the exception, reason required), and the older metrics, log analysis and decision tabs.
* **Empty state** explains what feeds the queue (alerts at `/api/ingest/alerts`, ITSM tickets at `/api/ingest/itsm-ticket`) and links to Connections.

## /soc?incident=ID, the incident report

Header with severity, status, tier, owner, SLA ring and the verdict banner (label, basis automated or analyst, confidence; "a person validates it"). Actions: Accept, Set status, Reassign, Escalate, Resolve with verdict, Reopen, Undo auto-close, and under More: add a note, merge another incident, split alerts out, rebuild the report, download or copy it as Markdown, copy the link, open the case tools.

Sections (a sticky jump bar): verdict rationale and summary, why it was routed; historical correlation; entities; ATT&CK mapping with next steps, look-in sources, mitigations and runbook; the **attack flow** (SVG, lanes per stage, nodes coloured by severity, entities below, next-stage edges animated unless reduced motion is set; click a node, or press Enter on it, to filter the timeline); the behaviour timeline; root cause (a Hypothesis chip with its gaps unless several sources agree); the IOC table (reputation status, context, blast radius); what the tools did; recommended actions (second-person flags) and what is not known; references (every search and lookup with its query); follow-up questions; related incidents.

* **Show evidence** reveals, under each statement, the evidence references behind it; a statement with none is marked "Not evidenced", and a reference that points at nothing is called out.
* **Run live searches** first calls `report/refresh` without `confirm`, and shows the indicators that would be sent for reputation, each planned search with its query, the look-back and the budget; nothing runs until "Confirm and run". The stop reason is recorded in the report. With no SIEM connected the server's message is shown and the report stays stored-data only.
* **Follow-ups**: ask a question, read the answer with its evidence, tick answers and merge them into the report. **Post to ticket** shows the exact comment and per-ticket status as a dry run, then posts only on confirm.

## /hunting

* **Suggested hunts**: ranked cards with a score you can open ("why this score": each factor against its maximum, the learned adjustment), why-now chips that link to the underlying records (strong evidence is outlined), ATT&CK chips (click to filter), scope counts, effort and value, a data-readiness badge ("Data connected" or "Cannot tell", never "not connected"), expected malicious and likely benign, SPL, Sigma and KQL tabs with copy, and Accept, Dismiss (reason), Conclude (outcome and notes) and Promote. Filter by type, tactic, lifecycle, text, connected data only. Gaps ("where Quanta has nothing to suggest from") are listed, so an empty board is never mistaken for a clean estate.
* **ATT&CK coverage**: tactics as columns, techniques as cells. Colour is the state: covered (an enabled rule claims it), hunted (a hunt tests it, no rule), exposed (open findings or alerts, no rule or hunt), quiet; shade is exposure. Click a cell for the rules, hunts, suggestions and findings behind it. Backed by `GET /api/hunting/attack-matrix` (admin). With no detection rules recorded the page says coverage cannot be judged.
* **Active hunts**: cards with a live trial-hit progress bar and verdict (refreshed every 20 s and on activity events), and closed hunts.
* **Hunt report**: verdict and time-to-report, executive summary, per-domain counts, the trial-hit table (all or per domain; click a row for its queries), record a result, add to the allow-list, remove an allow-list entry, detection recommendations, set the time box, run trial hits in the SIEM (preview and confirm), download Markdown or HTML, copy Markdown.
* The older tabs are reachable as before: `?tab=alerts`, `intel`, `detections`, and `more` (overview, proposals, hunts).

## Command palette and Home

The palette ( `Ctrl/Cmd+K` ) now finds open incidents (`#12 title`) and hunts from the real list APIs; the group appears for administrators only and is simply left out when the lists cannot be read. Home shows a "Today in the SOC" card (open, unowned, service-level and auto-closed counts) for people who can read the incident list.

## Backend added

`GET /api/hunting/attack-matrix` (administrator, licensed with `/api/hunting`): `{tactics, techniques[{technique_id, name, tactic, tactics, rules, rules_disabled, findings, alerts, hunts, suggestions, in_library, exposure, state}], totals, note}`. A technique is placed under the first tactic in `attack_tactics.yaml`; one that is not there goes under `Unmapped`, never a guessed tactic. Sub-techniques roll up to their parent. Tests: `tests/test_attack_matrix.py`.

## Tests

`tests/test_soc_hunt_ui_js.py` (Node; skipped without it) covers the move rules, filter URL state, SLA ring maths, KPI counts, live merge helpers, attack-flow layout, timeline filter, evidence marks, the live feed delivery and polling fallback, matrix aggregation, suggestion filters and score bars. The DOM parts were checked in a browser: see the limits.

## Limits

* Verified in a browser against a throwaway server with seeded alerts (a multi-stage chain on one host, an ITSM ticket, threat intel, KEV findings, a stored SIEM and reputation connection that was never contacted): the command center, board drag, list view and card menu, incident report with attack flow, the live-search confirm dialog (cancelled, never confirmed), a follow-up merged into the report, the post-to-ticket dry run, suggested hunts, the matrix, a hunt report and the palette lookup, at desktop width and at 360 px.
* **Not verified**: a confirmed live search or reputation lookup, a real ticket post, the SSE stream under a proxy, more than a handful of incidents (the board renders every incident in memory; it is not virtualised), touch drag (HTML5 drag and drop does not fire on touch; the card menu is the touch route), the Allow-list and Record-result dialogs and the Conclude and Promote dialogs beyond opening them, and light theme.
* The live stream reads the incident event table every couple of seconds per open connection; the page falls back to polling when it is refused.
* Trend sparklines come from `GET /api/soc/metrics` (14 days of case timestamps); there is no per-incident history of the KPI figures, so a delta chip is not shown.
* The page loads three incident lists (open, resolved, auto-closed) and shows the 12 most recent resolved; older ones are in the report pages and the legacy case tools.
* The dev server used for checking was slow to answer while loading the 9,445-finding sample queue (several seconds per shell load); the SOC routes themselves answered in under a second.
