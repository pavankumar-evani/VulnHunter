# Insights and structured Ask

Quanta watches its own data and tells you what needs attention, instead of waiting to be asked. Everything here is deterministic: explicit rules, robust statistics and
counting. No model is called, none is required, and nothing leaves the machine. Code: `remediation/insights/`; thresholds: `remediation/config/insights.yaml`.

## What an insight is

| Field | Meaning |
|---|---|
| `id` | A hash of the detector and its **subject** (an asset, a rule, an application), never of a changing number, so the same situation keeps the same id across refreshes and your decision about it survives. |
| `kind` | `risk-change`, `anomaly`, `correlation`, `deadline`, `gap`, `opportunity`, `drift` |
| `module` | one of the eight modules, or `core` for cross-module compound insights |
| `title`, `what`, `why` | what happened in plain language and why it matters |
| `evidence` | links to the findings, assets and pages behind it |
| `impact`, `confidence` | 0..1 each, with the text/reasoning that justify them |
| `action` | the next best action: a label, the page to do it on and the role who should |
| `roles` | relevance 0..1 for `admin`, `analyst`, `appsec`, `exec` |
| `state` | `open`, `snoozed`, `dismissed`, `acted`, with a reason, who and when |

## Detectors (17)

Each declares the data it needs. If a source is unavailable it is reported as a gap note in the refresh result (never as an insight, never as "nothing happened");
if the data exists but is too short it says "not enough history" and emits nothing.

| Detector | Looks for | Method |
|---|---|---|
| `kev_week_over_week` | New KEV-listed findings this week vs last | counts by first-seen date |
| `sla_trend` | Critical/High findings newly past SLA | deadline derived from days remaining; MTTR itself needs closed-finding history and is not used |
| `finding_burst` | A burst of new findings on one asset | median/MAD robust z against peer assets |
| `exposure_change` | Newly internet-facing or newly unowned asset with urgent findings | diff against the previous recorded asset snapshot |
| `unowned_critical` | Critical findings on assets nobody owns | count |
| `control_disappeared` | A compensating control removed or not seen for 30 days, on an asset with urgent findings | diff against the previous controls snapshot; last-seen age |
| `exception_expiring` | An exception on a KEV finding ends within 14 days | date comparison |
| `approval_stalled` | An approved remediation not started after 7 days | timestamps |
| `same_cve_many_apps` | One upgrade closes the same CVE in 3+ applications | grouping by CVE and package |
| `source_quiet` | A scheduled connection overdue, or no finding refreshed in 7 days | last run vs schedule |
| `noisy_rules` | A detection rule that is mostly false positives | rate over closed alerts with a disposition |
| `alert_volume_anomaly` | Yesterday's alert count far above baseline | robust z; seasonal-naive (same weekday, 3 weeks) or EWMA baseline; needs 14 days |
| `entity_repeat` | One entity in 3+ alerts, hunts or cases within 14 days | exact case-insensitive entity match |
| `posture_drop` | Control-test pass rate falling for a framework | single change-point on daily pass rates (`na` is never counted) |
| `expiry` | Licence expiring/grace/expired; API keys expiring in 14 days | dates |
| `ai_cost_spike` | A day of AI cost far above its baseline | robust z; days with unknown cost are excluded, never counted as zero |
| `policy_drift` | Policy/configuration changes with no approval reference | activity-log action prefixes in `insights.yaml` and the absence of an approval key |

Certificate expiry is not a separate detector: certificate findings already flow through the queue and the deadline detectors.

## Correlation

When one entity (`asset:NAME`, `app:NAME`) is named by at least 3 insights from at least 2 detectors, a compound `correlation` insight is added: impact is the strongest member
plus 0.1 per extra member, confidence is the mean, and the members are listed. Matching is on the exact entity key; the same identities the relationship graphs
(`remediation/graphs`) are built from, but the engine reads the insights' own entities rather than rebuilding a graph. There is no ontology layer in the repository to consult.

## Scoring

`score = impact x confidence x urgency x role relevance x learned weight` (0..100, every factor shown in `breakdown`). The role lens (`?role=admin|analyst|appsec|exec`;
default admin for administrators, analyst otherwise) changes only the ranking. Near-duplicates (same kind, module and primary entity) fold into the best one. At most
`max_per_role` (10) are returned.

**Learning.** Each detector's acted and dismissed counts adjust its weight: `1 + strength x (acted - dismissed) / total`, only once `min_actions` (5) actions exist, clamped
to `[0.6, 1.4]`. Snoozes are not counted. The admin sees counts and weight per detector in `GET /api/insights/settings`.

## Who sees what

Insights are computed once for everyone and filtered when read. Administrators see all. Everyone else loses insights marked admin-only (SOC, GRC, connections, licence, AI cost,
policy drift) and, if they belong to a team, insights limited to other teams. Only a person changes an insight's state; the engine never does.

## API

| Route | Who | |
|---|---|---|
| `GET /api/insights?role=&limit=&include_closed=` | login | `{enabled, role, insights[], last_refresh}` ranked, with `score` and `breakdown` |
| `GET /api/insights/{id}` | login | one insight (404 if not visible) |
| `POST /api/insights/{id}/snooze` `{days?}` | login | default 7 days, 1 to 90 |
| `POST /api/insights/{id}/dismiss` `{reason}` | login | a reason is required |
| `POST /api/insights/{id}/acted` `{reason?}` | login | |
| `POST /api/insights/refresh` | admin | `{refreshed_at, produced, new, gaps[], errors[]}` |
| `GET /api/insights/settings`, `PUT` `{settings:{...}}` | admin | thresholds in `insights.yaml`; unknown keys and wrong types are rejected |
| `POST /api/ask/structured` `{query}` | login | see below |

The leader's hourly tick refreshes (idempotent and cheap; `QUANTA_INSIGHTS=false` switches the feature off). Tables `insights` and `insight_baselines` (migration 8, additive).
Routes are `core` in `licensing.yaml`.

## Structured Ask

`POST /api/ask/structured` turns a sentence into a structured query from a fixed grammar and runs it with the asker's own permissions. The response always carries the exact
query that ran. Shapes: findings filters (severity, KEV, internet-facing, overdue / at risk, team, asset, CVE, "new in N days", "how many ..."), "what changed this week/today",
"who owns host X", "open incidents assigned to me" (administrators), "hunts for T1059" (administrators), "applications using log4j", "what should I do first".
Anything else returns `parsed: false` with suggestions and a pointer to the older keyword search (`/api/search/ask`); the Ask Quanta page tries the structured layer first and
falls back automatically. The text is only matched against a fixed vocabulary; the few free parts are cut to a strict identifier and used for in-memory comparison only.

## Honest limits

- Change detection (exposure, controls) needs a previous snapshot: the first refresh records one and says so; a change is then visible for `resolve_after_days` (3) days.
- Week-over-week uses finding first-seen dates, not a history of the queue. MTTR is not computed.
- `policy_drift` cannot know about approvals made outside Quanta; its confidence says so.
- Statistical detectors need history (14 days of alerts, 10 days of AI cost, 6 evidence collections) and say "not enough history" before then.
- Learning only reorders; it never hides or creates an insight.
- The structured grammar is small by design and is not language understanding.
- Never run against a live estate; tested against fakes and a synthetic snapshot.
