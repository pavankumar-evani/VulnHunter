# Anthropic CVD feed (threat-intel source)

Reads Anthropic's PUBLIC coordinated-vulnerability-disclosure page (https://red.anthropic.com/2026/cvd/) and its published `payload.json`. Nothing unofficial or leaked is ever read.
Read only: nothing about your estate is sent.

- Connector: `remediation/connectors/cvd_feed_connector.py` (`test_connection`, `fetch`; https only; `session=` seam; `url_safety.safe_session()`).
- Store: table `cvd_advisories` (migration 6), unique per source + advisory id; a refresh updates the row.
- Matching: `remediation/cvd/matching.py`. A CVE match against findings is exact. A name match reuses the zero-day-watch vocabulary and is NOT a version check.
  Ledger entries that have not yet revealed a project or CVE cannot match.
- Routes (Threat Detection licence, `/api/cvd`): `POST /api/cvd/test-connection` (admin), `POST /api/cvd/fetch` (admin; previews unless `confirm=true`), `GET /api/cvd/advisories` (login).
- UI: an "Anthropic CVD feed" section on Zero-day Watch (`/zero-day-watch`).
- Optional hourly refresh in the leader tick: off unless `QUANTA_CVD_FEED_REFRESH=true`.

## Honest limits

- The payload schema is not documented and `payload.json` could not be retrieved when this was built, so the parser assumes a shape and is tolerant (`FIELD_ALIASES`).
  Check the first real fetch and adjust the aliases. Never run against the live site.
- Not done: a stored connection type in the connections registry, a hook into `hunting/intel.py` scoring (its input is an extracted report, so there was no small clean fit), and an OSV CVE lookup helper.
