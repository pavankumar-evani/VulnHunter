# Threat-intelligence report watcher

The watcher reads the threat-intelligence reports an administrator points it at and turns the relevant ones into hunts. It reads; it never runs a search on a SIEM.

## Sources

Add them on **Threat Intelligence > Report sources** (admin only).

- **Feed**: any RSS 2.0, Atom 1.0, JSON Feed or plain JSON list of reports (a vendor blog, CISA advisories, ...). `https://` only; the address goes through the SSRF guard at save time and on every
  redirect; the document is capped (2 MB), read as a stream, and refused if it declares a DOCTYPE or ENTITY. Polls use `ETag` / `Last-Modified`, so an unchanged feed costs one 304. The reader
  takes the item's own text (markup stripped) and does **not** follow the link to the full article, so a teaser-only feed gives only the teaser; paste the full report on the Intel tab if needed.
- **TAXII 2.1 collection**: for credentialed platforms (MISP, OpenCTI, Anomali, ThreatConnect, any TAXII 2.1 server). Add a `taxii` connection on Connections (credentials encrypted in the vault),
  then a source naming the connection and a collection id (the Test button lists the collections the account can read). GET requests only. Each STIX `report` becomes one item whose content is a
  bundle of the report and the indicators, actors, attack patterns and vulnerabilities it references; the `added_after` cursor is kept per source.

## What happens to a new report

1. Deduped: the same (source, external id) is never read twice, and the same content (hash) is never stored twice even across sources.
2. Extracted and scored by `remediation/hunting/intel.py`: CVEs, ATT&CK techniques, actors, indicators; relevance 0 to 100 to this estate.
3. At or above `hunting.auto_create_hunt_at_or_above` (`remediation/config/soc_triage.yaml`), the hunt is created (the same as the manual "start a hunt") and the hunt engine is refreshed so the report
   is also a suggestion. Below it, the report is stored and shown.
4. **Why this triggered** is stored on the report: score, priority, the threshold, the reasons, the hosts and CVEs that matched, the source, and the decision (`created`, `below-threshold`,
   `no-threshold`, `exists`). It is returned as `why_triggered` by `GET /api/hunting/intel`.

The hunt is an ordinary proposed hunt. A person accepts it and confirms any run in the SIEM; the watcher has no search connection to use.

## Schedule

The leader tick polls each enabled source whose last poll is older than `interval_minutes` in `remediation/config/intel_watch.yaml` (default 60). With no source added it does nothing.
`QUANTA_INTEL_WATCH=false` switches the scheduled polling off (a person can still poll a source from the page, after a confirm). Limits per poll: 50 newest items read, 25 new reports stored.
A source that fails is marked `error` with a short message; the others still run.

## Time to report

The hunt report's time-to-report clock starts at the report's arrival: the source's `published_at` when it gave one, else when Quanta fetched (or was given) it. This covers a hunt made straight from
a report and a hunt accepted from a hunt-engine suggestion whose evidence names a report. Any other hunt starts at its creation. The report timing shows `clock_started_at` and
`clock_start_source` (`report-published`, `report-fetched` or `hunt-created`).

## Honest limits

Built against the public RSS, Atom, JSON Feed, TAXII 2.1 and STIX 2.1 specifications and tested against fakes; never run against a live feed or TAXII server. Platforms differ in what a STIX report
references. The relevance score is the existing explicit-rule score, not a model. Dedupe by content means an edited report with new text is a new report.
