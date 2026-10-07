# SIEM and EDR search connectors

Quanta can run a hunt lead or an investigation's live search in the customer's own SIEM or EDR, read-only, after a person confirms. Five products sit behind one interface in
`remediation/hunting/search_base.py`.

| Connection type | Product | Query language | Reaches | Auth |
|---|---|---|---|---|
| `splunk-search` | Splunk | `splunk-spl` | `/services/search/jobs` (create, poll, results, cancel), `/services/server/info` | token or basic |
| `sentinel-search` | Microsoft Sentinel (Log Analytics) | `kql` | `POST /v1/workspaces/<id>/query` only | Entra client credentials (or a ready token) |
| `chronicle-search` | Google SecOps (Chronicle) | `udm` | one UDM search method (`SEARCH_PATH`) | OAuth2 access token you supply |
| `elastic-search` | Elasticsearch | `esql` or `eql` (a setting) | `_query`, `<index>/_eql/search`, `DELETE /_eql/search/<id>` (cancel), `GET /` | API key, bearer token or basic |
| `falcon-search` | CrowdStrike Falcon | `fql` | five read calls: token, device and alert queries, device and alert entities | OAuth2 client credentials |

## The interface

```python
conn.test_connection()                                       # a small dict, no search
conn.search(query, earliest="-24h", latest="now", max_rows=25, deadline=90)
# -> {"rows": [...], "count": N, "truncated": bool, "took_ms": N, "query_language": "kql"}
```

`count` is the full count when the product reports one (Splunk, EQL) and otherwise the rows received. Rows are flattened (`a.b.c`), clipped (30 fields, 300 characters) and capped at 100.

Every implementation: refuses the query before sending when it contains a write, administrative or code-running construct (Splunk: `delete`, `outputlookup`, `script`, ...; KQL: a leading `.`,
`set`, `externaldata`, `http_request`, `sql_request`, `invoke`, `ingest`; ES|QL: anything but `FROM` and an allow-list of read commands; EQL: must start with an event category and `where`, or
`sequence`; UDM: a YARA-L rule is refused; Falcon: only `hosts <FQL>` or `detections <FQL>`); fixes its endpoints in code, so there is no way to name another path (Falcon refuses any call
outside its five-entry allow-list); has a deadline (Splunk and an Elastic EQL search are cancelled; Log Analytics, Chronicle and Falcon have no cancel call, so a slow request is abandoned by the
client timeout and ended by the service's own limit); and maps errors to a short message (`HTTP 403: the account may not run this search`) that never contains a credential, token or response body.

Give each connection the smallest account that can search the data you hunt in. The code limits what Quanta sends; the account limits what the SIEM would accept.

## Languages and "not expressible"

`remediation/hunting/translate.py` renders the Sigma-style selections the hunt library and engine use (contains, startswith, endswith, exact match, lists as OR, several fields as AND)
as SPL, KQL, EQL, ES|QL, UDM search and a Falcon FQL host lookup, scoped to the hunt's hosts. A hunt lead stores its selection, hosts and index, so it can be rendered for whichever connection runs it.

What a language cannot say is reported, not dropped: another modifier (`re`, `cidr`, `all`), a field with no UDM mapping (`UDM_FIELDS`), a literal `*` in an EQL equality, or event data for the Falcon
host lookup (process and command-line selections are not expressible there). The lead is recorded as `not-expressible` with the reason, nothing is sent, and the hunt report lists it. Field names
are Sigma's except in UDM; the analyst maps the others to their own data model, as before.

The investigation query playbook (`remediation/config/query_playbook.yaml`) and the golden playbook carry a template per language next to `spl`; a pattern with none for the connection's language
is listed as skipped with the reason, never translated by guesswork. A follow-up's free-text "where else was this seen" search exists for SPL, KQL and ES|QL only.

## Running a hunt

`POST /api/hunting/hunts/{id}/run-all` (and the single-lead `.../queries/{index}/run`, and the investigation refresh) choose the connection by `connection_id`, else the first enabled search
connection (Splunk, Sentinel, Google SecOps, Elastic, Falcon). They keep the confirm gate (a preview first), the look-back ceiling and written justification, and the per-run cap. Each lead records
`query_run` (the exact text), `language_run`, `connection`, `window`, `took_ms` and its result (`hits`, `no-hits`, `error`, `not-expressible`); the hunt report's trial-hit rows carry
`state` (no-hit, needs-investigation, not-run, error), `language`, `query_run`, `connection` and `not_expressible_reason`, and the Markdown report lists the exact queries run.

`GET /api/hunting/hunts/{id}/run-plan?earliest=-30d&connection_id=...` is the dry-run plan: which leads would run, written in which language, in which connection, over which window, which are not
expressible and which fall past the cap. It builds no connector and contacts nothing.

## Honest limits

- Every connector was built against the vendor's public documentation and tested only against hand-rolled fakes. **None has been run against a live tenant.**
- Google SecOps: the reference for the UDM search method is thin; the path (`SEARCH_PATH`), the request fields and the response reader are isolated and tolerant, and must be checked against your tenant.
  Quanta takes an access token and does not mint one from a service-account key.
- Sentinel cancels nothing; a slow query is abandoned client-side. `count` for Log Analytics, UDM, ES|QL and Falcon is the rows received (a lower bound when `truncated`).
- Falcon is a host and detection lookup, not an event search; most hunt leads are not expressible there.
- UDM and KQL renderings use a small field mapping and `union *`; they are starting points for the analyst, not a data-model integration.
- Quanta never changes a SIEM, EDR, rule, policy or host. A person approves anything that changes an environment.
