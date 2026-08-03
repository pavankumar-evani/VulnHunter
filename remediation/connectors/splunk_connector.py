"""
Splunk HTTP Event Collector (HEC) connector - sends findings TO Splunk as events.

Implements Splunk's documented HEC ingestion contract:
  - Auth: token in an `Authorization: Splunk <token>` header (not Basic auth, not OAuth).
  - POST <hec_url>  ({"event": {...}, "sourcetype": "...", "time": <unix ts>, ["index": "..."]})
    -> {"text": "Success", "code": 0} on success.

Reference: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector

This is genuinely one-directional and push-based - the *opposite* direction of the
Tenable/Armis/CrowdStrike connectors in this package, which pull data out of the vendor
using the vendor's own auth and query APIs. Here, VulnHunter is the client making the
call, but Splunk is the destination, not the source: this module hands a finding to
Splunk as a log event, the same way an app would ship any other event to a SIEM. That's
a deliberate, honest description of what this integration actually is, not a limitation
of what could be built - see remediation/connectors/generic_connector.py's module
docstring for the same kind of directionality note on the inbound-webhook adapter.

Like the Tenable/Armis/ServiceNow/Jira connectors, this was built against Splunk's
publicly documented HEC contract and has NOT been exercised against a real Splunk
instance - no credentials were available while building it. See
remediation/connectors/README.md for what "tested" means here.
"""
import datetime
import time as _time

import requests

DEFAULT_SOURCETYPE = "vulnhunter:finding"


class SplunkHECError(RuntimeError):
    pass


def _event_time(finding):
    """Unix timestamp for the HEC event: derived from the finding's last_seen date
    (YYYY-MM-DD, per normalized-finding-schema.md) if present and parseable, else the
    current time."""
    last_seen = finding.get("last_seen")
    if last_seen:
        try:
            dt = datetime.datetime.strptime(last_seen, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
            return dt.timestamp()
        except (ValueError, TypeError):
            pass
    return _time.time()


def build_hec_event(finding, sourcetype=DEFAULT_SOURCETYPE, index=None):
    """Builds the HEC event envelope for one finding - pure function, no network, so
    callers (like the dashboard's preview mode) can show exactly what would be sent
    without needing real credentials or a live Splunk instance.

    The whole normalized finding dict is passed through as the event body (rather than
    a hand-picked subset) so nothing gets silently dropped before it reaches Splunk -
    id/title/severity/asset/cve/kev/epss and everything else in
    normalized-finding-schema.md all land as fields on the indexed event."""
    event = {
        "event": dict(finding),
        "sourcetype": sourcetype,
        "time": _event_time(finding),
    }
    # Splunk uses the HEC token's configured default index when none is given -
    # only include the key at all when the caller wants to override that.
    if index is not None:
        event["index"] = index
    return event


class SplunkConnector:
    def __init__(self, hec_url, hec_token, session=None):
        self.hec_url = hec_url
        self.session = session or requests.Session()
        self.session.headers["Authorization"] = f"Splunk {hec_token}"

    def send_event(self, finding, sourcetype=DEFAULT_SOURCETYPE, index=None):
        """Sends one finding to Splunk as a HEC event. Returns the parsed HEC
        acknowledgement response (`{"text": "Success", "code": 0}` on success)."""
        body = build_hec_event(finding, sourcetype=sourcetype, index=index)
        resp = self.session.post(self.hec_url, json=body)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or "text" not in data:
            raise SplunkHECError(f"Unexpected HEC response shape: {data!r}")
        return data

    def send_events_for_findings(self, findings, sourcetype=DEFAULT_SOURCETYPE, index=None):
        """Sends a whole findings list to Splunk. Returns a list of
        {finding_id, status, error} per finding - never raises for a single finding's
        failure, so one bad record doesn't abort the whole batch.

        Deliberately no idempotency/dedup check here, unlike ServiceNow/Jira's
        find-existing-then-skip pattern: HEC events are an append-only stream, not a
        ticket system, and re-sending the same finding on a pipeline re-run is normal
        and expected for a SIEM (Splunk correlates/dedups downstream in search, not at
        ingest time). There's no "skip if exists" that maps onto that model, so this
        doesn't try to fake one."""
        results = []
        for f in findings:
            try:
                self.send_event(f, sourcetype=sourcetype, index=index)
                results.append({"finding_id": f["id"], "status": "sent", "error": None})
            except Exception as exc:  # noqa: BLE001 - one failure must not abort the batch
                results.append({"finding_id": f.get("id", "?"), "status": "error", "error": str(exc)})
        return results
