"""
Tests for remediation/connectors/splunk_connector.py. All HTTP mocked - no real Splunk
instance touched, no credentials needed. See remediation/connectors/README.md for what
this suite does and doesn't prove.
"""
import datetime
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.splunk_connector import (  # noqa: E402
    SplunkConnector, SplunkHECError, build_hec_event,
)


def fake_response(json_data):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


SAMPLE_FINDING = {
    "id": "FIND-1",
    "source": "tenable",
    "source_ref": "12345",
    "title": "MS Windows Print Spooler Remote Code Execution (PrintNightmare)",
    "description": "The Windows Print Spooler service allows remote code execution.",
    "cve": "CVE-2021-34527",
    "cvss": 8.8,
    "severity": "Critical",
    "asset": {"name": "WIN-DC01", "ip": "10.20.30.41", "type": "windows-server"},
    "recommended_fix": "Apply KB5004945.",
    "first_seen": "2026-07-28",
    "last_seen": "2026-08-02",
    "kev": {"listed": True, "date_added": "2021-11-03"},
    "epss": {"score": 0.99759, "percentile": 0.99955},
}


class BuildHecEventPureFunction(unittest.TestCase):
    """No network, no connector instance needed - this is what the dashboard's preview
    mode calls directly to show what WOULD be sent without real credentials."""

    def test_event_wraps_the_full_finding(self):
        event = build_hec_event(SAMPLE_FINDING)
        self.assertEqual(event["event"], SAMPLE_FINDING)

    def test_default_sourcetype(self):
        event = build_hec_event(SAMPLE_FINDING)
        self.assertEqual(event["sourcetype"], "vulnhunter:finding")

    def test_custom_sourcetype(self):
        event = build_hec_event(SAMPLE_FINDING, sourcetype="custom:type")
        self.assertEqual(event["sourcetype"], "custom:type")

    def test_index_omitted_when_none(self):
        event = build_hec_event(SAMPLE_FINDING)
        self.assertNotIn("index", event)

    def test_index_included_when_given(self):
        event = build_hec_event(SAMPLE_FINDING, index="vulnhunter_findings")
        self.assertEqual(event["index"], "vulnhunter_findings")

    def test_time_derived_from_last_seen(self):
        event = build_hec_event(SAMPLE_FINDING)
        expected = datetime.datetime(2026, 8, 2, tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual(event["time"], expected)

    def test_time_defaults_to_now_when_last_seen_missing(self):
        finding = {k: v for k, v in SAMPLE_FINDING.items() if k != "last_seen"}
        before = time.time()
        event = build_hec_event(finding)
        after = time.time()
        self.assertTrue(before <= event["time"] <= after)

    def test_time_defaults_to_now_when_last_seen_unparseable(self):
        finding = {**SAMPLE_FINDING, "last_seen": "not-a-date"}
        before = time.time()
        event = build_hec_event(finding)
        after = time.time()
        self.assertTrue(before <= event["time"] <= after)


class AuthAndConstruction(unittest.TestCase):
    def test_session_gets_hec_token_auth_header(self):
        session = MagicMock()
        session.headers = {}
        SplunkConnector("https://splunk:8088/services/collector/event", "hec-tok-1", session=session)
        self.assertEqual(session.headers["Authorization"], "Splunk hec-tok-1")

    def test_hec_url_stored_as_given(self):
        session = MagicMock()
        session.headers = {}
        conn = SplunkConnector("https://splunk:8088/services/collector/event", "tok", session=session)
        self.assertEqual(conn.hec_url, "https://splunk:8088/services/collector/event")


class SendEvent(unittest.TestCase):
    def _connector(self):
        session = MagicMock()
        session.headers = {}
        return SplunkConnector("https://splunk:8088/services/collector/event", "tok", session=session), session

    def test_send_event_posts_to_hec_url(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"text": "Success", "code": 0})

        conn.send_event(SAMPLE_FINDING)
        called_url = session.post.call_args.args[0]
        self.assertEqual(called_url, "https://splunk:8088/services/collector/event")

    def test_send_event_body_matches_build_hec_event(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"text": "Success", "code": 0})

        conn.send_event(SAMPLE_FINDING, sourcetype="vulnhunter:finding", index="idx1")
        sent_body = session.post.call_args.kwargs["json"]
        self.assertEqual(sent_body, build_hec_event(SAMPLE_FINDING, sourcetype="vulnhunter:finding", index="idx1"))

    def test_send_event_returns_parsed_response(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"text": "Success", "code": 0})

        result = conn.send_event(SAMPLE_FINDING)
        self.assertEqual(result, {"text": "Success", "code": 0})

    def test_send_event_raises_on_http_error(self):
        conn, session = self._connector()
        bad_resp = MagicMock()
        bad_resp.raise_for_status.side_effect = Exception("500 Server Error")
        session.post.return_value = bad_resp

        with self.assertRaises(Exception):
            conn.send_event(SAMPLE_FINDING)

    def test_send_event_raises_on_unexpected_response_shape(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"unexpected": "shape"})

        with self.assertRaises(SplunkHECError):
            conn.send_event(SAMPLE_FINDING)


class SendEventsForFindingsBatch(unittest.TestCase):
    def _connector(self):
        session = MagicMock()
        session.headers = {}
        return SplunkConnector("https://splunk:8088/services/collector/event", "tok", session=session), session

    def test_batch_sends_events_for_all_findings(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"text": "Success", "code": 0})

        results = conn.send_events_for_findings([SAMPLE_FINDING])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "sent")
        self.assertIsNone(results[0]["error"])

    def test_batch_continues_past_a_single_finding_failure(self):
        """One malformed finding must not abort the whole batch."""
        conn, session = self._connector()
        session.post.return_value = fake_response({"unexpected": "shape"})

        results = conn.send_events_for_findings([SAMPLE_FINDING, {"id": "FIND-2"}])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["status"] == "error" for r in results))
        self.assertIsNotNone(results[0]["error"])

    def test_batch_has_no_dedup_resending_same_finding_both_succeed(self):
        """Unlike ServiceNow/Jira, there is deliberately no skip-if-exists here - HEC
        events are a stream, re-sending the same finding is normal."""
        conn, session = self._connector()
        session.post.return_value = fake_response({"text": "Success", "code": 0})

        results = conn.send_events_for_findings([SAMPLE_FINDING, SAMPLE_FINDING])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["status"] == "sent" for r in results))
        self.assertEqual(session.post.call_count, 2)

    def test_batch_passes_custom_sourcetype_and_index_through(self):
        conn, session = self._connector()
        session.post.return_value = fake_response({"text": "Success", "code": 0})

        conn.send_events_for_findings([SAMPLE_FINDING], sourcetype="custom:type", index="idx2")
        sent_body = session.post.call_args.kwargs["json"]
        self.assertEqual(sent_body["sourcetype"], "custom:type")
        self.assertEqual(sent_body["index"], "idx2")


if __name__ == "__main__":
    unittest.main()
