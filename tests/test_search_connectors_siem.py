"""
Read-only search connectors beyond Splunk: Microsoft Sentinel (KQL), Google SecOps (UDM), Elastic (EQL and ES|QL), CrowdStrike Falcon (host and detection
lookups) and the Splunk adapter, all behind remediation/hunting/search_base.SearchConnector. Each is tested against a hand-rolled fake session: request shape, auth
header, row and time caps, refusal of write verbs and administrative endpoints, error mapping that never leaks a credential.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation.connections import registry  # noqa: E402
from remediation.connectors import siem_search_connector as splunk  # noqa: E402
from remediation.connectors.chronicle_search_connector import ChronicleSearchConnector  # noqa: E402
from remediation.connectors.elastic_search_connector import ElasticSearchConnector  # noqa: E402
from remediation.connectors.falcon_search_connector import FalconSearchConnector  # noqa: E402
from remediation.connectors.sentinel_search_connector import SentinelSearchConnector  # noqa: E402
from remediation.hunting import search_base  # noqa: E402
from remediation.hunting.search_base import SearchError, SearchRefused  # noqa: E402

WS = "11111111-2222-3333-4444-555555555555"
INSTANCE = "projects/p1/locations/us/instances/i1"


class Resp:
    def __init__(self, data=None, status=200, headers=None):
        self._d, self.status_code, self.headers = data if data is not None else {}, status, headers or {}

    def json(self):
        return self._d

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} for url https://secret-host/?key=SECRETVALUE", response=self)


class FakeSession:
    """Answers by (method, url suffix) from `routes`; a value may be a Resp, a list of Resps (consumed in order) or an Exception to raise."""
    def __init__(self, routes=None):
        self.headers, self.auth, self.verify, self.calls, self.routes = {}, None, True, [], routes or {}

    def _answer(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, **kw})
        for (m, suffix), r in self.routes.items():
            if m == method and url.endswith(suffix):
                if isinstance(r, list):
                    r = r.pop(0) if len(r) > 1 else r[0]
                if isinstance(r, Exception):
                    raise r
                return r
        return Resp({}, 404)

    def get(self, url, **kw):
        return self._answer("GET", url, **kw)

    def post(self, url, **kw):
        return self._answer("POST", url, **kw)

    def delete(self, url, **kw):
        return self._answer("DELETE", url, **kw)

    def request(self, method, url, **kw):
        return self._answer(method, url, **kw)


def sentinel(session, **kw):
    return SentinelSearchConnector(WS, "tenant-1", "client-1", "client-secret-9", session=session, **kw)


TOKEN = ("POST", "/tenant-1/oauth2/v2.0/token")
QUERY = ("POST", f"/v1/workspaces/{WS}/query")


def la_table(n, cols=("Computer", "Type")):
    return {"tables": [{"name": "PrimaryResult", "columns": [{"name": c, "type": "string"} for c in cols], "rows": [[f"H{i}", "Event"] for i in range(n)]}]}


class SentinelTests(unittest.TestCase):
    def conn(self, rows=3, **kw):
        s = FakeSession({TOKEN: Resp({"access_token": "tok-abc"}), QUERY: Resp(la_table(rows))})
        return sentinel(s, **kw), s

    def test_request_shape_auth_and_envelope(self):
        c, s = self.conn(3)
        r = c.search('SecurityEvent | where Computer == "A"', earliest="-7d", max_rows=10)
        tok = s.calls[0]
        self.assertEqual((tok["data"]["grant_type"], tok["data"]["scope"]), ("client_credentials", "https://api.loganalytics.io/.default"))
        q = s.calls[1]
        self.assertEqual(q["headers"]["Authorization"], "Bearer tok-abc")
        self.assertTrue(q["headers"]["Prefer"].startswith("wait="))
        self.assertTrue(q["json"]["query"].endswith("| take 11"))
        start, end = q["json"]["timespan"].split("/")
        self.assertTrue(start < end)
        self.assertEqual((r["query_language"], r["count"], r["truncated"], len(r["rows"])), ("kql", 3, False, 3))
        self.assertEqual(r["rows"][0], {"Computer": "H0", "Type": "Event"})
        self.assertIn("took_ms", r)

    def test_row_cap_and_truncation(self):
        c, _ = self.conn(500)
        r = c.search("SecurityEvent", max_rows=1000)
        self.assertEqual((len(r["rows"]), r["truncated"]), (search_base.HARD_MAX_ROWS, True))

    def test_write_and_reach_out_constructs_are_refused_before_anything_is_sent(self):
        c, s = self.conn()
        for bad in (".drop table T", ".set-or-append T <| X", "T | take 1; .show tables", "set notruncation; T", "externaldata(x:string)[h@'https://x']", "T | evaluate http_request('https://x')",
                    "T | invoke foo()", "", "x" * 7000):
            with self.assertRaises(SearchRefused, msg=bad):
                c.search(bad)
        self.assertEqual(s.calls, [])
        c.search('T | where x == "externaldata"')   # inside a string it is just text
        self.assertEqual(len(s.calls), 2)

    def test_errors_are_mapped_and_never_carry_the_credential(self):
        s = FakeSession({TOKEN: Resp({"access_token": "tok-abc"}), QUERY: Resp({}, 403)})
        with self.assertRaises(SearchError) as cm:
            sentinel(s).search("T")
        self.assertIn("HTTP 403", str(cm.exception))
        for secret in ("SECRETVALUE", "secret-host", "client-secret-9", "tok-abc"):
            self.assertNotIn(secret, str(cm.exception))
        s = FakeSession({TOKEN: Resp({"access_token": "t"}), QUERY: Resp({"error": {"code": "SyntaxError"}}, 400)})
        with self.assertRaisesRegex(SearchError, "SyntaxError"):
            sentinel(s).search("T")

    def test_a_slow_query_is_abandoned_with_a_clear_message(self):
        s = FakeSession({TOKEN: Resp({"access_token": "t"}), QUERY: requests.Timeout("slow")})
        with self.assertRaisesRegex(SearchError, "did not finish within 5 seconds"):
            sentinel(s).search("T", deadline=5)

    def test_construction_and_test_connection(self):
        with self.assertRaises(ValueError):
            SentinelSearchConnector("not-a-guid", "t", "c", "s")
        with self.assertRaises(ValueError):
            SentinelSearchConnector(WS)
        s = FakeSession({TOKEN: Resp({"access_token": "t"}), QUERY: Resp({"tables": [{"name": "PrimaryResult", "columns": [{"name": "ok"}], "rows": [[1]]}]})})
        self.assertTrue(sentinel(s).test_connection()["reachable"])
        self.assertEqual(len([c for c in s.calls if c["url"].endswith("/query")]), 1)


def chronicle(session):
    return ChronicleSearchConnector("https://us-chronicle.googleapis.com/", INSTANCE, "ya29.token", session=session)


SEARCH = ("POST", f"/v1alpha/{INSTANCE}/legacy:legacyFetchUdmSearchView")


class ChronicleTests(unittest.TestCase):
    def test_request_shape_and_flattened_rows(self):
        ev = {"events": [{"event": {"principal": {"hostname": "WEB-1", "ip": ["10.0.0.1", "10.0.0.2"]}, "metadata": {"event_type": "PROCESS_LAUNCH"}}} for _ in range(3)]}
        s = FakeSession({SEARCH: Resp(ev)})
        r = chronicle(s).search('principal.hostname = "WEB-1"', earliest="-24h", max_rows=2)
        self.assertEqual(s.headers["Authorization"], "Bearer ya29.token")
        body = s.calls[0]["json"]
        self.assertEqual((body["query"], body["limit"]), ('principal.hostname = "WEB-1"', 3))
        self.assertTrue(body["timeRange"]["startTime"] < body["timeRange"]["endTime"])
        self.assertEqual((r["query_language"], len(r["rows"]), r["truncated"]), ("udm", 2, True))
        self.assertEqual(r["rows"][0]["principal.hostname"], "WEB-1")
        self.assertEqual(r["rows"][0]["principal.ip"], "10.0.0.1, 10.0.0.2")

    def test_rules_are_refused_and_only_the_search_path_is_called(self):
        s = FakeSession({SEARCH: Resp({"events": []})})
        c = chronicle(s)
        for bad in ('rule r { meta: author = "x" events: $e.metadata.event_type = "X" condition: $e }', "meta: x", ""):
            with self.assertRaises(SearchRefused):
                c.search(bad)
        c.search('principal.hostname = "A"')
        self.assertTrue(all(call["url"].endswith("legacy:legacyFetchUdmSearchView") for call in s.calls))

    def test_validation_errors_and_timeouts_map_cleanly(self):
        with self.assertRaises(ValueError):
            ChronicleSearchConnector("https://x", "not-an-instance", "t")
        with self.assertRaises(ValueError):
            ChronicleSearchConnector("https://x", INSTANCE, "")
        with self.assertRaisesRegex(SearchError, "rejected the UDM query"):
            chronicle(FakeSession({SEARCH: Resp({}, 400)})).search("x = 1")
        with self.assertRaisesRegex(SearchError, "abandoned"):
            chronicle(FakeSession({SEARCH: requests.Timeout()})).search("x = 1", deadline=3)
        with self.assertRaises(SearchError) as cm:
            chronicle(FakeSession({SEARCH: Resp({}, 401)})).search("x = 1")
        self.assertNotIn("ya29.token", str(cm.exception))


def elastic(session, language="esql", **kw):
    return ElasticSearchConnector("https://es.acme.com:9200", api_key="KEY123", language=language, session=session, **kw)


class ElasticTests(unittest.TestCase):
    def test_esql_request_shape_cap_and_columns(self):
        s = FakeSession({("POST", "/_query"): Resp({"columns": [{"name": "host.name"}, {"name": "count"}], "values": [[f"h{i}", i] for i in range(6)]})})
        r = elastic(s).search('FROM logs-* | WHERE host.name == "a" | STATS count = COUNT(*) BY host.name', earliest="-7d", max_rows=5)
        call = s.calls[0]
        self.assertEqual(s.headers["Authorization"], "ApiKey KEY123")
        self.assertTrue(call["json"]["query"].endswith("| LIMIT 6"))
        self.assertIn("range", call["json"]["filter"])
        self.assertEqual(call["params"], {"format": "json"})
        self.assertEqual((r["query_language"], len(r["rows"]), r["truncated"]), ("esql", 5, True))
        self.assertEqual(r["rows"][0], {"host.name": "h0", "count": "0"})

    def test_eql_request_shape_and_hits(self):
        hits = {"hits": {"total": {"value": 42}, "events": [{"_source": {"host": {"name": "W1"}, "process": {"name": "cmd.exe"}}}] * 3}}
        s = FakeSession({("POST", "/logs-*/_eql/search"): Resp(hits)})
        r = elastic(s, language="eql", index="logs-*").search('process where process.name : "cmd.exe"', max_rows=2)
        body = s.calls[0]["json"]
        self.assertEqual((body["size"], body["keep_on_completion"]), (2, False))
        self.assertEqual((r["query_language"], r["count"], len(r["rows"]), r["truncated"]), ("eql", 42, 2, True))
        self.assertEqual(r["rows"][0]["host.name"], "W1")

    def test_a_still_running_eql_search_is_cancelled(self):
        s = FakeSession({("POST", "/logs-*/_eql/search"): Resp({"is_running": True, "id": "abc"}), ("DELETE", "/_eql/search/abc"): Resp({})})
        with self.assertRaisesRegex(SearchError, "cancelled"):
            elastic(s, language="eql", index="logs-*").search("any where true", deadline=2)
        self.assertEqual(s.calls[-1]["method"], "DELETE")

    def test_non_read_constructs_are_refused(self):
        s = FakeSession()
        e = elastic(s)
        for bad in ("DELETE FROM x", "FROM logs-* | ENRICH policy", "FROM logs-* | WHERE x == 1 | DROP_INDEX y", "SHOW INFO", "FROM", ""):
            with self.assertRaises(SearchRefused, msg=bad):
                e.search(bad)
        q = elastic(s, language="eql")
        for bad in ("DROP INDEX x", "select * from y", "FROM logs-*"):
            with self.assertRaises(SearchRefused, msg=bad):
                q.search(bad)
        self.assertEqual(s.calls, [])

    def test_only_fixed_paths_and_index_pattern_is_validated(self):
        with self.assertRaises(ValueError):
            ElasticSearchConnector("https://es", api_key="k", index="logs-*/../_security")
        with self.assertRaises(ValueError):
            ElasticSearchConnector("https://es")
        s = FakeSession({("POST", "/_query"): Resp({"columns": [], "values": []}), ("GET", "/"): Resp({"cluster_name": "c1", "version": {"number": "8.15.0"}})})
        c = elastic(s)
        self.assertEqual(c.test_connection()["version"], "8.15.0")
        c.search("FROM logs-*")
        self.assertTrue(all(call["url"].endswith(("/_query", "/")) for call in s.calls))

    def test_basic_auth_and_error_mapping(self):
        s = FakeSession({("POST", "/_query"): Resp({}, 401)})
        c = ElasticSearchConnector("https://es", username="u", password="pw-secret-1", session=s)
        self.assertEqual(s.auth, ("u", "pw-secret-1"))
        with self.assertRaises(SearchError) as cm:
            c.search("FROM logs-*")
        self.assertIn("authentication failed", str(cm.exception))
        self.assertNotIn("pw-secret-1", str(cm.exception))
        with self.assertRaisesRegex(SearchError, "rejected the query"):
            elastic(FakeSession({("POST", "/_query"): Resp({}, 400)})).search("FROM logs-*")


FALCON_TOKEN = ("POST", "/oauth2/token")


def falcon(routes):
    r = {FALCON_TOKEN: Resp({"access_token": "ft-1"}), **routes}
    s = FakeSession(r)
    return FalconSearchConnector("cid", "csecret-77", session=s), s


class FalconTests(unittest.TestCase):
    def test_host_lookup_query_then_entities(self):
        c, s = falcon({("GET", "/devices/queries/devices/v1"): Resp({"resources": ["d1", "d2"]}),
                       ("GET", "/devices/entities/devices/v2"): Resp({"resources": [{"hostname": "WEB-1", "local_ip": "10.0.0.5", "platform_name": "Windows", "secret_field": "x"}]})})
        r = c.search("hosts hostname:'WEB-1'", earliest="-30d", max_rows=10)
        self.assertEqual(s.headers["Authorization"], "Bearer ft-1")
        q = next(x for x in s.calls if x["url"].endswith("/devices/queries/devices/v1"))
        self.assertIn("hostname:'WEB-1'", q["params"]["filter"])
        self.assertIn("last_seen:>=", q["params"]["filter"])
        self.assertEqual(q["params"]["limit"], 11)
        self.assertEqual((r["query_language"], r["rows"][0]["hostname"], "secret_field" in r["rows"][0]), ("fql", "WEB-1", False))

    def test_detection_lookup_posts_ids_to_the_entities_endpoint(self):
        c, s = falcon({("GET", "/alerts/queries/alerts/v2"): Resp({"resources": ["a:1"]}),
                       ("POST", "/alerts/entities/alerts/v2"): Resp({"resources": [{"composite_id": "a:1", "name": "Cred dump", "severity_name": "High", "device": {"hostname": "WEB-1"}}]})})
        r = c.search("detections device.hostname:'WEB-1'")
        post = next(x for x in s.calls if x["url"].endswith("/alerts/entities/alerts/v2"))
        self.assertEqual(post["json"], {"composite_ids": ["a:1"]})
        self.assertEqual((r["rows"][0]["name"], r["rows"][0]["device.hostname"]), ("Cred dump", "WEB-1"))

    def test_only_the_five_read_calls_are_reachable(self):
        c, s = falcon({})
        for method, path in (("POST", "/devices/entities/devices-actions/v2"), ("PATCH", "/alerts/entities/alerts/v3"), ("DELETE", "/devices/entities/devices/v2"),
                             ("POST", "/policy/entities/prevention/v1"), ("GET", "/devices/entities/devices-actions/v2")):
            with self.assertRaises(SearchRefused):
                c._call(method, path)
        self.assertEqual(s.calls, [])

    def test_malformed_lookups_are_refused_and_errors_do_not_leak(self):
        c, s = falcon({})
        for bad in ("devices hostname:'x'", "hosts", "hosts hostname:'x'; DROP", "contain host", "hosts " + "a" * 700, ""):
            with self.assertRaises(SearchRefused, msg=bad):
                c.search(bad)
        self.assertEqual(s.calls, [])
        c, s = falcon({("GET", "/devices/queries/devices/v1"): Resp({}, 403)})
        with self.assertRaises(SearchError) as cm:
            c.search("hosts hostname:'a'")
        self.assertNotIn("csecret-77", str(cm.exception))
        self.assertNotIn("ft-1", str(cm.exception))
        c, _ = falcon({("GET", "/devices/queries/devices/v1"): Resp({}, 400)})
        with self.assertRaisesRegex(SearchError, "rejected the filter"):
            c.search("hosts hostname:'a'")

    def test_construction(self):
        with self.assertRaises(ValueError):
            FalconSearchConnector("", "s")


class SplunkAdapterTests(unittest.TestCase):
    def test_splunk_is_a_search_connector_with_the_common_envelope(self):
        s = FakeSession({("POST", "/services/search/jobs"): Resp({"sid": "S1"}), ("GET", "/services/search/jobs/S1"): Resp({"entry": [{"content": {"isDone": True, "resultCount": 7}}]}),
                         ("GET", "/services/search/jobs/S1/results"): Resp({"results": [{"host": "A", "_time": "t"}] * 3})})
        c = splunk.SplunkSearchConnector("https://s:8089", token="tok", session=s, sleep=lambda x: None)
        self.assertIsInstance(c, search_base.SearchConnector)
        r = c.search('search host="A"', earliest="-7d", latest="now", max_rows=3)
        self.assertEqual((r["query_language"], r["count"], r["truncated"], r["sid"]), ("splunk-spl", 7, True, "S1"))
        self.assertIn("took_ms", r)
        self.assertEqual(s.calls[0]["data"]["earliest_time"], "-7d")
        self.assertIs(splunk.SearchRefused, SearchRefused)
        self.assertIs(splunk.SiemSearchError, SearchError)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        # no DNS in tests: a literal loopback / metadata address is still refused by the real guard, any other name is treated as public
        from remediation.connectors import url_safety
        real = url_safety.assert_safe_target

        def guard(target):
            if any(x in target for x in ("127.0.0.1", "169.254.169.254")):
                return real(target)
        self.p = patch.object(url_safety, "assert_safe_target", side_effect=guard)
        self.p.start()
        self.addCleanup(self.p.stop)

    def test_every_search_connection_is_a_tool_with_a_schema_and_secrets_split(self):
        for t in registry.SEARCH_TYPES:
            spec = registry.SPECS[t]
            self.assertEqual(spec["kind"], "tool", t)
            self.assertTrue(any(f["secret"] for f in spec["fields"]), t)
        cfg, sec = registry.split_values("sentinel-search", {"workspace_id": WS, "tenant_id": "t", "client_id": "c", "client_secret": "s3cret!"})
        self.assertEqual((cfg["workspace_id"], sec), (WS, {"client_secret": "s3cret!"}))
        with self.assertRaises(ValueError):
            registry.split_values("sentinel-search", {"workspace_id": WS})
        cfg, sec = registry.split_values("elastic-search", {"base_url": "https://es.acme.com:9200", "api_key": "k", "language": "eql"})
        self.assertEqual((cfg["language"], sec), ("eql", {"api_key": "k"}))
        with self.assertRaises(ValueError):
            registry.split_values("elastic-search", {"base_url": "https://es.acme.com:9200"})
        with self.assertRaises(ValueError):
            registry.split_values("chronicle-search", {"base_url": "https://us-chronicle.googleapis.com", "instance": INSTANCE})
        with self.assertRaises(ValueError):
            registry.split_values("falcon-search", {"client_id": "c"})
        cfg, sec = registry.split_values("falcon-search", {"client_id": "c", "client_secret": "s"})
        self.assertEqual(sec, {"client_secret": "s"})

    def test_ssrf_guard_applies_to_the_new_urls(self):
        with self.assertRaises(ValueError):
            registry.split_values("falcon-search", {"client_id": "c", "client_secret": "s", "base_url": "http://169.254.169.254"})
        with self.assertRaises(ValueError):
            registry.split_values("elastic-search", {"base_url": "https://127.0.0.1:9200", "api_key": "k"})

    def test_builders_make_the_right_connector_and_language(self):
        built = registry.SPECS["elastic-search"]["build"]({"base_url": "https://es.acme.com", "api_key": "k", "language": "eql"})
        self.assertEqual((built.language, built.type), ("eql", "elastic-search"))
        built = registry.SPECS["sentinel-search"]["build"]({"workspace_id": WS, "access_token": "x"})
        self.assertEqual(built.language, "kql")
        built = registry.SPECS["falcon-search"]["build"]({"client_id": "c", "client_secret": "s"})
        self.assertEqual(built.language, "fql")
        built = registry.SPECS["chronicle-search"]["build"]({"base_url": "https://us-chronicle.googleapis.com", "instance": INSTANCE, "access_token": "t"})
        self.assertEqual(built.language, "udm")

    def test_public_catalog_lists_them_and_never_a_callable(self):
        cat = {c["type"]: c for c in registry.public_catalog()}
        for t in registry.SEARCH_TYPES + ("taxii",):
            self.assertIn(t, cat)
            self.assertEqual(cat[t]["kind"], "tool")
            self.assertNotIn("build", cat[t])


if __name__ == "__main__":
    unittest.main()
