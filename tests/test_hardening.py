"""Hardening found by static analysis: untrusted XML and the declared non-security hashes."""
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from remediation.firewall import model
from remediation.utils import digest, safe_xml

BOMB = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<config><security><rules><entry name="r"><from><member>any</member></from></entry></rules></security></config>"""
EXTERNAL = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><x>&secret;</x>'
DTD_ONLY = '<?xml version="1.0"?><!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd"><report><package name="a"/></report>'


class SafeXmlTests(unittest.TestCase):
    def test_entity_declarations_are_refused(self):
        for doc in (BOMB, EXTERNAL):
            with self.assertRaises(safe_xml.UnsafeXml):
                safe_xml.fromstring(doc)

    def test_internal_subset_without_entities_is_refused_too(self):
        with self.assertRaises(safe_xml.UnsafeXml):
            safe_xml.fromstring('<!DOCTYPE x [<!ELEMENT x ANY>]><x/>')

    def test_a_dtd_that_is_only_named_is_accepted(self):
        self.assertEqual(safe_xml.fromstring(DTD_ONLY).tag, "report")

    def test_ordinary_documents_and_bytes_parse(self):
        self.assertEqual(safe_xml.fromstring("<a><b/></a>").tag, "a")
        self.assertEqual(safe_xml.fromstring(b"<a/>").tag, "a")

    def test_malformed_xml_is_a_parse_error(self):
        with self.assertRaises(safe_xml.ParseError):
            safe_xml.fromstring("<a><b></a>")

    def test_the_firewall_importer_refuses_an_entity_bomb(self):
        with self.assertRaises(model.RuleFormatError) as ctx:
            model.from_panos_xml(BOMB, "fw1")
        self.assertIn("Entity declarations", str(ctx.exception))

    def test_the_firewall_importer_still_reads_a_normal_rulebase(self):
        xml = ('<config><security><rules><entry name="allow-web"><from><member>untrust</member></from>'
               '<to><member>trust</member></to><source><member>any</member></source><destination><member>10.0.0.5</member></destination>'
               '<service><member>tcp-443</member></service><application><member>any</member></application><action>allow</action></entry>'
               '</rules></security></config>')
        rules = model.from_panos_xml(xml, "fw1")
        self.assertEqual(len(rules), 1)


class DigestTests(unittest.TestCase):
    def test_keys_are_unchanged_from_plain_sha1(self):
        # existing stored keys must keep matching, so the output must equal the old hashlib.sha1 result
        for data in ("a|b|c", b"bytes", "ünïcode"):
            raw = data.encode("utf-8", "replace") if isinstance(data, str) else data
            self.assertEqual(digest.dedup_sha1(data).hexdigest(), hashlib.sha1(raw).hexdigest())


sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard"))
from unittest.mock import patch  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

import app as dash  # noqa: E402
import rate_limit  # noqa: E402

USER = {"email": "admin@example.test", "name": "A", "role": "admin"}


def _clear_login_limits():
    dash._LOGIN_FAIL_PER_ACCOUNT._hits.clear()
    dash._LOGIN_FAIL_PER_ADDRESS._hits.clear()


class RateLimiterPeekTests(unittest.TestCase):
    def test_blocked_records_nothing_and_record_counts(self):
        rl = rate_limit.RateLimiter(2, 60)
        self.assertFalse(rl.blocked("k", now=0))
        rl.record("k", now=0)
        rl.record("k", now=1)
        self.assertTrue(rl.blocked("k", now=2))
        self.assertFalse(rl.blocked("k", now=61))  # the oldest hit has aged out
        rl.reset("k")
        self.assertFalse(rl.blocked("k", now=2))


class LoginThrottleTests(unittest.TestCase):
    def setUp(self):
        _clear_login_limits()
        self.client = TestClient(dash.app)

    def tearDown(self):
        _clear_login_limits()

    def _login(self, ok):
        with patch.object(dash.auth_users, "verify_login", return_value=USER if ok else None):
            return self.client.post("/api/auth/login", json={"email": "admin@example.test", "password": "x"})

    def test_repeated_failures_lock_the_account_from_that_address(self):
        for _ in range(dash._LOGIN_FAIL_PER_ACCOUNT.max_requests):
            self.assertEqual(self._login(False).status_code, 401)
        blocked = self._login(False)
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Retry-After", blocked.headers)
        # even the right password is refused while locked
        self.assertEqual(self._login(True).status_code, 429)

    def test_successful_sign_ins_never_use_up_the_quota(self):
        for _ in range(dash._LOGIN_FAIL_PER_ACCOUNT.max_requests + 3):
            self.assertEqual(self._login(True).status_code, 200)

    def test_a_success_clears_that_accounts_failures(self):
        for _ in range(dash._LOGIN_FAIL_PER_ACCOUNT.max_requests - 1):
            self._login(False)
        self.assertEqual(self._login(True).status_code, 200)
        for _ in range(dash._LOGIN_FAIL_PER_ACCOUNT.max_requests - 1):
            self.assertEqual(self._login(False).status_code, 401)

    def test_trying_many_accounts_from_one_address_is_stopped(self):
        with patch.object(dash.auth_users, "verify_login", return_value=None):
            codes = [self.client.post("/api/auth/login", json={"email": f"u{i}@example.test", "password": "x"}).status_code
                     for i in range(dash._LOGIN_FAIL_PER_ADDRESS.max_requests + 1)]
        self.assertEqual(codes[:-1], [401] * dash._LOGIN_FAIL_PER_ADDRESS.max_requests)
        self.assertEqual(codes[-1], 429)


class CookieAndHeaderTests(unittest.TestCase):
    def setUp(self):
        _clear_login_limits()

    def _cookie(self, client, headers=None):
        with patch.object(dash.auth_users, "verify_login", return_value=USER):
            r = client.post("/api/auth/login", json={"email": "admin@example.test", "password": "x"}, headers=headers or {})
        return r.headers.get("set-cookie", "")

    def test_cookie_is_secure_over_https_and_not_over_plain_http(self):
        self.assertIn("Secure", self._cookie(TestClient(dash.app, base_url="https://testserver")))
        self.assertNotIn("Secure", self._cookie(TestClient(dash.app, base_url="http://testserver")))

    def test_cookie_is_secure_behind_a_tls_proxy(self):
        self.assertIn("Secure", self._cookie(TestClient(dash.app, base_url="http://testserver"), {"X-Forwarded-Proto": "https"}))

    def test_cookie_is_http_only_and_same_site(self):
        c = self._cookie(TestClient(dash.app))
        self.assertIn("HttpOnly", c)
        self.assertIn("SameSite=lax", c)

    def test_csp_defaults_on_in_production_and_can_be_forced_either_way(self):
        with patch.dict(os.environ, {"QUANTA_PRODUCTION": "true"}, clear=False):
            os.environ.pop("QUANTA_ENABLE_CSP", None)
            self.assertTrue(dash._csp_enabled())
            with patch.dict(os.environ, {"QUANTA_ENABLE_CSP": "false"}):
                self.assertFalse(dash._csp_enabled())
        with patch.dict(os.environ, {"QUANTA_ENABLE_CSP": "true"}, clear=False):
            os.environ.pop("QUANTA_PRODUCTION", None)
            self.assertTrue(dash._csp_enabled())

    def test_csp_is_off_by_default_locally(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("QUANTA_PRODUCTION", None)
            os.environ.pop("QUANTA_ENABLE_CSP", None)
            self.assertFalse(dash._csp_enabled())

    def test_isolation_headers_are_always_sent(self):
        r = TestClient(dash.app).get("/healthz")
        self.assertEqual(r.headers.get("cross-origin-opener-policy"), "same-origin")
        self.assertEqual(r.headers.get("cross-origin-resource-policy"), "same-origin")
        self.assertEqual(r.headers.get("x-frame-options"), "DENY")


if __name__ == "__main__":
    unittest.main()
