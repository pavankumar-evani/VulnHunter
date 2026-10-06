"""SSRF hardening: IPv4-mapped IPv6, AWS IPv6 range, scheme allow-list, redirect re-validation, default SafeSession."""
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402
from requests.adapters import HTTPAdapter  # noqa: E402

from remediation.connectors import url_safety  # noqa: E402
from remediation.connectors.osv_connector import OsvConnector  # noqa: E402
from remediation.connectors.tenable_connector import TenableConnector  # noqa: E402

PUBLIC = "93.184.216.34"


def gai(mapping, default=PUBLIC):
    def fake(host, *a, **k):
        addr = mapping.get(host, default)
        fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
        return [(fam, socket.SOCK_STREAM, 6, "", (addr, 0))]
    return fake


class AddressTests(unittest.TestCase):
    def blocked(self, addr):
        with patch("socket.getaddrinfo", gai({"h.example": addr})):
            with self.assertRaises(url_safety.UnsafeTargetError):
                url_safety.assert_safe_target("https://h.example/")

    def test_mapped_metadata_and_loopback(self):
        self.blocked("::ffff:169.254.169.254")
        self.blocked("::ffff:127.0.0.1")

    def test_aws_ipv6_range(self):
        self.blocked("fd00:ec2::254")
        self.blocked("fd00:ec2::1")

    def test_public_allowed_and_private_still_allowed(self):
        with patch("socket.getaddrinfo", gai({"h.example": PUBLIC, "p.example": "10.1.2.3"})):
            url_safety.assert_safe_target("https://h.example/")
            url_safety.assert_safe_target("https://p.example/")

    def test_schemes(self):
        with patch("socket.getaddrinfo", gai({})):
            for u in ("ftp://h.example/x", "file:///etc/passwd", "gopher://h.example/"):
                with self.assertRaises(url_safety.UnsafeTargetError):
                    url_safety.assert_safe_target(u)
            url_safety.assert_safe_target("http://h.example/")


class Scripted(HTTPAdapter):
    def __init__(self, hops):
        super().__init__()
        self.hops = list(hops)  # [(status, location)]
        self.calls = []

    def send(self, request, **kw):
        self.calls.append(request.url)
        if not self.hops:
            raise AssertionError(f"unexpected request to {request.url}")
        status, loc = self.hops.pop(0)
        r = requests.Response()
        r.status_code = status
        r.url = request.url
        r._content = b"ok"
        if loc:
            r.headers["Location"] = loc
        r.request = request
        return r


class RedirectTests(unittest.TestCase):
    def session(self, hops):
        s = url_safety.safe_session()
        ad = Scripted(hops)
        s.mount("https://", ad)
        s.mount("http://", ad)
        return s, ad

    def test_redirect_to_metadata_refused(self):
        s, ad = self.session([(302, "http://169.254.169.254/latest/meta-data/")])
        with patch("socket.getaddrinfo", gai({"169.254.169.254": "169.254.169.254"})):
            with self.assertRaises(url_safety.UnsafeTargetError):
                s.get("https://a.example/")
        self.assertEqual(len(ad.calls), 1)

    def test_https_to_http_downgrade_refused(self):
        s, ad = self.session([(302, "http://b.example/x")])
        with patch("socket.getaddrinfo", gai({})):
            with self.assertRaises(url_safety.UnsafeTargetError):
                s.get("https://a.example/")
        self.assertEqual(len(ad.calls), 1)

    def test_safe_https_redirect_followed(self):
        s, ad = self.session([(302, "https://b.example/x"), (200, None)])
        with patch("socket.getaddrinfo", gai({})):
            r = s.get("https://a.example/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(ad.calls, ["https://a.example/", "https://b.example/x"])


class DefaultSessionTests(unittest.TestCase):
    def test_connectors_default_to_safe_session(self):
        self.assertIsInstance(TenableConnector("a", "b").session, url_safety.SafeSession)

    def test_injected_session_untouched(self):
        fake = MagicMock()
        self.assertIs(TenableConnector("a", "b", session=fake).session, fake)


class OsvBaseUrlTests(unittest.TestCase):
    def test_custom_base_url_checked(self):
        with self.assertRaises(url_safety.UnsafeTargetError):
            OsvConnector(base_url="http://169.254.169.254")
        with self.assertRaises(url_safety.UnsafeTargetError):
            OsvConnector(base_url="http://localhost:9")

    def test_default_not_resolved(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("no DNS for the default")):
            OsvConnector()


if __name__ == "__main__":
    unittest.main()
