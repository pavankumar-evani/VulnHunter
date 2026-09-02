"""
Tests for the shared SSRF guardrail (remediation/connectors/url_safety.py).

Real DNS resolution happens for hostname-based cases here (socket.getaddrinfo has no
honest offline mode) - every test either uses a literal IP address (no DNS involved) or
a hostname whose resolution is stable and safe to depend on in CI (localhost,
metadata.google.internal's own literal string check happens before any resolution).
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.url_safety import (  # noqa: E402
    UnsafeTargetError, assert_safe_instance_label, assert_safe_target,
)


class AssertSafeTargetBlocksDangerousAddresses(unittest.TestCase):
    def test_blocks_aws_gcp_azure_metadata_ip(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("169.254.169.254")

    def test_blocks_alibaba_metadata_ip(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("100.100.100.200")

    def test_blocks_metadata_ip_inside_a_full_url(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("http://169.254.169.254/latest/meta-data/")

    def test_blocks_loopback_ipv4(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("127.0.0.1")

    def test_blocks_loopback_hostname(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("localhost")

    def test_blocks_ipv6_loopback(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("::1")

    def test_blocks_link_local(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("169.254.1.1")

    def test_blocks_known_cloud_metadata_hostname(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("metadata.google.internal")

    def test_unresolvable_hostname_raises(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_target("this-host-does-not-exist.invalid")


class AssertSafeTargetAllowsLegitimateTargets(unittest.TestCase):
    def test_allows_private_rfc1918_address(self):
        """On-prem Tenable/Qualys/OpenVAS/ServiceNow is the expected common case for
        these connectors - a private address must not be treated as unsafe."""
        assert_safe_target("10.20.30.40")
        assert_safe_target("192.168.1.1")
        assert_safe_target("172.16.0.1")

    def test_allows_public_ip_literal(self):
        assert_safe_target("8.8.8.8")

    def test_allows_full_https_url_with_a_safe_host(self):
        assert_safe_target("https://qualysapi.qualys.com/api/2.0/fo/")


class AssertSafeInstanceLabel(unittest.TestCase):
    def test_accepts_a_bare_instance_name(self):
        assert_safe_instance_label("acmecorp")

    def test_accepts_hyphenated_name(self):
        assert_safe_instance_label("acme-corp-prod")

    def test_rejects_embedded_fragment_hash(self):
        """The exact real bypass this exists to close: a value like
        '169.254.169.254#' makes the fixed 'https://{instance}.service-now.com'
        template's suffix fall inside a URL fragment, which a standards-compliant
        parser drops - the real connection target becomes attacker-controlled despite
        the fixed suffix."""
        with self.assertRaises(UnsafeTargetError):
            assert_safe_instance_label("169.254.169.254#")

    def test_rejects_embedded_dot(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_instance_label("evil.com")

    def test_rejects_embedded_slash(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_instance_label("acme/../../evil")

    def test_rejects_empty_string(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_instance_label("")

    def test_rejects_none(self):
        with self.assertRaises(UnsafeTargetError):
            assert_safe_instance_label(None)


if __name__ == "__main__":
    unittest.main()
