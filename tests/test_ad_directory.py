"""
Tests for dashboard/auth/ad_directory.py - the real, read-only Active Directory/LDAP
connector used to validate remediation-approval group membership. Every test either
clears AD_SERVER/AD_BASE_DN (to test the not-configured path) or injects a fake
ldap3.Connection double (to test the search-query path) - none of these tests ever open
a real network socket or require a real domain controller.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from dashboard.auth import ad_directory  # noqa: E402


class FakeEntry:
    pass


class FakeConnection:
    """A minimal stand-in for ldap3.Connection - records the search filter it was
    called with and returns a pre-configured number of "entries"."""

    def __init__(self, entry_count=0):
        self.entry_count = entry_count
        self.entries = []
        self.last_search_filter = None
        self.last_search_base = None
        self.unbound = False

    def search(self, search_base, search_filter, attributes=None):  # noqa: ARG002
        self.last_search_base = search_base
        self.last_search_filter = search_filter
        self.entries = [FakeEntry() for _ in range(self.entry_count)]
        return True

    def unbind(self):
        self.unbound = True


class IsConfigured(unittest.TestCase):
    def setUp(self):
        self._env_backup = {k: os.environ.get(k) for k in ("AD_SERVER", "AD_BASE_DN", "AD_BIND_USER", "AD_BIND_PASSWORD")}
        for k in self._env_backup:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_not_configured_when_env_vars_absent(self):
        self.assertFalse(ad_directory.is_configured())

    def test_configured_when_server_and_base_dn_present(self):
        os.environ["AD_SERVER"] = "ldap://dc01.example.com"
        os.environ["AD_BASE_DN"] = "DC=example,DC=com"
        self.assertTrue(ad_directory.is_configured())

    def test_not_configured_when_only_one_var_present(self):
        os.environ["AD_SERVER"] = "ldap://dc01.example.com"
        self.assertFalse(ad_directory.is_configured())

    def test_is_member_of_group_raises_when_not_configured(self):
        with self.assertRaises(ad_directory.ADNotConfiguredError):
            ad_directory.is_member_of_group("alice", "CN=IT-Change-Approvers,OU=Groups,DC=example,DC=com")


class IsMemberOfGroup(unittest.TestCase):
    def setUp(self):
        self._env_backup = {k: os.environ.get(k) for k in ("AD_SERVER", "AD_BASE_DN")}
        os.environ["AD_SERVER"] = "ldap://dc01.example.com"
        os.environ["AD_BASE_DN"] = "DC=example,DC=com"

    def tearDown(self):
        for k, v in self._env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_returns_true_when_search_finds_a_member(self):
        conn = FakeConnection(entry_count=1)
        result = ad_directory.is_member_of_group("alice", "CN=IT-Change-Approvers,OU=Groups,DC=example,DC=com", connection=conn)
        self.assertTrue(result)

    def test_returns_false_when_search_finds_no_member(self):
        conn = FakeConnection(entry_count=0)
        result = ad_directory.is_member_of_group("bob", "CN=IT-Change-Approvers,OU=Groups,DC=example,DC=com", connection=conn)
        self.assertFalse(result)

    def test_search_uses_configured_base_dn(self):
        conn = FakeConnection(entry_count=0)
        ad_directory.is_member_of_group("bob", "CN=IT-Change-Approvers,OU=Groups,DC=example,DC=com", connection=conn)
        self.assertEqual(conn.last_search_base, "DC=example,DC=com")

    def test_search_filter_includes_username_and_nested_group_match_rule(self):
        conn = FakeConnection(entry_count=0)
        ad_directory.is_member_of_group("bob", "CN=IT-Change-Approvers,OU=Groups,DC=example,DC=com", connection=conn)
        self.assertIn("bob", conn.last_search_filter)
        self.assertIn("1.2.840.113556.1.4.1941", conn.last_search_filter)  # LDAP_MATCHING_RULE_IN_CHAIN
        self.assertIn("IT-Change-Approvers", conn.last_search_filter)

    def test_injected_connection_is_not_unbound_by_the_function(self):
        """An injected connection is owned by the caller (e.g. a test or a future
        connection-pooling caller) - only a connection this function opens itself
        should be unbound."""
        conn = FakeConnection(entry_count=0)
        ad_directory.is_member_of_group("bob", "CN=X,DC=example,DC=com", connection=conn)
        self.assertFalse(conn.unbound)

    def test_own_connection_is_unbound_after_use(self):
        conn = FakeConnection(entry_count=1)
        with mock.patch.object(ad_directory, "_connect", return_value=conn):
            ad_directory.is_member_of_group("alice", "CN=X,DC=example,DC=com")
        self.assertTrue(conn.unbound)


if __name__ == "__main__":
    unittest.main()
