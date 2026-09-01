"""
Tests for the live Active Directory asset-inventory connector
(remediation/connectors/active_directory_connector.py).

Every test injects a fake ldap3.Connection/Entry double (the same convention
tests/test_ad_directory.py already established for this repo's other LDAP code) - none
of these tests ever open a real network socket or require a real domain controller.
They verify: connection ownership/unbind semantics, the test-connection search shape,
the computer-object search filter/attributes, safe attribute extraction (including a
missing/None attribute not crashing), OS-string-based type inference, the
userAccountControl ACCOUNTDISABLE-bit decode, and correct normalization into
VulnHunter's shared asset shape.

These do NOT prove the connector works against a real Active Directory domain
controller - only that it behaves correctly against objects shaped like AD's public
schema documentation. See remediation/connectors/README.md.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.active_directory_connector import (  # noqa: E402
    ActiveDirectoryConnector,
)


class FakeAttr:
    def __init__(self, value):
        self.value = value


class FakeEntry:
    """A minimal stand-in for an ldap3.Entry - only the attributes passed in are set,
    so accessing an attribute the real directory object never populated behaves the
    same as a real ldap3.Entry missing that value (via ActiveDirectoryConnector._attr's
    getattr(..., None) fallback)."""
    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, FakeAttr(v))


class FakeConnection:
    """A minimal stand-in for ldap3.Connection - records the search args it was called
    with and returns a pre-configured list of entries."""

    def __init__(self, entries=None):
        self.entries = entries or []
        self.last_search_base = None
        self.last_search_filter = None
        self.last_search_scope = None
        self.last_attributes = None
        self.unbound = False

    def search(self, search_base, search_filter, attributes=None, search_scope=None):
        self.last_search_base = search_base
        self.last_search_filter = search_filter
        self.last_attributes = attributes
        self.last_search_scope = search_scope
        return True

    def unbind(self):
        self.unbound = True


class ActiveDirectoryConnection(unittest.TestCase):
    def test_injected_connection_is_not_unbound(self):
        conn = FakeConnection()
        ad = ActiveDirectoryConnector("dc01.example.com", "DC=example,DC=com", connection=conn)
        ad.fetch_computer_entries()
        self.assertFalse(conn.unbound)

    def test_own_connection_is_unbound_after_use(self):
        import unittest.mock as mock
        conn = FakeConnection()
        ad = ActiveDirectoryConnector("dc01.example.com", "DC=example,DC=com")
        with mock.patch.object(ad, "_connect", return_value=(conn, True)):
            ad.fetch_computer_entries()
        self.assertTrue(conn.unbound)


class ActiveDirectoryTestConnection(unittest.TestCase):
    def test_searches_base_dn_with_base_scope(self):
        import ldap3
        conn = FakeConnection()
        ad = ActiveDirectoryConnector("dc01.example.com", "DC=example,DC=com", connection=conn)
        result = ad.test_connection()
        self.assertEqual(conn.last_search_base, "DC=example,DC=com")
        self.assertEqual(conn.last_search_scope, ldap3.BASE)
        self.assertEqual(result, {"ok": True})


class ActiveDirectoryFetchComputerEntries(unittest.TestCase):
    def test_uses_default_filter_and_attributes(self):
        from remediation.connectors.active_directory_connector import DEFAULT_ATTRIBUTES
        conn = FakeConnection()
        ad = ActiveDirectoryConnector("dc01.example.com", "DC=example,DC=com", connection=conn)
        ad.fetch_computer_entries()
        self.assertEqual(conn.last_search_filter, "(objectClass=computer)")
        self.assertEqual(conn.last_attributes, DEFAULT_ATTRIBUTES)

    def test_honors_custom_filter(self):
        conn = FakeConnection()
        ad = ActiveDirectoryConnector("dc01.example.com", "DC=example,DC=com", connection=conn)
        ad.fetch_computer_entries(search_filter="(&(objectClass=computer)(cn=WIN-*))")
        self.assertEqual(conn.last_search_filter, "(&(objectClass=computer)(cn=WIN-*))")

    def test_returns_configured_entries(self):
        entries = [FakeEntry(cn="host1"), FakeEntry(cn="host2")]
        conn = FakeConnection(entries=entries)
        ad = ActiveDirectoryConnector("dc01.example.com", "DC=example,DC=com", connection=conn)
        result = ad.fetch_computer_entries()
        self.assertEqual(result, entries)


class ActiveDirectoryAttr(unittest.TestCase):
    def test_returns_value_when_present(self):
        entry = FakeEntry(cn="host1")
        self.assertEqual(ActiveDirectoryConnector._attr(entry, "cn"), "host1")

    def test_returns_none_when_attribute_missing(self):
        entry = FakeEntry(cn="host1")
        self.assertIsNone(ActiveDirectoryConnector._attr(entry, "managedBy"))


class ActiveDirectoryNormalizeComputerEntry(unittest.TestCase):
    def test_normalize_maps_documented_shape(self):
        entry = FakeEntry(
            cn="WIN-DC01",
            dNSHostName="win-dc01.corp.local",
            operatingSystem="Windows Server 2019 Datacenter",
            operatingSystemVersion="10.0 (17763)",
            distinguishedName="CN=WIN-DC01,OU=Domain Controllers,DC=corp,DC=local",
            managedBy="CN=IT Admins,OU=Groups,DC=corp,DC=local",
            userAccountControl=532480,  # a real DC's typical flags - enabled
        )
        asset = ActiveDirectoryConnector.normalize_computer_entry(entry)
        self.assertEqual(asset["name"], "WIN-DC01")
        self.assertIsNone(asset["ip"])
        self.assertIsNone(asset["mac"])
        self.assertEqual(asset["type"], "windows-server")
        self.assertEqual(asset["source"], "active-directory")
        self.assertEqual(asset["source_ref"], "CN=WIN-DC01,OU=Domain Controllers,DC=corp,DC=local")
        self.assertEqual(asset["extra"]["dns_hostname"], "win-dc01.corp.local")
        self.assertEqual(asset["extra"]["operating_system"], "Windows Server 2019 Datacenter")
        self.assertTrue(asset["extra"]["enabled"])

    def test_falls_back_to_dns_hostname_when_cn_missing(self):
        entry = FakeEntry(dNSHostName="fallback-host.corp.local")
        asset = ActiveDirectoryConnector.normalize_computer_entry(entry)
        self.assertEqual(asset["name"], "fallback-host.corp.local")

    def test_workstation_os_maps_to_windows_endpoint(self):
        entry = FakeEntry(cn="LAPTOP01", operatingSystem="Windows 11 Enterprise")
        asset = ActiveDirectoryConnector.normalize_computer_entry(entry)
        self.assertEqual(asset["type"], "windows-endpoint")

    def test_non_windows_os_maps_to_unknown(self):
        entry = FakeEntry(cn="LINUXBOX", operatingSystem="Ubuntu 22.04")
        asset = ActiveDirectoryConnector.normalize_computer_entry(entry)
        self.assertEqual(asset["type"], "unknown")

    def test_missing_os_maps_to_unknown_not_a_crash(self):
        entry = FakeEntry(cn="NOOSHOST")
        asset = ActiveDirectoryConnector.normalize_computer_entry(entry)
        self.assertEqual(asset["type"], "unknown")
        self.assertIsNone(asset["extra"]["operating_system"])

    def test_disabled_account_control_bit_decodes_to_false(self):
        # 532482 = 532480 | 2 (ACCOUNTDISABLE bit set)
        entry = FakeEntry(cn="DISABLEDHOST", userAccountControl=532482)
        asset = ActiveDirectoryConnector.normalize_computer_entry(entry)
        self.assertFalse(asset["extra"]["enabled"])

    def test_missing_user_account_control_yields_none_enabled(self):
        entry = FakeEntry(cn="NOUACHOST")
        asset = ActiveDirectoryConnector.normalize_computer_entry(entry)
        self.assertIsNone(asset["extra"]["enabled"])

    def test_completely_empty_entry_does_not_crash(self):
        asset = ActiveDirectoryConnector.normalize_computer_entry(FakeEntry())
        self.assertIsNone(asset["name"])
        self.assertEqual(asset["type"], "unknown")


class ActiveDirectoryFetchAndNormalizeComputers(unittest.TestCase):
    def test_returns_normalized_list(self):
        entries = [
            FakeEntry(cn="host1", operatingSystem="Windows Server 2022"),
            FakeEntry(cn="host2", operatingSystem="Windows 10 Pro"),
        ]
        conn = FakeConnection(entries=entries)
        ad = ActiveDirectoryConnector("dc01.example.com", "DC=example,DC=com", connection=conn)
        assets = ad.fetch_and_normalize_computers()
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0]["type"], "windows-server")
        self.assertEqual(assets[1]["type"], "windows-endpoint")
        self.assertTrue(all(a["source"] == "active-directory" for a in assets))

    def test_handles_empty_directory(self):
        conn = FakeConnection(entries=[])
        ad = ActiveDirectoryConnector("dc01.example.com", "DC=example,DC=com", connection=conn)
        self.assertEqual(ad.fetch_and_normalize_computers(), [])


if __name__ == "__main__":
    unittest.main()
