"""
Live Active Directory / LDAP asset-inventory connector - pull, like Infoblox/Axonius.

Implements a standard LDAP (RFC 4511) simple bind + computer-object search against an
on-prem Active Directory domain controller, via the real `ldap3` Python library -
already a dependency of this project (see dashboard/auth/ad_directory.py, pinned in
dashboard/requirements.txt):
  1. Bind:   ldap3.Server(server) + ldap3.Connection(server, user=bind_dn,
             password=..., auto_bind=True)
  2. Search: (objectClass=computer) against base_dn, requesting cn, dNSHostName,
             operatingSystem, operatingSystemVersion, distinguishedName, managedBy,
             userAccountControl.

A distinct concern from dashboard/auth/ad_directory.py: that module is READ-ONLY for one
narrow purpose (checking whether a named user is a member of one AD group, to gate the
remediation-approval workflow) and is configured server-wide via AD_SERVER/AD_BASE_DN
environment variables. This connector instead pulls computer objects as asset-inventory
records (name/ip/mac/type/source/source_ref/extra - the same shape infoblox_connector.py
and axonius_connector.py already produce), takes credentials per-request like the
dashboard's other new connector forms, and performs a completely separate real-world
action (bulk asset-inventory sync vs. one approval-gate lookup). Both are real, both use
ldap3, neither depends on the other.

Reference: Microsoft's documented Active Directory schema (the "computer" object class)
and RFC 4511 (LDAP). Built against this publicly documented schema and unit-tested
against a hand-rolled fake ldap3.Connection double (see tests/test_active_directory_connector.py -
the same test-double convention tests/test_ad_directory.py already established for this
repo's other LDAP code, rather than ldap3's own MOCK_SYNC strategy) - this has NOT been
exercised against a real Active Directory domain controller, because no credentials were
available while building it. Same honesty convention as every other connector here
(remediation/connectors/README.md); verify attribute names against your own domain's
schema before trusting live output - a computer object's populated attributes can vary
by AD schema version and domain functional level.

Output mapping: like infoblox_connector.py, this produces plain asset/inventory records,
not vulnerability Findings - a computer object has no vulnerability data of its own
(that comes from Tenable/Qualys/etc. actually scanning it). `ip` and `mac` are always
None: AD computer objects do not carry a network address (that's DHCP/DNS's job, not
AD's) - the same honest "don't guess what the source doesn't carry" choice
infoblox_connector.py already makes for `mac`. `type` is inferred from the
operatingSystem string (a real AD attribute, populated by the computer object itself at
domain-join time) - "server" in the OS string maps to "windows-server", any other
recognizably-Windows string maps to "windows-endpoint", anything else is honestly
"unknown" rather than guessed.
"""
import ldap3

DEFAULT_ATTRIBUTES = [
    "cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "distinguishedName", "managedBy", "userAccountControl",
]

# The standard AD "ACCOUNTDISABLE" bit within userAccountControl - a Microsoft-documented
# AD schema constant, not something this repo invented. Bit 1 (value 2) set means the
# account object is administratively disabled.
_ACCOUNTDISABLE_BIT = 2


class ActiveDirectoryConnector:
    def __init__(self, server, base_dn, bind_dn=None, bind_password=None, use_ssl=False, connection=None):
        self.server_url = server
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.use_ssl = use_ssl
        # Injectable, real-or-test-double connection - same pattern
        # dashboard/auth/ad_directory.py already establishes for this repo's other
        # LDAP code, so tests never open a real network socket.
        self._injected_connection = connection

    def _connect(self):
        """Returns (connection, owns_connection). owns_connection is False when a
        connection was injected (the caller owns its lifecycle, e.g. a test) - only a
        connection this method opens itself should later be unbound."""
        if self._injected_connection is not None:
            return self._injected_connection, False
        server = ldap3.Server(self.server_url, use_ssl=self.use_ssl, get_info=ldap3.NONE)
        if self.bind_dn and self.bind_password:
            conn = ldap3.Connection(server, user=self.bind_dn, password=self.bind_password, auto_bind=True)
        else:
            conn = ldap3.Connection(server, auto_bind=True)  # anonymous bind
        return conn, True

    def test_connection(self):
        """Cheap, real connectivity/credential check - a real LDAP simple bind (via
        _connect()) plus a trivial rootDSE-style search (search_scope BASE against
        base_dn itself, no filter match required) - the smallest real authenticated
        call this protocol offers. Used by the dashboard's "Test Connection" action."""
        conn, owns_connection = self._connect()
        try:
            conn.search(self.base_dn, "(objectClass=*)", search_scope=ldap3.BASE)
            return {"ok": True}
        finally:
            if owns_connection:
                conn.unbind()

    def fetch_computer_entries(self, search_filter="(objectClass=computer)", attributes=None):
        """Searches base_dn for AD computer objects, returning the raw list of ldap3
        Entry objects (or test-double equivalents)."""
        attributes = attributes or DEFAULT_ATTRIBUTES
        conn, owns_connection = self._connect()
        try:
            conn.search(self.base_dn, search_filter, attributes=attributes)
            return list(conn.entries)
        finally:
            if owns_connection:
                conn.unbind()

    @staticmethod
    def _attr(entry, name):
        """Safe attribute access across both a real ldap3.Entry (dot-access returns an
        Attribute wrapper with a .value) and a bare object missing the attribute
        entirely (a computer object doesn't always populate every optional field)."""
        value = getattr(entry, name, None)
        if value is None:
            return None
        return getattr(value, "value", None)

    @staticmethod
    def normalize_computer_entry(entry):
        """Maps one raw AD computer Entry into VulnHunter's shared asset shape:
            {name, ip, mac, type, source, source_ref, extra}
        See module docstring for why ip/mac are always None and how type is inferred."""
        attr = ActiveDirectoryConnector._attr
        name = attr(entry, "cn") or attr(entry, "dNSHostName")
        os_name = attr(entry, "operatingSystem") or ""
        os_lower = os_name.lower()
        if "server" in os_lower:
            asset_type = "windows-server"
        elif "windows" in os_lower:
            asset_type = "windows-endpoint"
        else:
            asset_type = "unknown"

        uac = attr(entry, "userAccountControl")
        enabled = None
        if uac is not None:
            try:
                enabled = (int(uac) & _ACCOUNTDISABLE_BIT) == 0
            except (TypeError, ValueError):
                enabled = None

        return {
            "name": name,
            "ip": None,
            "mac": None,
            "type": asset_type,
            "source": "active-directory",
            "source_ref": attr(entry, "distinguishedName"),
            "extra": {
                "dns_hostname": attr(entry, "dNSHostName"),
                "operating_system": os_name or None,
                "operating_system_version": attr(entry, "operatingSystemVersion"),
                "enabled": enabled,
                "managed_by": attr(entry, "managedBy"),
            },
        }

    def fetch_and_normalize_computers(self):
        """Orchestrates fetch_computer_entries -> normalize_computer_entry, returns
        the list of normalized asset dicts."""
        entries = self.fetch_computer_entries()
        return [self.normalize_computer_entry(e) for e in entries]
