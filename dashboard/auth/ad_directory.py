"""
A real Active Directory / LDAP directory client - built against the standard LDAP
protocol (RFC 4511) via the real `ldap3` Python library (a genuinely new dependency -
there is no honest way to speak LDAP from the stdlib alone, unlike smtplib/http where a
stdlib module already exists). Used by the Remediation Approval workflow
(remediation/remediation_approvals/) to check whether the person approving a
change-managed remediation is actually a member of that policy's configured
`requires_approval_group` (remediation/config/remediation_policy.yaml).

Deliberately inert unless configured: is_configured() is False (and every lookup raises
ADNotConfiguredError, same shape as email_sender.EmailNotConfiguredError/
cli.ClaudeBinaryNotFound elsewhere in this app) unless AD_SERVER and AD_BASE_DN are set as
real environment variables - this code cannot register a real domain controller on
anyone's behalf, so it stays dormant until a real operator supplies a real AD
environment. AD_BIND_USER/AD_BIND_PASSWORD are optional (anonymous bind is enough to read
some directories' group memberships, though most real ADs require an authenticated bind -
set them if yours does).

Like every other connector in this repo, this was built against the public LDAP protocol
and Microsoft's documented AD group-membership query pattern, and has NOT been exercised
against a real Active Directory environment - no real domain controller was available
while building it. Before relying on this for a real approval gate, point it at a real
test AD environment and verify a real group-membership lookup manually first.

Firm, deliberate scope limit: this module is READ-ONLY. It never creates, modifies, or
deletes an AD object, never resets a password, never disables/enables an account. The
only operation it performs is a group-membership search - the same category of action a
"whoami /groups" command or a read-only LDAP browser would perform, nothing more.
"""
import os

import ldap3

REQUIRED_ENV_VARS = ("AD_SERVER", "AD_BASE_DN")

# The standard AD "LDAP_MATCHING_RULE_IN_CHAIN" OID - matches nested/transitive group
# membership (a user in a sub-group of the target group), not just direct membership.
# Real, documented Microsoft AD extended matching rule, not invented here.
_NESTED_GROUP_MATCH_OID = "1.2.840.113556.1.4.1941"


class ADNotConfiguredError(RuntimeError):
    pass


def is_configured():
    return all(os.environ.get(var) for var in REQUIRED_ENV_VARS)


def _connect():
    server = ldap3.Server(os.environ["AD_SERVER"], get_info=ldap3.ALL)
    bind_user = os.environ.get("AD_BIND_USER")
    bind_password = os.environ.get("AD_BIND_PASSWORD")
    if bind_user and bind_password:
        return ldap3.Connection(server, user=bind_user, password=bind_password, auto_bind=True)
    return ldap3.Connection(server, auto_bind=True)  # anonymous bind


def is_member_of_group(username, group_dn, connection=None):
    """Returns True/False for whether `username` (an AD sAMAccountName) is a direct or
    nested member of `group_dn` (a full distinguished name, e.g.
    "CN=IT-Change-Approvers,OU=Groups,DC=example,DC=com"). `connection` is injectable
    (a real or test-double ldap3.Connection) so tests never open a real network socket.
    Raises ADNotConfiguredError if AD_SERVER/AD_BASE_DN aren't set."""
    if not is_configured():
        raise ADNotConfiguredError(
            "Active Directory is not configured on this server - set AD_SERVER and "
            "AD_BASE_DN (and optionally AD_BIND_USER/AD_BIND_PASSWORD) as environment "
            "variables first.",
        )
    own_connection = connection is None
    conn = connection or _connect()
    try:
        search_filter = (
            f"(&(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)})"
            f"(memberOf:{_NESTED_GROUP_MATCH_OID}:={group_dn}))"
        )
        conn.search(os.environ["AD_BASE_DN"], search_filter, attributes=["sAMAccountName"])
        return len(conn.entries) > 0
    finally:
        if own_connection:
            conn.unbind()
