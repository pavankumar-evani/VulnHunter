"""
Real SSRF guardrail (OWASP API Security Top 10 2023 API7, OWASP LLM Top 10 2026 #3
"Excessive Agency") shared by every connector that accepts an admin-supplied host/URL
and then makes a server-side request to it: Qualys, Prisma Cloud, Cortex XSIAM,
Infoblox, Axonius, Active Directory, OpenVAS/GVM, and the push connectors (Jira,
Splunk, ServiceNow). Before this module existed, none of them validated the
destination at all - an authenticated admin session (or a compromised one) could point
any of these at a cloud metadata endpoint (169.254.169.254, etc.) or the server's own
loopback interface and have this app fetch it on their behalf, entirely server-side.

Deliberately does NOT block private RFC1918/RFC4193 ranges by default: on-prem
security tools (an internal Tenable/Qualys/OpenVAS instance, an on-prem ServiceNow) are
the expected, legitimate common case for exactly these connectors, and a blanket
private-IP block would make this app unusable against real on-prem infrastructure -
the actual dangerous targets are the metadata/loopback/link-local ones below, not
"private" in general.

Known, disclosed limitation: this resolves DNS once, at connector-construction time,
not on every individual request the connector later makes - a sufficiently
sophisticated DNS-rebinding attack (the hostname resolves safely at check-time, then to
a blocked address on a later request) is not fully closed by this alone. Closing that
completely needs a pinned-IP HTTP transport (resolve once, connect to that literal IP
for every request in the session), a real, larger change not made here - this stops the
straightforward case (a static malicious/misconfigured target), not a live adversary
actively rebinding DNS mid-session.
"""
import ipaddress
import socket
from urllib.parse import urlparse

# Real, publicly documented cloud-provider metadata hostnames/IPs - the single most
# dangerous class of SSRF target, since they hand back real cloud credentials.
_BLOCKED_HOSTNAMES = {"metadata.google.internal", "metadata", "instance-data"}
_BLOCKED_IPS = {
    "169.254.169.254",  # AWS / GCP / Azure / OpenStack instance metadata
    "fd00:ec2::254",  # AWS IMDSv2, IPv6
    "100.100.100.200",  # Alibaba Cloud metadata
}

# A bare hostname/instance-name label (letters, digits, hyphens only) - used to validate
# fields like ServiceNow's `instance`, which this app interpolates into a fixed template
# URL (f"https://{instance}.service-now.com") rather than accepting a full URL. Without
# this, a value like "169.254.169.254#" produces a URL whose "#" starts a fragment that
# silently drops ".service-now.com" in any standards-compliant URL parser, leaving the
# real connection target attacker-controlled despite the fixed-suffix template.
_SAFE_LABEL_RE = None


def _label_re():
    global _SAFE_LABEL_RE
    if _SAFE_LABEL_RE is None:
        import re
        _SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return _SAFE_LABEL_RE


class UnsafeTargetError(ValueError):
    pass


def _is_blocked_ip(ip):
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if str(ip) in _BLOCKED_IPS:
        return True
    return False


def assert_safe_target(host_or_url):
    """Raises UnsafeTargetError if `host_or_url` (a bare hostname, or a full URL) is or
    resolves to a cloud metadata endpoint, loopback, or link-local address. Returns
    None (does not return the resolved address - callers don't need it, they only need
    this to raise or not) on a safe target. Private RFC1918/RFC4193 addresses are
    intentionally allowed - see the module docstring."""
    candidate = host_or_url.strip()
    if "://" not in candidate:
        candidate = f"//{candidate}"
    hostname = urlparse(candidate).hostname
    if not hostname:
        raise UnsafeTargetError(f"Could not parse a hostname from {host_or_url!r}.")
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise UnsafeTargetError(
            f"Refusing to connect to {hostname!r} - a known cloud metadata hostname.",
        )
    try:
        # AF_UNSPEC resolves both A and AAAA records - a target that's only unsafe over
        # IPv6 (or only over IPv4) must not slip through by checking just one family.
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Could not resolve {hostname!r}: {exc}") from exc
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if _is_blocked_ip(ip):
            raise UnsafeTargetError(
                f"Refusing to connect to {hostname!r} - resolves to {ip}, a blocked "
                f"address (loopback/link-local/cloud-metadata).",
            )


def assert_safe_instance_label(label, field_name="instance"):
    """For fields like ServiceNow's `instance` that this app interpolates into a fixed
    URL template rather than accepting as a free URL - rejects anything that isn't a
    bare DNS label (no dots, slashes, '#', '@', or other characters a URL parser could
    treat specially), then applies the same resolved-address check as
    assert_safe_target() against the real, fully-templated hostname."""
    if not _label_re().match(label or ""):
        raise UnsafeTargetError(
            f"{field_name!r} must be a bare instance name (letters, digits, hyphens "
            f"only) - got {label!r}.",
        )
