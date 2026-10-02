"""
Indicator reputation connector (VirusTotal API v3) - looks up an IP, domain, file hash or URL and returns how many engines flag it.

Implements the documented v3 contract:
  GET https://www.virustotal.com/api/v3/ip_addresses/<ip>
  GET https://www.virustotal.com/api/v3/domains/<domain>
  GET https://www.virustotal.com/api/v3/files/<md5|sha1|sha256>
  GET https://www.virustotal.com/api/v3/urls/<url id>   (url id = unpadded urlsafe base64 of the URL)
  Auth: `x-apikey: <key>`. The answer's data.attributes.last_analysis_stats holds malicious / suspicious / harmless / undetected counts.

Reference: https://docs.virustotal.com/reference/overview

What leaves your network: only the indicator value (never the alert, host names or anything else). Private, loopback and link-local addresses
are never sent. An indicator the service has not seen comes back as `unknown`, which is not the same as clean. The public API is rate
limited (HTTP 429 raises ReputationError so the caller can say enrichment was unavailable instead of guessing).

Built against the public documentation and unit-tested against a hand-rolled fake. It has NOT been exercised against a real account.
"""
import base64
import ipaddress
import re

import requests

BASE = "https://www.virustotal.com/api/v3"
_HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


class ReputationError(RuntimeError):
    pass


def classify(value):
    """Returns (type, normalised value) for an indicator, or (None, None) when it is not one we will send."""
    v = (value or "").strip()
    if not v:
        return None, None
    try:
        ip = ipaddress.ip_address(v)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return None, None
        return "ip", str(ip)
    except ValueError:
        pass
    if _HASH.match(v):
        return "hash", v.lower()
    if re.match(r"^https?://", v, re.I):
        return "url", v
    if _DOMAIN.match(v):
        return "domain", v.lower()
    return None, None


class ReputationConnector:
    def __init__(self, api_key, session=None):
        if not api_key:
            raise ValueError("An API key is required")
        self.session = session or requests.Session()
        self.session.headers["x-apikey"] = api_key

    def test_connection(self):
        resp = self.session.get(f"{BASE}/ip_addresses/8.8.8.8", timeout=20)
        if resp.status_code in (401, 403):
            raise ReputationError("The API key was rejected")
        resp.raise_for_status()
        return {"ok": True}

    def lookup(self, value):
        kind, v = classify(value)
        if not kind:
            return {"indicator": value, "type": None, "result": "skipped", "reason": "not a public indicator"}
        path = {"ip": f"ip_addresses/{v}", "domain": f"domains/{v}", "hash": f"files/{v}",
                "url": "urls/" + base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")}[kind]
        resp = self.session.get(f"{BASE}/{path}", timeout=20)
        if resp.status_code == 404:
            return {"indicator": v, "type": kind, "result": "unknown", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total": 0}
        if resp.status_code == 429:
            raise ReputationError("The reputation service is rate limiting this key")
        if resp.status_code in (401, 403):
            raise ReputationError("The API key was rejected")
        resp.raise_for_status()
        stats = (((resp.json().get("data") or {}).get("attributes") or {}).get("last_analysis_stats")) or {}
        counts = {k: int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected")}
        total = sum(counts.values())
        return {"indicator": v, "type": kind, "result": "seen" if total else "unknown", **counts, "total": total}
