"""
Live Infoblox NIOS asset-inventory connector.

Implements Infoblox NIOS's real, documented WAPI (Web API) REST interface against the
`record:host` object type:
  GET {base_url}/record:host?_return_fields=name,ipv4addrs,view,extattrs&_max_results=N
                                 -> JSON array of host-record objects

Reference: Infoblox NIOS WAPI documentation (the "WAPI Guide" shipped with every NIOS
grid, also mirrored at https://ipam.illinois.edu/wapidoc/ and similar public mirrors).
Built against Infoblox's publicly documented API and unit-tested against mocked HTTP -
this has NOT been exercised against a real Infoblox tenant/appliance, because no
credentials were available while building it. Verify field names against your own
tenant/appliance's current API version before trusting live output - see
remediation/connectors/README.md.

Output mapping: unlike the Tenable/Armis connectors (which produce vulnerability
Findings, see remediation/schema/normalized-finding-schema.md), this connector produces
plain asset/inventory records - VulnHunter's asset inventory
(remediation/inventory/asset_inventory.py) is currently built entirely from findings, not
from a real CMDB/DNS/IPAM system. See infoblox_connector's and axonius_connector's shared
asset-record shape (a plain dict with name/ip/mac/type/source/source_ref/extra) documented
in normalize_host_record() below.
"""
import requests

DEFAULT_API_VERSION = "v2.12"

# WAPI record:host fields we ask for. `extattrs` (Extensible Attributes) is included
# because it's the standard place Infoblox admins stash org-specific metadata (owner,
# environment, etc.) - kept in `extra` rather than the strict asset shape.
RETURN_FIELDS = "name,ipv4addrs,view,extattrs"


class InfobloxConnector:
    def __init__(self, grid_master, username, password, api_version=DEFAULT_API_VERSION, session=None):
        self.base_url = f"https://{grid_master}/wapi/{api_version}"
        self.session = session or requests.Session()
        # WAPI supports either Basic auth per-request or an initial session-cookie
        # login; Basic auth per request is simpler and equally real/documented (and
        # matches how ServiceNowConnector already does Basic auth in this repo).
        self.session.auth = (username, password)
        self.session.headers.update({"Accept": "application/json"})

    def fetch_host_records(self, max_results=1000):
        """GET record:host - WAPI's response is a plain JSON array of host-record
        objects (no envelope/pagination wrapper), each with `name`, `ipv4addrs` (a list
        of objects, since a single host record can have multiple IPs), `view` (the DNS
        view), and `_ref` (WAPI's own object reference string)."""
        resp = self.session.get(
            f"{self.base_url}/record:host",
            params={"_return_fields": RETURN_FIELDS, "_max_results": max_results},
        )
        resp.raise_for_status()
        return resp.json()

    def test_connection(self):
        """Cheap, real connectivity/credential check - WAPI has no dedicated 'ping'
        endpoint, so the smallest real authenticated call is a record:host fetch
        capped to a single result. Used by the dashboard's "Test Connection" action."""
        self.fetch_host_records(max_results=1)
        return {"ok": True}

    @staticmethod
    def normalize_host_record(record):
        """Maps one raw WAPI record:host object into VulnHunter's shared asset shape:
            {name, ip, mac, type, source, source_ref, extra}

        - `ip` is taken from the first entry in `ipv4addrs` (or None if there are no
          IPs on this host record at all).
        - `mac` is intentionally left None here: a `record:host` object is DNS-oriented
          and does not carry a MAC address in WAPI - MAC addresses live on Infoblox's
          `lease` or `ipv4address` objects instead, which this connector doesn't fetch
          (documented scope; a real follow-up if MAC data is specifically needed).
        - `type` is left as "unknown": WAPI host records don't carry OS/platform
          information, so asset-type classification isn't actually knowable from this
          source alone. Guessing a specific type (e.g. "unix-server") here would be
          fabricating data we don't have - honest "unknown" is the right default.
        """
        ipv4addrs = record.get("ipv4addrs") or []
        ip = ipv4addrs[0].get("ipv4addr") if ipv4addrs else None

        return {
            "name": record.get("name"),
            "ip": ip,
            "mac": None,
            "type": "unknown",
            "source": "infoblox",
            "source_ref": record.get("_ref"),
            "extra": {
                "view": record.get("view"),
                "extattrs": record.get("extattrs", {}),
            },
        }

    def fetch_and_normalize_hosts(self, max_results=1000):
        """Orchestrates fetch + normalize, returns the list of normalized asset dicts."""
        records = self.fetch_host_records(max_results=max_results)
        return [self.normalize_host_record(r) for r in records]
