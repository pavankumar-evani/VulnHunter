"""
Live Axonius cyber asset management connector.

Implements Axonius's documented REST API devices endpoint:
  POST {base_url}/api/devices
       body: {"page": {"offset": N, "limit": N}}
                                 -> {"assets": [ {device record}, ... ]}

Reference: Axonius's public REST API documentation (api-key/api-secret header auth,
POST-with-body pagination against /api/devices and /api/users). Built against Axonius's
publicly documented API and unit-tested against mocked HTTP - this has NOT been
exercised against a real Axonius tenant, because no credentials were available while
building it. Verify field names against your own tenant's current API version before
trusting live output - see remediation/connectors/README.md.

Response envelope caveat: the exact top-level key wrapping the device list has varied
across Axonius API versions/deployments in public docs and community reports. "assets"
is used here as the most standard/likely key - like Tenable's and Armis's own
field-name uncertainty notes, this may need adjustment against a real tenant's current
API version.

Field-flattening caveat: Axonius's real query language lets you request specific
flattened fields (e.g. "specific_data.data.hostname") via the request body's `fields`
list, and a real raw device record nests almost everything under
`specific_data.data.*`. Replicating that flattening/query-building logic in full is out
of scope for this MVP connector - normalize_device() below pragmatically assumes the
response has already been shaped with reasonably flattened top-level keys (`hostname`,
`ip`/`ips`, `mac`/`macs`, `os_type`, `adapters`). A real integration should request
those fields explicitly via the `fields` list in the request body and adjust this
mapping to match whatever shape comes back.

Output mapping: like infoblox_connector.py, this produces plain asset/inventory records
(not vulnerability Findings) - see the shared asset shape documented in
normalize_device() below.
"""
import requests

DEFAULT_PAGE_SIZE = 1000

# Best-effort, intentionally incomplete OS-type -> VulnHunter asset.type mapping (see
# remediation/schema/normalized-finding-schema.md for the full asset.type vocabulary).
# Real deployments should extend this as they encounter more `os_type` values.
OS_TYPE_TO_ASSET_TYPE = {
    "windows": "windows-server",
    "linux": "unix-server",
    "unix": "unix-server",
}


class AxoniusConnector:
    def __init__(self, base_url, api_key, api_secret, session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        # Axonius's documented auth pattern: api-key/api-secret sent as headers on
        # every request (not query params, not a login/token-exchange flow).
        self.session.headers.update({
            "api-key": api_key,
            "api-secret": api_secret,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def fetch_devices(self, page_size=DEFAULT_PAGE_SIZE, offset=0):
        """POST /api/devices with a pagination body. Returns the raw JSON response
        (an object with an "assets" array - see the module docstring's envelope-key
        caveat)."""
        resp = self.session.post(
            f"{self.base_url}/api/devices",
            json={"page": {"offset": offset, "limit": page_size}},
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def normalize_device(device):
        """Maps one raw (assumed-flattened, see module docstring) Axonius device
        record into VulnHunter's shared asset shape:
            {name, ip, mac, type, source, source_ref, extra}

        - `name` comes from a top-level `hostname` key.
        - `ip` comes from `ip` if present, else the first entry of an `ips` list.
        - `mac` comes from `mac` if present, else the first entry of a `macs` list.
        - `type` is derived from `os_type` via OS_TYPE_TO_ASSET_TYPE, defaulting to
          "unknown" when os_type is missing or unrecognized.
        - `adapters` (the list of source systems that reported this asset - a
          distinctive Axonius concept, since it aggregates from many adapters) is kept
          in `extra`, not the strict schema.
        """
        ip = device.get("ip")
        if not ip:
            ips = device.get("ips") or []
            ip = ips[0] if ips else None

        mac = device.get("mac")
        if not mac:
            macs = device.get("macs") or []
            mac = macs[0] if macs else None

        os_type = device.get("os_type")
        asset_type = OS_TYPE_TO_ASSET_TYPE.get((os_type or "").strip().lower(), "unknown")

        return {
            "name": device.get("hostname"),
            "ip": ip,
            "mac": mac,
            "type": asset_type,
            "source": "axonius",
            "source_ref": device.get("internal_axon_id"),
            "extra": {
                "adapters": device.get("adapters", []),
            },
        }

    def fetch_and_normalize_devices(self, page_size=DEFAULT_PAGE_SIZE):
        """Orchestrates a single-page fetch + normalize. Note: this does NOT loop
        through offset/limit pages until an empty page is returned - a real
        integration would need that pagination loop (same as Armis's
        search_all_pages()); a single page is fine for this MVP, documented as an
        honest scope limit rather than exhaustive pagination."""
        response = self.fetch_devices(page_size=page_size, offset=0)
        devices = response.get("assets", [])
        return [self.normalize_device(d) for d in devices]
