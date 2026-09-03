"""
Live Armis device-risk connector.

Implements Armis's documented REST API v1 auth + search flow:
  1. POST /api/v1/access_token/  (form field: secret_key)
                                 -> {"data": {"access_token": "...", "expiration_utc": ...}}
  2. GET  /api/v1/search/?aql=<query>&from=<n>&length=<n>
     (Authorization: <access_token> header on every subsequent call)
                                 -> {"data": {"results": [...], "total": N, "next": <n or null>}}

Reference: Armis's AQL (Armis Query Language) and REST API v1 docs. Like the Tenable
connector, this was built against publicly documented shapes and has NOT been exercised
against a live Armis tenant - no credentials were available while building it. Verify
field names against your tenant's current API version. See
remediation/connectors/README.md for what "tested" means here.

Output mapping: assembles alerts + their owning device's details into the same nested
{"devices": [{"alerts": [...]}]} shape as remediation/sample-data/armis_export.json, so
vuln-ingest-normalizer.md needs zero changes to consume live data.
"""
import datetime
import json
from pathlib import Path

import requests

from remediation.utils.retry import retry_with_backoff

DEFAULT_BASE_URL = "https://YOUR_INSTANCE.armis.com"
DEFAULT_ALERTS_AQL = "in:alerts"

_RETRYABLE_EXCEPTIONS = (requests.exceptions.ConnectionError, requests.exceptions.Timeout)


class ArmisAuthError(RuntimeError):
    pass


class ArmisConnector:
    def __init__(self, secret_key, base_url=DEFAULT_BASE_URL, session=None):
        self.secret_key = secret_key
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self._access_token = None

    def authenticate(self):
        def _do_post():
            resp = self.session.post(
                f"{self.base_url}/api/v1/access_token/",
                data={"secret_key": self.secret_key},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()

        data = retry_with_backoff(_do_post, retryable_exceptions=_RETRYABLE_EXCEPTIONS)
        try:
            token = data["data"]["access_token"]
        except (KeyError, TypeError):
            raise ArmisAuthError(f"Unexpected auth response shape: {data!r}")
        self._access_token = token
        self.session.headers.update({"Authorization": token})
        return token

    def _ensure_authenticated(self):
        if not self._access_token:
            self.authenticate()

    def search(self, aql_query, from_=0, length=100):
        self._ensure_authenticated()

        def _do_get():
            resp = self.session.get(
                f"{self.base_url}/api/v1/search/",
                params={"aql": aql_query, "from": from_, "length": length},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()

        return retry_with_backoff(_do_get, retryable_exceptions=_RETRYABLE_EXCEPTIONS)

    def search_all_pages(self, aql_query, page_size=100, max_pages=100):
        """Follows Armis's `next` pagination cursor until exhausted. `max_pages` is a
        safety cap so a misbehaving API can't loop forever."""
        results = []
        offset = 0
        for _ in range(max_pages):
            page = self.search(aql_query, from_=offset, length=page_size)
            data = page.get("data", {})
            results.extend(data.get("results", []))
            next_offset = data.get("next")
            if next_offset is None:
                break
            offset = next_offset
        return results

    def fetch_alerts(self, aql_query=DEFAULT_ALERTS_AQL):
        return self.search_all_pages(aql_query)

    def fetch_device(self, device_id):
        self._ensure_authenticated()

        def _do_get():
            resp = self.session.get(f"{self.base_url}/api/v1/devices/{device_id}/", timeout=30)
            resp.raise_for_status()
            return resp.json()

        return retry_with_backoff(_do_get, retryable_exceptions=_RETRYABLE_EXCEPTIONS).get("data", {})

    @staticmethod
    def _alert_to_sample_shape(alert):
        return {
            "alertType": alert.get("type", alert.get("alertType", "")),
            "title": alert.get("title", alert.get("name", "")),
            "description": alert.get("description", ""),
            "cve": alert.get("cve"),
            "firstSeen": alert.get("firstSeen", alert.get("time", "")),
            "lastSeen": alert.get("lastSeen", alert.get("time", "")),
        }

    def fetch_and_write_json(self, output_path, aql_query=DEFAULT_ALERTS_AQL):
        """Fetches live alerts, resolves each alert's owning device, and writes the
        combined result to output_path in the exact same nested shape as
        remediation/sample-data/armis_export.json - drop-in replacement for the sample
        file, no normalizer changes needed."""
        alerts = self.fetch_alerts(aql_query=aql_query)

        devices_by_id = {}
        for alert in alerts:
            device_id = alert.get("deviceId") or alert.get("device_id")
            if device_id is None:
                continue
            if device_id not in devices_by_id:
                device = self.fetch_device(device_id)
                devices_by_id[device_id] = {
                    "deviceId": device_id,
                    "deviceName": device.get("name", ""),
                    "deviceType": device.get("type", device.get("category", "")),
                    "manufacturer": device.get("manufacturer", ""),
                    "model": device.get("model", ""),
                    "ipAddress": device.get("ipAddress", device.get("ip", "")),
                    "macAddress": device.get("macAddress", device.get("mac", "")),
                    "site": device.get("site", device.get("siteName", "")),
                    "riskLevel": device.get("riskLevel", alert.get("severity", "")),
                    "alerts": [],
                }
            devices_by_id[device_id]["alerts"].append(self._alert_to_sample_shape(alert))

        output = {
            "exportedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "devices": list(devices_by_id.values()),
        }

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
        return output_path
