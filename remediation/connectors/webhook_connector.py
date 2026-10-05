"""
Outbound webhooks for SOAR playbooks: a chat/notification webhook, and a signed response-action webhook.

Quanta does not isolate hosts, block addresses or disable accounts itself. A response action is a signed request to an endpoint YOU own
(your SOAR, EDR automation, firewall automation or ITSM), which decides whether and how to act. The request is:

  POST <your url>
  Content-Type: application/json
  X-Quanta-Timestamp: <unix seconds>
  X-Quanta-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>" with your signing secret>
  {"action": "isolate-host", "target": "WEB-1", "alert_id": 12, "run_id": 3, "playbook": "...", "requested_by": "...", "approved_by": "...", "reason": "..."}

Verify the signature and reject a timestamp more than a few minutes old before acting. The notification webhook posts {"text": "..."} which
Slack and Microsoft Teams incoming webhooks accept.

Built against those conventions and unit-tested against a hand-rolled fake. It has NOT been exercised against a real SOAR, EDR or chat service.
"""
import hashlib
import hmac
import json
import time

import requests

ACTIONS = {
    # action: (label, destructive)
    "create-ticket": ("Open a ticket in your ITSM", False),
    "enrich-asset": ("Ask your CMDB or EDR for more about the asset", False),
    "isolate-host": ("Network-isolate a host", True),
    "block-ip": ("Block an IP address", True),
    "block-domain": ("Block a domain", True),
    "disable-account": ("Disable a user account", True),
    "revoke-sessions": ("Revoke a user's sessions and tokens", True),
    "reset-credentials": ("Force a credential reset", True),
    "quarantine-file": ("Quarantine a file by hash", True),
}


class WebhookError(RuntimeError):
    pass


def sign(secret, timestamp, body):
    return "sha256=" + hmac.new(secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()


class ResponseWebhook:
    def __init__(self, url, signing_secret, allowed_actions=None, session=None, clock=time.time):
        if not signing_secret:
            raise ValueError("A signing secret is required")
        self.url, self.secret, self.session, self.clock = url, signing_secret, session or requests.Session(), clock
        self.allowed = set(allowed_actions) if allowed_actions else set(ACTIONS)

    def send(self, action, target, context=None, timeout=20):
        if action not in ACTIONS:
            raise WebhookError(f"Unknown response action '{action}'")
        if action not in self.allowed:
            raise WebhookError(f"This connection does not allow the action '{action}'")
        if not str(target or "").strip():
            raise WebhookError("A response action needs a target")
        body = json.dumps({"action": action, "target": str(target), **(context or {})}, sort_keys=True)
        ts = str(int(self.clock()))
        resp = self.session.post(self.url, data=body, headers={"Content-Type": "application/json", "X-Quanta-Timestamp": ts, "X-Quanta-Signature": sign(self.secret, ts, body)}, timeout=timeout)
        if resp.status_code >= 400:
            raise WebhookError(f"The endpoint answered {resp.status_code}")
        return {"status": resp.status_code}

    def test_connection(self):
        return self.send("enrich-asset", "quanta-connection-test", {"test": True})


class NotifyWebhook:
    def __init__(self, url, session=None):
        self.url, self.session = url, session or requests.Session()

    def send(self, text, timeout=20):
        resp = self.session.post(self.url, json={"text": str(text)[:3500]}, timeout=timeout)
        if resp.status_code >= 400:
            raise WebhookError(f"The endpoint answered {resp.status_code}")
        return {"status": resp.status_code}

    def test_connection(self):
        return self.send("Quanta connection test")


class PolicyWebhook:
    """Sends an API protection policy, signed exactly like a response action, to an endpoint the customer owns. Quanta never changes a WAF or gateway itself: the customer's
    automation verifies the signature and timestamp, then applies, adjusts or rejects the policy in its own change process, and may report the edge result back to Quanta.

      POST <your url>   X-Quanta-Timestamp, X-Quanta-Signature (sha256= HMAC of "<timestamp>.<body>"), X-Quanta-Delivery: <delivery id>
      {"type": "api-protection-policy", "delivery_id": "...", "policy": {"id", "name", "version", "kind", "mode", "enabled", "scope", "params"}, "requested_by", "approved_by"}

    Built against those conventions and unit-tested against a hand-rolled fake. It has NOT been exercised against a real WAF-automation endpoint."""

    def __init__(self, url, signing_secret, session=None, clock=time.time):
        if not signing_secret:
            raise ValueError("A signing secret is required")
        self.url, self.secret, self.session, self.clock = url, signing_secret, session or requests.Session(), clock

    def _post(self, body_obj, delivery_id, timeout=20):
        body = json.dumps(body_obj, sort_keys=True)
        ts = str(int(self.clock()))
        resp = self.session.post(self.url, data=body, headers={"Content-Type": "application/json", "X-Quanta-Timestamp": ts, "X-Quanta-Signature": sign(self.secret, ts, body),
                                                              "X-Quanta-Delivery": str(delivery_id)}, timeout=timeout)
        if resp.status_code >= 400:
            raise WebhookError(f"The endpoint answered {resp.status_code}")
        return {"status": resp.status_code}

    def push(self, payload, timeout=20):
        if not isinstance(payload, dict) or payload.get("type") != "api-protection-policy":
            raise WebhookError("Not a policy payload")
        return self._post(payload, payload.get("delivery_id", ""), timeout)

    def test_connection(self):
        return self._post({"type": "connection-test", "note": "Quanta connection test. Nothing to apply."}, "quanta-connection-test")
