"""
Git host webhooks: a signed callback from GitHub or GitLab telling Quanta that one of its pull requests changed state, so Quanta need not wait for the next poll.

Verification is the point of this module, because the endpoint is reachable without a login:
  GitHub  X-Hub-Signature-256 = "sha256=" + HMAC-SHA256(secret, raw request body), compared in constant time
          (https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
  GitLab  X-Gitlab-Token must equal the secret token set on the webhook, compared in constant time
          (https://docs.gitlab.com/ee/user/project/integrations/webhooks.html)
With no secret configured the endpoint refuses everything. The payload is never trusted for anything but the pull request's URL and state, and a URL that
matches no Quanta proposal is ignored without saying whether it was close.

Built against the hosts' public documentation and unit-tested with hand-signed payloads; not yet received from a live GitHub or GitLab.
"""
import hashlib
import hmac


class WebhookError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def verify_github(secret, body, signature):
    if not secret:
        raise WebhookError("Webhook secret is not configured", 503)
    if not signature or not signature.startswith("sha256="):
        raise WebhookError("Missing or malformed signature", 401)
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise WebhookError("Signature does not match", 401)


def verify_gitlab(secret, token):
    if not secret:
        raise WebhookError("Webhook secret is not configured", 503)
    if not token or not hmac.compare_digest(secret.encode("utf-8"), token.encode("utf-8")):
        raise WebhookError("Token does not match", 401)


def provider_of(headers):
    """'github', 'gitlab' or None, from the delivery's own headers (case-insensitive)."""
    h = {k.lower(): v for k, v in headers.items()}
    if "x-hub-signature-256" in h or "x-github-event" in h:
        return "github"
    if "x-gitlab-token" in h or "x-gitlab-event" in h:
        return "gitlab"
    return None


def parse_github(event, payload):
    """{"pr_url", "state", "merged_at"} for a pull_request event that changes open/merged/closed, or None for anything else (including ping)."""
    if event != "pull_request":
        return None
    pr = payload.get("pull_request") or {}
    url = pr.get("html_url")
    if not url:
        return None
    action = payload.get("action")
    if action == "closed":
        return {"pr_url": url, "state": "merged" if pr.get("merged") else "closed", "merged_at": pr.get("merged_at")}
    if action in ("reopened", "opened", "ready_for_review", "converted_to_draft", "synchronize"):
        return {"pr_url": url, "state": "open", "merged_at": None}
    return None


def parse_gitlab(event, payload):
    if event != "Merge Request Hook":
        return None
    a = payload.get("object_attributes") or {}
    url = a.get("url")
    if not url:
        return None
    state = {"merged": "merged", "closed": "closed", "locked": "closed", "opened": "open"}.get(a.get("state"))
    if state is None:
        return None
    return {"pr_url": url, "state": state, "merged_at": a.get("merged_at") if state == "merged" else None}
