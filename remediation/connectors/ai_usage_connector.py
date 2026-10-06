"""
Provider usage connectors: pull an organization's AI usage from the provider's own admin API into Quanta's AI usage analytics.

* AnthropicUsageConnector: the Usage & Cost Admin API, `GET /v1/organizations/usage_report/messages` (admin API key in `x-api-key`,
  `anthropic-version: 2023-06-01`; query `starting_at`, `ending_at`, `bucket_width`, repeated `group_by[]`, `limit`, `page`;
  response `data[].{starting_at, ending_at, results[]}`, `has_more`, `next_page`). Result fields used: `uncached_input_tokens`,
  `cache_creation.{ephemeral_5m,ephemeral_1h}_input_tokens`, `cache_read_input_tokens`, `output_tokens`, `model`, `workspace_id`,
  `api_key_id`. Needs an Admin API key; workspace keys do not work.
* OpenAIUsageConnector: the organization usage API, `GET /v1/organization/usage/completions` (admin key as Bearer; query `start_time`
  as epoch seconds, `bucket_width`, repeated `group_by`, `limit`, `page`; response `data[]` buckets with `start_time` and `results[]`
  carrying `input_tokens` (including cached), `input_cached_tokens`, `output_tokens`, `num_model_requests`, `model`, `project_id`),
  paged with `has_more` / `next_page`.

Both return aggregated buckets (one event = many requests, `request_count`), keyed so a re-pull updates rather than duplicates.
Neither has been run against a live account (see remediation/connectors/README.md): they are built to the providers' published
documentation and tested against hand-written responses. Each provider's schema evolves; check field names against your account first.
"""
import datetime

import requests

from remediation.connectors import url_safety

ANTHROPIC_URL = "https://api.anthropic.com/v1/organizations/usage_report/messages"
OPENAI_URL = "https://api.openai.com/v1/organization/usage/completions"
MAX_PAGES = 200


class UsageApiError(RuntimeError):
    pass


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class AnthropicUsageConnector:
    def __init__(self, admin_key, days=7, session=None, now=None):
        self.admin_key = admin_key
        self.days = max(1, min(int(days), 31))
        self.session = session or url_safety.safe_session()
        self.now = now or datetime.datetime.now(datetime.timezone.utc)

    def _get(self, params):
        r = self.session.get(ANTHROPIC_URL, params=params, timeout=60,
                             headers={"x-api-key": self.admin_key, "anthropic-version": "2023-06-01", "User-Agent": "Quanta/1.0 (usage analytics)"})
        if r.status_code in (401, 403):
            raise UsageApiError("Anthropic refused the key. The usage API needs an Admin API key (sk-ant-admin...), not a workspace API key.")
        r.raise_for_status()
        return r.json()

    def test_connection(self):
        data = self._get({"starting_at": _iso(self.now - datetime.timedelta(days=1)), "ending_at": _iso(self.now), "bucket_width": "1d", "limit": 1})
        return {"ok": True, "buckets": len(data.get("data", []))}

    def fetch_events(self):
        params = {"starting_at": _iso((self.now - datetime.timedelta(days=self.days)).replace(hour=0, minute=0, second=0, microsecond=0)),
                  "ending_at": _iso(self.now), "bucket_width": "1d", "limit": min(self.days, 31),
                  "group_by[]": ["model", "workspace_id", "api_key_id"]}
        events, page = [], None
        for _ in range(MAX_PAGES):
            data = self._get({**params, **({"page": page} if page else {})})
            for bucket in data.get("data", []):
                for r in bucket.get("results", []):
                    cc = r.get("cache_creation") or {}
                    ev = {
                        "ts": bucket["starting_at"], "provider": "anthropic", "model": r.get("model") or "unknown",
                        "application": r.get("workspace_id") or "default workspace", "user_ref": r.get("api_key_id"),
                        "input_tokens": r.get("uncached_input_tokens") or 0, "output_tokens": r.get("output_tokens") or 0,
                        "cache_read_tokens": r.get("cache_read_input_tokens") or 0,
                        "cache_write_tokens": (cc.get("ephemeral_5m_input_tokens") or 0) + (cc.get("ephemeral_1h_input_tokens") or 0),
                        "event_key": f"anthropic|{bucket['starting_at']}|{r.get('model')}|{r.get('workspace_id')}|{r.get('api_key_id')}|{r.get('service_tier')}",
                    }
                    if ev["input_tokens"] or ev["output_tokens"] or ev["cache_read_tokens"] or ev["cache_write_tokens"]:
                        events.append(ev)
            if not data.get("has_more") or not data.get("next_page"):
                return events
            page = data["next_page"]
        raise UsageApiError("Too many pages of usage data; reduce the number of days.")


class OpenAIUsageConnector:
    def __init__(self, admin_key, days=7, session=None, now=None):
        self.admin_key = admin_key
        self.days = max(1, min(int(days), 31))
        self.session = session or url_safety.safe_session()
        self.now = now or datetime.datetime.now(datetime.timezone.utc)

    def _get(self, params):
        r = self.session.get(OPENAI_URL, params=params, timeout=60, headers={"Authorization": f"Bearer {self.admin_key}", "User-Agent": "Quanta/1.0 (usage analytics)"})
        if r.status_code in (401, 403):
            raise UsageApiError("OpenAI refused the key. The organization usage API needs an Admin key, not a project API key.")
        r.raise_for_status()
        return r.json()

    def test_connection(self):
        start = int((self.now - datetime.timedelta(days=1)).timestamp())
        data = self._get({"start_time": start, "bucket_width": "1d", "limit": 1})
        return {"ok": True, "buckets": len(data.get("data", []))}

    def fetch_events(self):
        start = int((self.now - datetime.timedelta(days=self.days)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        params = {"start_time": start, "bucket_width": "1d", "limit": min(self.days, 31), "group_by": ["model", "project_id"]}
        events, page = [], None
        for _ in range(MAX_PAGES):
            data = self._get({**params, **({"page": page} if page else {})})
            for bucket in data.get("data", []):
                ts = _iso(datetime.datetime.fromtimestamp(bucket["start_time"], datetime.timezone.utc))
                for r in bucket.get("results", []):
                    cached = r.get("input_cached_tokens") or 0
                    ev = {
                        "ts": ts, "provider": "openai", "model": r.get("model") or "unknown", "application": r.get("project_id") or "default project",
                        "input_tokens": max((r.get("input_tokens") or 0) - cached, 0), "cache_read_tokens": cached, "output_tokens": r.get("output_tokens") or 0,
                        "request_count": r.get("num_model_requests") or 1,
                        "event_key": f"openai|{ts}|{r.get('model')}|{r.get('project_id')}",
                    }
                    if ev["input_tokens"] or ev["output_tokens"] or ev["cache_read_tokens"]:
                        events.append(ev)
            if not data.get("has_more") or not data.get("next_page"):
                return events
            page = data["next_page"]
        raise UsageApiError("Too many pages of usage data; reduce the number of days.")
