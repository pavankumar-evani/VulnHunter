"""
A real, append-only log of every actual Claude API call this app makes (the
/vulnhunt and /remediate pipelines via cli/vulnhunter.py, plus AI Assist and AI Trend
Analysis via dashboard/app.py) - who made it, which model, and (best-effort) how many
tokens/what it cost - so an admin can see real per-user usage instead of no visibility
at all, and so a configured per-user daily token limit (see
remediation/config/ai_governance.yaml) can actually be enforced server-side before a
real call is made, not just displayed after the fact.

Honesty note on the usage/cost numbers themselves: they come from parsing the real
`claude -p ... --output-format json` response's own reported fields - there is no
official published schema for that JSON envelope (verified: Claude Code's own --help
documents --output-format's three choices but not the response shape), so field names
are extracted defensively (multiple known real/likely key spellings tried, camelCase and
snake_case) and this module NEVER guesses a number that wasn't actually present in that
response. `extraction_ok=False` on a record is the honest "we got a response but
couldn't find usage figures in it, so cost/tokens for that call are unknown, not zero" -
never silently coerced to zero, which would make a real cap under-count real spend.

Persistence: a single local JSON file (remediation/audit/ai_usage_log.json), same
append-only, gitignored pattern as activity_log.py (real runtime output, not seed data).
"""
import datetime
import json
from pathlib import Path

from remediation.utils.file_lock import FileLock

DEFAULT_LOG_PATH = Path(__file__).resolve().parent / "ai_usage_log.json"

# Every key spelling actually seen or plausible for this field across Claude Code
# versions (see this module's docstring on why there's no single documented schema) -
# tried in order, first match wins, so a version that renames a field doesn't silently
# read as zero.
_TOKEN_FIELD_ALIASES = {
    "input_tokens": ("input_tokens", "inputTokens"),
    "output_tokens": ("output_tokens", "outputTokens"),
    "cache_creation_input_tokens": ("cache_creation_input_tokens", "cacheCreationInputTokens"),
    "cache_read_input_tokens": ("cache_read_input_tokens", "cacheReadInputTokens"),
}


def _first_present(d, aliases):
    for key in aliases:
        if key in d and isinstance(d[key], (int, float)):
            return d[key]
    return None


def extract_usage(parsed_response):
    """Given the parsed JSON object from a real `claude -p ... --output-format json`
    call, returns (model, usage_dict, total_cost_usd, extraction_ok). `usage_dict` has
    the four real token-count fields (None for any this response didn't report -
    never 0 as a stand-in for "didn't say"). `model` is the first key of a
    `model_usage`-shaped dict if present, else None - Claude Code's JSON envelope has
    no separate top-level "model" field as of this writing. extraction_ok is True only
    if at least a real cost or token figure was actually found."""
    if not isinstance(parsed_response, dict):
        return None, {k: None for k in _TOKEN_FIELD_ALIASES}, None, False

    total_cost_usd = parsed_response.get("total_cost_usd")
    if not isinstance(total_cost_usd, (int, float)):
        total_cost_usd = None

    model_usage = parsed_response.get("model_usage") or parsed_response.get("modelUsage")
    model = None
    per_model_stats = {}
    if isinstance(model_usage, dict) and model_usage:
        model = next(iter(model_usage))
        per_model_stats = model_usage[model] if isinstance(model_usage[model], dict) else {}

    usage_source = per_model_stats or parsed_response.get("usage") or {}
    usage = {
        field: _first_present(usage_source, aliases)
        for field, aliases in _TOKEN_FIELD_ALIASES.items()
    }
    extraction_ok = total_cost_usd is not None or any(v is not None for v in usage.values())
    return model, usage, total_cost_usd, extraction_ok


def _total_tokens(usage):
    return sum(v for v in usage.values() if isinstance(v, (int, float)))


def _load(path=None):
    path = Path(path) if path is not None else DEFAULT_LOG_PATH
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _save(entries, path=None):
    path = Path(path) if path is not None else DEFAULT_LOG_PATH
    path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")


def record_usage(actor, route, model, usage, total_cost_usd, extraction_ok, path=None, as_of=None):
    """Appends one real AI-call usage record and returns it. `route` is a short,
    machine-readable label for which feature made the call (e.g. "ai-assist",
    "ai-trend-analysis", "vulnhunt", "remediate")."""
    # Locked for the full read-modify-write cycle - see activity_log.py's
    # record_activity() for the exact same reasoning (two concurrent real AI calls
    # would otherwise race on `id` and one's real cost/token record could be
    # silently dropped, undercounting real spend against a configured daily cap).
    lock_path = Path(path) if path is not None else DEFAULT_LOG_PATH
    with FileLock(lock_path):
        entries = _load(path)
        entry = {
            "id": len(entries) + 1,
            "actor": actor or "unknown",
            "route": route,
            "model": model,
            "usage": usage,
            "total_tokens": _total_tokens(usage) if extraction_ok else None,
            "total_cost_usd": total_cost_usd,
            "extraction_ok": extraction_ok,
            "timestamp": (as_of or datetime.datetime.now(datetime.timezone.utc)).isoformat(),
        }
        entries.append(entry)
        _save(entries, path)
    return entry


def list_usage(path=None, actor=None, limit=None):
    """Returns entries newest-first, optionally filtered to one actor."""
    entries = list(reversed(_load(path)))
    if actor:
        entries = [e for e in entries if e["actor"] == actor]
    if limit is not None:
        entries = entries[:limit]
    return entries


def usage_by_user(path=None, since=None):
    """Returns {actor: {call_count, total_tokens, total_cost_usd, unknown_cost_calls}}
    across every recorded call, optionally only those at/after `since` (a real
    datetime.date or datetime.datetime) - the aggregation the Admin Settings page's
    per-user usage table renders. total_tokens/total_cost_usd only sum calls where
    extraction actually succeeded - unknown_cost_calls counts the rest honestly instead
    of silently treating them as zero-cost."""
    result = {}
    for e in _load(path):
        if since is not None:
            entry_time = datetime.datetime.fromisoformat(e["timestamp"])
            since_dt = since if isinstance(since, datetime.datetime) else datetime.datetime.combine(
                since, datetime.time.min, tzinfo=entry_time.tzinfo,
            )
            if entry_time < since_dt:
                continue
        actor = e["actor"]
        bucket = result.setdefault(actor, {
            "call_count": 0, "total_tokens": 0, "total_cost_usd": 0.0, "unknown_cost_calls": 0,
        })
        bucket["call_count"] += 1
        if e.get("extraction_ok"):
            bucket["total_tokens"] += e.get("total_tokens") or 0
            bucket["total_cost_usd"] += e.get("total_cost_usd") or 0.0
        else:
            bucket["unknown_cost_calls"] += 1
    return result


def tokens_used_today(actor, path=None, as_of=None):
    """Real total tokens `actor` has consumed since the start of "today" (UTC), for
    daily-limit enforcement. Only counts calls where extraction succeeded - an unknown-
    usage call can't be counted against a token cap that's measured in tokens."""
    today_start = datetime.datetime.combine(
        (as_of or datetime.datetime.now(datetime.timezone.utc)).date(),
        datetime.time.min, tzinfo=datetime.timezone.utc,
    )
    total = 0
    for e in _load(path):
        if e["actor"] != actor or not e.get("extraction_ok"):
            continue
        if datetime.datetime.fromisoformat(e["timestamp"]) >= today_start:
            total += e.get("total_tokens") or 0
    return total


def would_exceed_limit(actor, governance_config, path=None, as_of=None):
    """Returns (would_exceed: bool, limit: int|None, used_today: int) - the real,
    server-side check every AI-spending route must call before making a real API call.
    `governance_config` is the parsed ai_governance.yaml dict; a per-user override in
    `per_user_overrides` takes precedence over `daily_token_limit_per_user`. A None
    limit (the default) always means unlimited - this is an opt-in cap, not a surprise
    restriction sprung on an unconfigured deployment."""
    overrides = governance_config.get("per_user_overrides") or {}
    limit = overrides.get(actor, governance_config.get("daily_token_limit_per_user"))
    if limit is None:
        return False, None, 0
    used_today = tokens_used_today(actor, path=path, as_of=as_of)
    return used_today >= limit, limit, used_today
