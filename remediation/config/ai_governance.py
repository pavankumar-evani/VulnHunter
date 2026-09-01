"""
Loads/saves remediation/config/ai_governance.yaml - the admin-editable policy for
which model every real Claude Code call this app makes should use, and an optional
per-user daily token cap. See that file's own comments for what each field means and
remediation/audit/ai_usage_log.py for how the cap is actually enforced.
"""
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent / "ai_governance.yaml"

# Real, current model aliases Claude Code's own --model flag documents (verified via
# `claude --help`: "Provide an alias for the latest model (e.g. 'fable', 'opus', or
# 'sonnet') or a model's full name") - the Admin Settings page offers these three plus
# "no preference" (null) rather than free-text, so a typo can't silently break every
# real AI call in this app.
MODEL_ALIASES = ("sonnet", "opus", "fable")


def load_governance(path=None):
    # Resolved inside the body, not a bound default - see exceptions/store.py's own
    # comment for why (patch.object on DEFAULT_PATH must take effect for callers that
    # omit `path`).
    path = Path(path) if path is not None else DEFAULT_PATH
    if not path.exists():
        return {"default_model": None, "daily_token_limit_per_user": None, "per_user_overrides": {}}
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("default_model", None)
    data.setdefault("daily_token_limit_per_user", None)
    data.setdefault("per_user_overrides", {})
    return data


def save_governance(default_model, daily_token_limit_per_user, per_user_overrides, path=None):
    """Validates before writing - raises ValueError on an invalid model alias or a
    negative/non-integer limit, same "fail before persisting" guardrail every other
    admin-editable config in this app uses."""
    path = Path(path) if path is not None else DEFAULT_PATH
    if default_model is not None and default_model not in MODEL_ALIASES:
        raise ValueError(f"default_model must be one of {MODEL_ALIASES} or null, got {default_model!r}")
    if daily_token_limit_per_user is not None and (
        not isinstance(daily_token_limit_per_user, int) or daily_token_limit_per_user < 0
    ):
        raise ValueError("daily_token_limit_per_user must be a non-negative integer or null")
    for user, limit in (per_user_overrides or {}).items():
        if limit is not None and (not isinstance(limit, int) or limit < 0):
            raise ValueError(f"per_user_overrides[{user!r}] must be a non-negative integer or null")

    data = {
        "default_model": default_model,
        "daily_token_limit_per_user": daily_token_limit_per_user,
        "per_user_overrides": per_user_overrides or {},
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False) + "\n", encoding="utf-8")
    return data
