"""Estimates the cost of an AI usage event from a price table the client maintains (remediation/config/ai_pricing.yaml)."""
import fnmatch
from pathlib import Path

import yaml

PATH = Path(__file__).resolve().parent.parent / "config" / "ai_pricing.yaml"
_CACHE = {"mtime": None, "table": None}


def load(path=None):
    path = Path(path or PATH)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}
    if _CACHE["table"] is None or _CACHE["mtime"] != (str(path), mtime):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        _CACHE["table"], _CACHE["mtime"] = (data.get("models") or {}), (str(path), mtime)
    return _CACHE["table"]


def price_for(model, table=None):
    table = load() if table is None else table
    for pattern, price in table.items():
        if fnmatch.fnmatchcase(model or "", pattern):
            return price
    return None


def estimate(row, table=None):
    """USD for the row's tokens, or None when no price is known for the model (never a guess)."""
    p = price_for(row.get("model"), table)
    if not p or p.get("input") is None or p.get("output") is None:
        return None
    cost = (row.get("input_tokens", 0) * p["input"] + row.get("output_tokens", 0) * p["output"]
            + row.get("cache_read_tokens", 0) * (p.get("cache_read") if p.get("cache_read") is not None else p["input"])
            + row.get("cache_write_tokens", 0) * (p.get("cache_write") if p.get("cache_write") is not None else p["input"])) / 1_000_000
    return round(cost, 6)
