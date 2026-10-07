"""Policy for the knowledge base (remediation/config/hunt_knowledge.yaml), read fresh each time with safe defaults."""
from pathlib import Path

import yaml

PATH = Path(__file__).resolve().parents[2] / "config" / "hunt_knowledge.yaml"
DEFAULTS = {"enabled": True, "generator": {"max_groups": 6, "max_software": 4, "max_techniques": 6, "recent_hunt_days": 90, "min_estate_overlap": 0, "use_industry": True},
            "languages": ["sigma", "splunk-spl", "kql", "eql"], "report": {"max_leads": 12, "default_lookback_days": 30, "max_lookback_days": 180, "keep_versions": 10},
            "ai": {"enabled": True, "max_prompt_chars": 6000, "max_drafts_per_subject": 20}}


def load(path=None):
    try:
        with open(path or PATH, encoding="utf-8") as fh:
            got = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        got = {}
    out = {**DEFAULTS, **{k: v for k, v in got.items() if k in DEFAULTS}}
    for k in ("generator", "report", "ai"):
        out[k] = {**DEFAULTS[k], **(got.get(k) or {})}
    return out
