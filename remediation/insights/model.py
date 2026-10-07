"""The insight record every detector emits. Plain dicts so they serialise as they are."""
import datetime
import hashlib

KINDS = ("risk-change", "anomaly", "correlation", "deadline", "gap", "opportunity", "drift")
ROLES = ("admin", "analyst", "appsec", "exec")
STATES = ("open", "snoozed", "dismissed", "acted")
# Modules are the eight of the sidebar (nav.js); "core" is for cross-cutting insights.
MODULES = ("soc", "appsec", "devsecops", "infra", "ai", "remediation", "grc", "admin", "core")


def stable_id(detector, key):
    """Same detector + same subject -> the same id on every refresh, so state (snoozed, dismissed) survives and the list never fills with duplicates.
    The key must name the SUBJECT (an asset, a rule, an application), never a changing number."""
    return "ins_" + hashlib.sha256(f"{detector}|{key}".encode("utf-8")).hexdigest()[:16]


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def make(detector, key, kind, module, title, what, why, *, evidence=(), impact=0.5, impact_text="", confidence=0.5, confidence_reason="",
         action_label="", action_page="", action_role="analyst", roles=None, entities=(), teams=(), admin_only=False, urgency=0.5):
    """Builds one insight. impact/confidence/urgency are 0..1; `roles` maps a role to its relevance 0..1 (missing roles get a low default in scoring).
    `entities` are typed keys such as asset:WIN-DC01 or app:payments used for cross-module correlation; `teams` limits who sees it (empty = everyone)."""
    if kind not in KINDS:
        raise ValueError(f"unknown insight kind {kind!r}")
    if module not in MODULES:
        raise ValueError(f"unknown module {module!r}")
    clamp = lambda x: max(0.0, min(1.0, float(x)))  # noqa: E731
    return {
        "id": stable_id(detector, key), "detector": detector, "kind": kind, "module": module, "title": title,
        "what": what, "why": why,
        "evidence": [dict(e) for e in evidence],
        "impact": {"value": clamp(impact), "text": impact_text},
        "confidence": {"value": clamp(confidence), "reasoning": confidence_reason},
        "urgency": clamp(urgency),
        "action": {"label": action_label, "page": action_page, "role": action_role},
        "roles": {r: clamp(v) for r, v in (roles or {}).items() if r in ROLES},
        "entities": sorted(set(entities)), "teams": sorted(set(teams)), "admin_only": bool(admin_only),
    }
