"""The shape of a posture check and the context checks run in.

A *check* asks one question of the recorded data ("do internet-facing applications have a stored SBOM?") and answers with a status, the evidence it
looked at, what to do about it and, when the fix is a setting, exactly which setting. Checks are honest about what Quanta cannot observe: a question
the data cannot answer is `unknown` and is left OUT of the score (and listed), never counted as a pass and never as a fail.

    status   pass      the data shows it is in place                      score 1.0
             partial   in place for some of the estate                    score 0.0..1.0 (the share that is)
             fail      the data shows it is not in place                  score 0.0
             unknown   nothing recorded that could answer it             not scored, listed as "not observable"
             na        does not apply to this estate                      not scored

Everything is deterministic: the same recorded data always gives the same checks, in the same order.
"""
STATUSES = ("pass", "partial", "fail", "unknown", "na")
CHANGE_KINDS = ("env", "yaml", "helm", "page", "process")   # where the fix is made: an environment variable, a config YAML, a Helm value, a Quanta page, or a human process


def check(id, framework, area, title, status, *, score=None, weight=3, evidence=(), detail="", recommendation="", change=None, refs=(), data_used=()):
    """Build one check result.

    id            stable, unique, kebab-case ("zt-identity-leavers")
    framework     the framework id this belongs to (see the registry in __init__.py)
    area          the pillar / layer / phase inside the framework ("identity", "perimeter", "design")
    weight        1 (nice to have) .. 5 (a gap here is serious); how much it counts in the framework score
    score         for "partial": the share in place, 0..1. Ignored for other statuses.
    evidence      short plain facts that justify the status ("3 of 7 internet-facing applications have no SBOM")
    detail        one or two sentences on why this matters
    recommendation  the next step, in plain words
    change        optional {"kind": one of CHANGE_KINDS, "where": file/env/page, "key": setting name, "value": suggested value, "effect": what it does}
    refs          [{"label": "...", "url": "..."}] to the standard or control it comes from
    data_used     which recorded data the check read, so a reader can see what to connect to improve it
    """
    if status not in STATUSES:
        raise ValueError(f"unknown status {status!r}")
    if not 1 <= weight <= 5:
        raise ValueError("weight must be 1..5")
    if change is not None and change.get("kind") not in CHANGE_KINDS:
        raise ValueError(f"unknown change kind {change.get('kind')!r}")
    if status == "pass":
        s = 1.0
    elif status == "fail":
        s = 0.0
    elif status == "partial":
        if score is None or not 0 <= score <= 1:
            raise ValueError("a partial check needs a score between 0 and 1")
        s = round(float(score), 4)
    else:
        s = None
    return {"id": id, "framework": framework, "area": area, "title": title, "status": status, "score": s, "weight": weight,
            "evidence": [str(e) for e in evidence], "detail": detail, "recommendation": recommendation, "change": change,
            "refs": [dict(r) for r in refs], "data_used": list(data_used)}


class Context:
    """What a check may look at. Loaded once per assessment and shared, so no check reads a file or table twice.

    engine     the database engine (None means the default shared one; stores take engine=None the same way)
    findings   the normalized findings the caller may see (already team-scoped by the route)
    env        a dict of environment variables (os.environ by default), so a check can read QUANTA_* settings and tests can pass their own
    now        a datetime the check must use for "how old" questions (never the clock), so results repeat

    get(key, loader) runs `loader()` once, caches the result under `key`, and returns it. If the loader raises, the exception is recorded under
    `unavailable[key]` and None is returned, so the check reports `unknown` ("could not read X") instead of the whole assessment failing.
    """

    def __init__(self, engine=None, findings=None, env=None, now=None):
        import datetime
        import os
        self.engine = engine
        self.findings = list(findings or [])
        self.env = dict(os.environ) if env is None else dict(env)
        self.now = now or datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
        self._cache = {}
        self.unavailable = {}

    def get(self, key, loader):
        if key not in self._cache:
            try:
                self._cache[key] = loader()
            except Exception as exc:  # noqa: BLE001 - one unreadable source must not stop the assessment
                self._cache[key] = None
                self.unavailable[key] = f"{type(exc).__name__}: {exc}"[:200]
        return self._cache[key]

    def flag(self, name, default=False):
        raw = self.env.get(name)
        if raw is None or str(raw).strip() == "":
            return default
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
