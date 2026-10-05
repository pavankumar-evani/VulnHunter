"""
The release gate: one decision, with reasons, that a CI/CD job can act on.

Policy is data (remediation/config/pipeline_gates.yaml). Evaluation is deterministic: the same findings, scan uploads and SBOM always give the same answer,
and each rule says which findings or which missing evidence caused a failure. Every evaluation is recorded (table gate_runs), so the gate's history is
evidence in its own right.

What it cannot do: it judges what Quanta has been told. A scan that was not uploaded is reported by `required_scans`, not assumed clean; a finding the
scanners missed is not a finding. The gate is a policy check, not a security guarantee.
"""
import datetime
import hashlib
import json
from pathlib import Path

import yaml
from sqlalchemy import insert, select

from remediation.utils import db as db_module

PATH = Path(__file__).resolve().parent.parent / "config" / "pipeline_gates.yaml"
SEV = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
MODES = ("block", "warn", "off")


def load(path=None):
    p = Path(path or PATH)
    raw = p.read_text(encoding="utf-8")
    pol = yaml.safe_load(raw) or {}
    for env, modes in (pol.get("environments") or {}).items():
        for rule, mode in list(modes.items()):
            if mode is False:  # an unquoted `off` is a boolean in YAML
                modes[rule] = mode = "off"
            if rule not in (pol.get("rules") or {}):
                raise ValueError(f"pipeline_gates.yaml: environment {env} names the unknown rule {rule}")
            if mode not in MODES:
                raise ValueError(f"pipeline_gates.yaml: {env}.{rule} must be one of {', '.join(MODES)}")
    if pol.get("default_environment") not in (pol.get("environments") or {}):
        raise ValueError("pipeline_gates.yaml: default_environment must be one of the environments")
    pol["_version"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return pol


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _age_days(stamp, now):
    try:
        d = datetime.datetime.strptime(str(stamp)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        try:
            d = datetime.datetime.strptime(str(stamp)[:10], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return None
    return (now - d).total_seconds() / 86400.0


def _fixable(f):
    return bool((f.get("dependency") or {}).get("fixed_version")) or (f.get("remediation_domain") and f.get("recommended_fix"))


def evaluate(application, environment, findings, scan_runs, sbom_summary, policy=None, now=None):
    """findings: the application's open findings (already filtered by the caller); scan_runs: its scan uploads; sbom_summary: {uploaded_at, ...} or None."""
    pol = policy or load()
    now = now or _now()
    env = environment if environment in pol["environments"] else pol["default_environment"]
    modes = pol["environments"][env]
    live = [f for f in findings if not f.get("exception") and f.get("status") not in ("resolved", "closed")]
    results = []

    def add(rule, ok, detail, ids=None):
        mode = modes.get(rule, "off")
        status = "skipped" if mode == "off" else ("pass" if ok else ("fail" if mode == "block" else "warn"))
        results.append({"id": rule, "title": pol["rules"][rule]["title"], "mode": mode, "status": status, "detail": detail, "finding_ids": (ids or [])[:50]})

    r = pol["rules"]
    over = []
    for sev, limit in (r["open_severity"].get("limits") or {}).items():
        mine = [f for f in live if f.get("severity") == sev]
        if len(mine) > limit:
            over.append((sev, limit, mine))
    add("open_severity", not over, ("; ".join(f"{len(m)} open {s} finding(s), limit {lim}" for s, lim, m in over) or "Within the limits."), [f["id"] for _, _, m in over for f in m])
    kev = [f for f in live if (f.get("kev") or {}).get("listed")]
    add("known_exploited", not kev, f"{len(kev)} open finding(s) are on the CISA known-exploited list." if kev else "None are on the known-exploited list.", [f["id"] for f in kev])
    floor = SEV.get(r["fixable_overdue"]["severity_at_least"], 1)
    overdue = [f for f in live if SEV.get(f.get("severity"), 9) <= floor and _fixable(f) and (_age_days(f.get("first_seen"), now) or 0) > r["fixable_overdue"]["older_than_days"]]
    add("fixable_overdue", not overdue, (f"{len(overdue)} {r['fixable_overdue']['severity_at_least']}-or-above finding(s) have had a fix available for more than {r['fixable_overdue']['older_than_days']} days."
                                          if overdue else "No fixable finding is overdue."), [f["id"] for f in overdue])
    need, age = r["required_scans"]["scan_types"], r["required_scans"]["max_age_days"]
    missing = []
    for st in need:
        latest = max((x["received_at"] for x in scan_runs if x["scan_type"] == st), default=None)
        a = _age_days(latest, now) if latest else None
        if a is None or a > age:
            missing.append(f"{st} ({'never uploaded' if a is None else f'last {int(a)} days ago'})")
    add("required_scans", not missing, ("Missing or stale: " + ", ".join(missing)) if missing else f"All of {', '.join(need)} ran within {age} days.")
    sage = _age_days(sbom_summary["uploaded_at"], now) if sbom_summary else None
    add("sbom", sbom_summary is not None and sage is not None and sage <= r["sbom"]["max_age_days"],
        "No SBOM is stored for this application." if not sbom_summary else (f"The SBOM is {int(sage)} days old; the limit is {r['sbom']['max_age_days']}." if sage > r["sbom"]["max_age_days"] else f"The SBOM is {int(sage)} days old."))
    sec = [f for f in live if f.get("scan_type") == "secrets"]
    add("secrets", not sec, f"{len(sec)} open secret finding(s)." if sec else "No open secret findings.", [f["id"] for f in sec])
    fails = [x for x in results if x["status"] == "fail"]
    warns = [x for x in results if x["status"] == "warn"]
    decision = "fail" if fails else ("warn" if warns else "pass")
    return {"application": application, "environment": env, "requested_environment": environment, "decision": decision, "rules": results,
            "summary": {"failed": len(fails), "warned": len(warns), "passed": sum(1 for x in results if x["status"] == "pass"), "skipped": sum(1 for x in results if x["status"] == "skipped")},
            "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "policy_version": pol["_version"],
            "note": "The gate judges what Quanta has been told: a scan that was not uploaded is reported, not assumed clean."}


def record(result, actor, engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.begin() as conn:
        conn.execute(insert(db_module.gate_runs), {"application": result["application"], "environment": result["environment"], "decision": result["decision"],
                                                    "detail_json": json.dumps({"rules": [{k: x[k] for k in ("id", "status", "mode")} for x in result["rules"]], "policy_version": result["policy_version"]}),
                                                    "evaluated_by": actor, "evaluated_at": result["evaluated_at"]})


def history(application=None, limit=100, engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    t = db_module.gate_runs
    q = select(t).order_by(t.c.id.desc()).limit(limit)
    if application:
        q = q.where(t.c.application == application)
    with engine.connect() as conn:
        return [{"id": r["id"], "application": r["application"], "environment": r["environment"], "decision": r["decision"], "evaluated_by": r["evaluated_by"], "evaluated_at": r["evaluated_at"],
                 **{k: v for k, v in json.loads(r["detail_json"]).items()}} for r in conn.execute(q).mappings().all()]


def last_by_application(engine=None):
    """{lower-case application name: latest evaluated_at}, the evidence for the library's release-gate control."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    out = {}
    with engine.connect() as conn:
        for r in conn.execute(select(db_module.gate_runs.c.application, db_module.gate_runs.c.evaluated_at).order_by(db_module.gate_runs.c.id)).all():
            out[r[0].strip().lower()] = r[1]
    return out


def snippets(base_url, application, environment):
    """Starting points for the CI step. They use no third-party action; pin any you add to a commit you have reviewed."""
    nl = chr(10)
    url = f"{base_url.rstrip('/')}/api/gate/evaluate?application={application}&environment={environment}"
    check = "python3 -c 'import json,sys; d=json.load(open(" + '"gate.json"' + ")); print(d[" + '"decision"' + "]); sys.exit(1 if d[" + '"decision"' + "]==" + '"fail"' + " else 0)'"
    lines = ['curl --fail-with-body -sS -H "Authorization: Bearer $QUANTA_API_KEY" "' + url + '" -o gate.json', "cat gate.json", check]

    def block(pad):
        return nl.join(pad + ln for ln in lines)
    gh = ["release-gate:", "  runs-on: ubuntu-latest", "  steps:", "    - name: Quanta release gate", "      env:", "        QUANTA_API_KEY: ${{ secrets.QUANTA_API_KEY }}", "      run: |", block("        ")]
    gl = ["release-gate:", "  stage: test", "  image: python:3.12-slim", "  before_script:", "    - apt-get update -qq && apt-get install -y -qq curl", "  script:", "    - |", block("      "),
          "  # QUANTA_API_KEY is a masked, protected CI/CD variable"]
    return {"github-actions": nl.join(gh), "gitlab-ci": nl.join(gl), "shell": nl.join(lines)}
