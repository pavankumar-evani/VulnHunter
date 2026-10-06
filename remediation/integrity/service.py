"""Glue for the API, the CLI and the scheduler: one full report, a cached summary for /readyz, and a once-per-problem alert."""
import hashlib
import json
import os
import threading
import time

from remediation.audit import activity_log
from remediation.integrity import checks, manifest
from remediation.utils import db as db_module

_LOCK = threading.Lock()
_LAST = {"summary": None, "at": 0.0}
_TICK = {"next": 0.0}
CHECK_INTERVAL_SECONDS = 3600.0


def enabled():
    return os.environ.get("QUANTA_INTEGRITY_CHECKS", "true").strip().lower() not in ("0", "false", "no", "off")


def summarise(report):
    """The small shape /readyz and the tick keep: status, counts, and the title of anything not ok."""
    code = report.get("code_state")
    problems = [c["title"] for c in report["checks"] if c["level"] in ("warn", "fail")]
    if code == "code-modified":
        problems.append("Application code differs from the release baseline")
    status = report["status"]
    if code == "code-modified" and status == "ok":
        status = "warn"
    return {"status": status, "checked_at": report["checked_at"], "counts": report["counts"], "code_state": code, "problems": problems}


def full_report(engine=None, root=None, now=None, with_manifest=True):
    engine = engine or db_module.get_engine()
    report = checks.run_all(engine=engine, root=root, now=now)
    if with_manifest:
        try:
            activity = activity_log.list_activity(engine=engine, limit=1000)
        except Exception:  # noqa: BLE001
            activity = []
        report["manifest"] = manifest.verify(root, activity=activity)
        report["code_state"] = report["manifest"]["state"]
    else:
        report["code_state"] = None
    summary = summarise(report)
    with _LOCK:
        _LAST["summary"], _LAST["at"] = summary, time.time()
    return report


def last_summary():
    """The newest summary any caller produced in this process, or None (the probe never triggers a scan itself)."""
    with _LOCK:
        return dict(_LAST["summary"]) if _LAST["summary"] else None


def _signature(summary):
    return hashlib.sha256(json.dumps([summary["status"], summary["problems"]], sort_keys=True).encode()).hexdigest()[:16]


def alert_if_new(summary, engine=None, send=None):
    """Writes one `integrity.alert` activity entry (and calls send(subject, body) when given) when the set of problems changed since the last alert.
    A clean result records `integrity.recovered` once after an alert. Returns 'alert', 'recovered' or None."""
    engine = engine or db_module.get_engine()
    last = next(iter(activity_log.list_activity(engine=engine, action="integrity.alert", limit=1)), None)
    last_ok = next(iter(activity_log.list_activity(engine=engine, action="integrity.recovered", limit=1)), None)
    clean = not summary["problems"]
    if clean:
        if last and (not last_ok or last_ok["id"] < last["id"]):
            activity_log.record_activity("system", "integrity.recovered", target="integrity", details={"checked_at": summary["checked_at"]}, engine=engine)
            return "recovered"
        return None
    sig = _signature(summary)
    if last and (last.get("details") or {}).get("signature") == sig and (not last_ok or last_ok["id"] < last["id"]):
        return None
    activity_log.record_activity("system", "integrity.alert", target="integrity",
                                 details={"signature": sig, "status": summary["status"], "problems": summary["problems"]}, engine=engine)
    if send:
        try:
            send("Quanta integrity check: " + summary["status"], "Problems found:\n- " + "\n- ".join(summary["problems"]) +
                 "\n\nOpen Administration > Activity Log > Integrity for detail and the safe repairs available.")
        except Exception:  # noqa: BLE001 - the activity-log entry is the record; a mail failure must not hide it
            pass
    return "alert"


def run_tick(engine=None, root=None, send=None, force=False):
    """Hourly leader tick. Does nothing when QUANTA_INTEGRITY_CHECKS=false or the hour has not passed."""
    if not enabled():
        return None
    now = time.monotonic()
    with _LOCK:
        if not force and now < _TICK["next"]:
            return None
        _TICK["next"] = now + CHECK_INTERVAL_SECONDS
    report = full_report(engine=engine, root=root)
    summary = summarise(report)
    summary["alert"] = alert_if_new(summary, engine=engine, send=send)
    return summary
