"""
The hunt hypothesis: the unit the engine proposes and a person decides on.

A hypothesis is a testable statement ("If <who> is active in our environment, we would expect to see <evidence> on <where>"), the chain of records that make it
worth testing now (`why_now`: every item names a record Quanta holds, so nothing is asserted that cannot be traced), what data and queries are needed, what
would be malicious versus benign, and a score with its working shown.

Frameworks borrowed: PEAK (Prepare / Execute / Act) for the lifecycle and the explicit "Prepare" content (scope, data, benign explanations), TaHiTI for the
hypothesis-first, outcome-recorded loop, the SANS hunting maturity ladder for the four hunt types, and MITRE ATT&CK for techniques and tactics.

Lifecycle: suggested -> accepted -> running -> evidence-recorded -> concluded (true-positive | benign | inconclusive-needs-data) -> promoted (to a detection
use case), or dismissed (with a reason) from any open state.
"""
from remediation.hunting import report
from remediation.utils.digest import dedup_sha1

HUNT_TYPES = ("hypothesis-driven", "baseline-anomaly", "intel-driven", "model-assisted")
STATUSES = ("suggested", "accepted", "running", "evidence-recorded", "concluded", "promoted", "dismissed")
OPEN = ("suggested", "accepted", "running", "evidence-recorded")
OUTCOMES = ("true-positive", "benign", "inconclusive-needs-data")
DISMISS_REASONS = ("not-relevant", "already-covered", "no-data", "accepted-risk", "other")
TRANSITIONS = {
    "suggested": ("accepted", "dismissed"),
    "accepted": ("running", "evidence-recorded", "concluded", "dismissed"),
    "running": ("evidence-recorded", "concluded", "dismissed"),
    "evidence-recorded": ("running", "concluded", "dismissed"),
    "concluded": ("promoted",),
    "promoted": (),
    "dismissed": ("suggested",),   # only the engine reopens it, when its evidence materially changed
}
HUNT_OUTCOME = {"true-positive": "confirmed", "benign": "not-found", "inconclusive-needs-data": "needs-data"}
FROM_HUNT_OUTCOME = {v: k for k, v in HUNT_OUTCOME.items()}
LINKS = {"alert": "/hunting?tab=alerts", "intel": "/hunting?tab=intel", "darkweb": "/dark-web-watch", "iam": "/access-governance", "hunt": "/hunting?tab=hunts",
         "finding": "/queue", "cvd": "/zero-day-watch", "actor": "/threat-intel", "control": "/compensating-controls", "rule": "/hunting?tab=detections", "asset": "/queue"}


def hypothesis_id(generator, subject):
    """Stable across refreshes: the same generator and subject always give the same id, so a refresh updates rather than duplicates."""
    return "hyp-" + dedup_sha1(f"{generator}|{subject}".encode()).hexdigest()[:12]


def ev(kind, ref, label, detail="", strong=False):
    """One piece of evidence. `kind`+`ref` must name a record Quanta holds (the tests resolve every one)."""
    return {"kind": kind, "ref": str(ref), "label": label[:200], "detail": detail[:300], "strong": bool(strong), "link": LINKS.get(kind)}


def ev_refs(why_now):
    return sorted({f"{e['kind']}:{e['ref']}" for e in why_now})


def technique_entry(tid, lib=None):
    info = report.technique_info(tid) or {}
    name = info.get("name") or ((lib or {}).get(tid.split(".")[0]) or {}).get("hunt") or tid
    return {"technique_id": tid, "technique_name": name, "tactic": info.get("tactic"), "tactics": info.get("tactics") or []}


def build(generator, hunt_type, subject, pattern, title, who, expect, where, why_now, techniques, assets=(), identities=(), segments=(), signals=None,
          malicious=(), benign=(), scoping="", next_step="", soar=None, source_note=""):
    """A raw hypothesis, before the engine adds readiness, queries, score and learned history."""
    assert hunt_type in HUNT_TYPES, hunt_type
    assets, identities, segments = sorted(set(assets)), sorted(set(identities)), sorted(set(segments))
    return {
        "id": hypothesis_id(generator, subject), "generator": generator, "hunt_type": hunt_type, "pattern_key": f"{generator}:{pattern}",
        "title": title[:200], "hypothesis": f"If {who} is active in our environment, we would expect to see {expect} on {where}.",
        "why_now": list(why_now), "techniques_wanted": list(techniques),
        "scope": {"assets": assets[:200], "identities": identities[:200], "segments": segments[:50],
                  "counts": {"assets": len(assets), "identities": len(identities), "segments": len(segments)}},
        "signals": signals or {}, "expected_malicious": list(malicious), "likely_benign": list(benign), "scoping": scoping,
        "next_step": next_step, "soar_playbook": soar, "source_note": source_note,
    }
