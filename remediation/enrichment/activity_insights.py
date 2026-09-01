"""
Real, unsupervised analysis of this app's own activity log (remediation/audit/
activity_log.py) - who did what, when, and whether that pattern looks unusual - built
the same honest way remediation/enrichment/ml_insights.py's asset/finding ML is: real
scikit-learn, genuinely fit at request time, never fabricated.

The one thing that's different here, and worth reading before wiring this up: this
app's activity log starts EMPTY on a fresh checkout (unlike normalized-findings.json,
which ships with thousands of real rows) - every entry in it is something a real user
of this running app actually did. That means a fresh demo genuinely has "not enough
data yet," and this module says so honestly (see _MIN_ACTIONS_FOR_ANOMALY_DETECTION
below) rather than fabricating history to make the ML feature look populated. The
non-ML summary functions below (summarize_activity()) work from day one regardless,
computed directly and honestly from whatever real activity actually exists so far -
zero, one, or ten thousand entries.

What this deliberately does NOT do: predict whether a specific future action is
"risky" before it happens (there's no real outcome label - "this action turned out
to be a problem" - anywhere in this log to train that from), and it never blocks or
gates any real action - purely an advisory insights layer, same posture as
ml_insights.py toward the deterministic policy/priority engines.
"""
import collections
import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

# Same "don't train on too little data" rule ml_insights.py's own floor enforces -
# below this many real recorded actions, per-actor behavioral features are too sparse
# to describe a genuine distribution, so detect_unusual_actors() honestly declines
# rather than flagging noise as "unusual."
_MIN_ACTIONS_FOR_ANOMALY_DETECTION = 30
_MIN_ACTORS_FOR_ANOMALY_DETECTION = 3

ACTOR_FEATURE_NAMES = ("action_count", "distinct_action_types", "off_hours_fraction", "self_approval_fraction")


def summarize_activity(entries):
    """Real, non-ML summary of the activity log as it stands right now - works
    correctly at any volume, including zero entries. Returns total count, counts by
    action, counts by actor, and the most recent entry's timestamp (or None)."""
    by_action = collections.Counter(e["action"] for e in entries)
    by_actor = collections.Counter(e["actor"] for e in entries)
    return {
        "total": len(entries),
        "by_action": dict(by_action.most_common()),
        "by_actor": dict(by_actor.most_common()),
        "most_recent_timestamp": entries[0]["timestamp"] if entries else None,
    }


def _is_off_hours(timestamp_str):
    try:
        dt = datetime.datetime.fromisoformat(timestamp_str)
    except (TypeError, ValueError):
        return False
    return dt.hour < 6 or dt.hour >= 20


def _build_actor_features(entries):
    """One row per distinct actor - real counts derived from that actor's own entries
    only, no cross-actor comparison baked into the numbers themselves (the comparison
    happens later, inside IsolationForest, across the population of actors)."""
    by_actor = collections.defaultdict(list)
    for e in entries:
        by_actor[e["actor"]].append(e)

    actors = sorted(by_actor.keys())
    rows = []
    for actor in actors:
        actor_entries = by_actor[actor]
        action_types = {e["action"] for e in actor_entries}
        off_hours_count = sum(1 for e in actor_entries if _is_off_hours(e["timestamp"]))
        approvals = [e for e in actor_entries if e["action"] == "approval.approve"]
        # A "self-approval" here means this actor both requested AND approved the same
        # finding_id's approval - a real, checkable pattern from this log's own
        # details/target fields, not an assumption about intent.
        requested_finding_ids = {
            e["details"].get("finding_id") for e in actor_entries if e["action"] == "approval.request"
        }
        self_approvals = sum(
            1 for e in approvals if e["details"].get("finding_id") in requested_finding_ids
        )
        rows.append([
            len(actor_entries),
            len(action_types),
            off_hours_count / len(actor_entries) if actor_entries else 0.0,
            self_approvals / len(approvals) if approvals else 0.0,
        ])
    return actors, np.array(rows, dtype=float)


def detect_unusual_actors(entries, contamination=0.1, random_state=42):
    """Real IsolationForest anomaly detection over per-actor behavioral features
    (action volume, action-type diversity, off-hours fraction, self-approval fraction).
    Returns a list of {"actor", "anomaly_score", "is_anomaly", "reasons", **raw
    features} - empty if there isn't yet enough real activity history to fit on
    honestly (see _MIN_ACTIONS_FOR_ANOMALY_DETECTION/_MIN_ACTORS_FOR_ANOMALY_DETECTION
    above), which is the expected, correct state for a freshly-checked-out demo."""
    if len(entries) < _MIN_ACTIONS_FOR_ANOMALY_DETECTION:
        return []
    actors, X = _build_actor_features(entries)
    if len(actors) < _MIN_ACTORS_FOR_ANOMALY_DETECTION:
        return []

    model = IsolationForest(random_state=random_state, contamination=contamination)
    model.fit(X)
    scores = model.decision_function(X)
    preds = model.predict(X)

    means = X.mean(axis=0)
    stds = X.std(axis=0)
    stds_safe = np.where(stds == 0, 1, stds)

    results = []
    for i, actor in enumerate(actors):
        is_anomaly = bool(preds[i] == -1)
        reasons = []
        if is_anomaly:
            z = (X[i] - means) / stds_safe
            top = np.argsort(-np.abs(z))[:2]
            for rank, feat_idx in enumerate(top):
                if rank > 0 and abs(z[feat_idx]) < 1.0:
                    continue
                direction = "higher" if z[feat_idx] > 0 else "lower"
                label = ACTOR_FEATURE_NAMES[feat_idx].replace("_", " ")
                reasons.append(f"{label} is unusually {direction} than other actors ({z[feat_idx]:+.1f} std dev)")
        results.append({
            "actor": actor,
            "anomaly_score": round(float(scores[i]), 4),
            "is_anomaly": is_anomaly,
            "reasons": reasons,
            "action_count": int(X[i][0]),
            "distinct_action_types": int(X[i][1]),
            "off_hours_fraction": round(float(X[i][2]), 4),
            "self_approval_fraction": round(float(X[i][3]), 4),
        })
    results.sort(key=lambda r: r["anomaly_score"])
    return results
