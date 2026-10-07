"""
Priority score (0-100) with its working shown, learned yield from past outcomes, and the effort estimate.

  likelihood  up to 30   KEV +12, known ransomware use +5, EPSS x 8, a true positive already seen +8, intel relevance/100 x 8
  impact      up to 25   internet-facing +8, crown jewel or privileged identity +8, a Critical finding +5, blast radius up to +6
  coverage    up to 15   no enabled detection claims the technique: full; partial: half; coverage unknown: one third (never zero: unknown is not a pass)
  freshness   up to 10   evidence from the last 3 days 10, 14 days 7, the KEV window 4, older 1, undated 0
  learned     -15..+10   from how past hunts of the same pattern ended (true positives raise it, benign conclusions lower it); needs `min_samples` conclusions
  effort      0 / -4 / -9  small, medium, large

Every factor is returned with its points, its maximum and a sentence, so the number can always be explained. Weights are in remediation/config/hunt_engine.yaml.
"""
import math

DEFAULT_W = {"likelihood_max": 30, "impact_max": 25, "coverage_gap_max": 15, "freshness_max": 10, "learned_min": -15, "learned_max": 10,
             "effort_penalty": {"S": 0, "M": 4, "L": 9}}


def weights(cfg):
    w = {**DEFAULT_W, **((cfg or {}).get("weights") or {})}
    w["effort_penalty"] = {**DEFAULT_W["effort_penalty"], **(w.get("effort_penalty") or {})}
    return w


def effort(scope_counts, has_queries, missing_techniques):
    """S: a handful of targets and ready queries. M: dozens, or queries need adapting. L: hundreds, or queries must be written from scratch."""
    n = max(scope_counts.get("assets", 0), scope_counts.get("identities", 0))
    if not has_queries or n > 100:
        return "L" if (not has_queries and missing_techniques) or n > 100 else "M"
    return "S" if n <= 10 and not missing_techniques else "M"


def learned_adjust(stats, cfg):
    """stats: {concluded, true_positive, benign, inconclusive, dismissed} for the hypothesis's pattern. -> (points, note, suppressed)."""
    lc = {"min_samples": 2, "suppress_after_benign": 3, **((cfg or {}).get("learning") or {})}
    w = weights(cfg)
    n = stats.get("concluded", 0) if stats else 0
    if not stats or n < lc["min_samples"]:
        return 0.0, ("No history for this pattern yet." if not n else f"Only {n} past conclusion for this pattern; at least {lc['min_samples']} are needed before it changes a score."), False
    tp, benign = stats["true_positive"], stats["benign"]
    pts = 20 * tp / n - 15 * benign / n
    pts = max(w["learned_min"], min(w["learned_max"], pts))
    suppressed = benign >= lc["suppress_after_benign"] and tp == 0
    note = f"Because of past outcomes: {n} similar hunts concluded, {tp} true positive, {benign} benign, {stats['inconclusive']} inconclusive."
    if suppressed:
        note += " Hidden from the default list until something changes or you ask to see suppressed suggestions."
    return round(pts, 1), note, suppressed


def score(sig, eff, learned_pts, learned_note, cfg):
    w = weights(cfg)
    sig = sig or {}
    rows = []

    def row(factor, pts, mx, note):
        rows.append({"factor": factor, "points": round(pts, 1), "max": mx, "note": note})
        return pts

    lk = 0.0
    bits = []
    if sig.get("kev"):
        lk += 12
        bits.append("on the CISA KEV list (+12)")
    if sig.get("ransomware"):
        lk += 5
        bits.append("known ransomware use (+5)")
    if sig.get("epss"):
        lk += 8 * float(sig["epss"])
        bits.append(f"EPSS {round(float(sig['epss']) * 100)}% (+{round(8 * float(sig['epss']), 1)})")
    if sig.get("tp_history"):
        lk += 8
        bits.append("a true positive of this kind was already confirmed (+8)")
    if sig.get("intel_relevance"):
        lk += 8 * min(100, float(sig["intel_relevance"])) / 100
        bits.append(f"intel relevance {int(sig['intel_relevance'])}/100 (+{round(8 * min(100, float(sig['intel_relevance'])) / 100, 1)})")
    if sig.get("anomaly"):
        lk += 10
        bits.append("a measured anomaly in your own alerts (+10)")
    lk = min(w["likelihood_max"], lk)
    row("likelihood", lk, w["likelihood_max"], "; ".join(bits) or "No strong likelihood signal; this is a hypothesis to test, not a sign of compromise.")

    im, bits = 0.0, []
    for key, pts, text in (("internet_facing", 8, "internet-facing"), ("crown_jewel", 8, "crown-jewel or privileged"), ("severity_critical", 5, "a Critical finding")):
        if sig.get(key):
            im += pts
            bits.append(f"{text} (+{pts})")
    blast = int(sig.get("blast") or 0)
    if blast:
        b = min(6.0, 2 * math.log2(blast + 1))
        im += b
        bits.append(f"{blast} asset(s) in scope (+{round(b, 1)})")
    im = min(w["impact_max"], im)
    row("impact", im, w["impact_max"], "; ".join(bits) or "No impact signal recorded (no asset criticality or exposure data).")

    cov = sig.get("coverage", "unknown")
    cmax = w["coverage_gap_max"]
    cp = {"none": cmax, "partial": cmax / 2, "unknown": cmax / 3, "covered": 0}.get(cov, cmax / 3)
    row("coverage_gap", cp, cmax, {"none": "No enabled detection rule claims this technique.", "partial": "Detection exists but only partly covers the behaviour.",
                                  "unknown": "Detection coverage could not be judged (no rules imported); counted as a third, never as covered.",
                                  "covered": "An enabled detection already claims it."}.get(cov, "Coverage unknown."))

    fd = sig.get("freshness_days")
    fmax = w["freshness_max"]
    fp = 0 if fd is None else fmax if fd <= 3 else fmax * 0.7 if fd <= 14 else fmax * 0.4 if fd <= 45 else fmax * 0.1
    row("freshness", fp, fmax, "The evidence is undated." if fd is None else f"Newest evidence is {fd} day(s) old.")

    row("learned_yield", learned_pts, w["learned_max"], learned_note)
    ep = w["effort_penalty"].get(eff, 4)
    row("effort", -ep, 0, f"Effort {eff}.")
    total = max(0.0, min(100.0, round(sum(r["points"] for r in rows), 1)))
    return {"score": total, "breakdown": rows}


def expected_value(total, sig):
    if total >= 60 or (sig or {}).get("tp_history"):
        return "high"
    return "medium" if total >= 35 else "low"
