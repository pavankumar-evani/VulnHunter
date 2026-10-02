"""
Cyber risk quantification in the FAIR style: how often a loss event happens, how much it costs, and what that adds up to in a year.

A scenario gives a minimum, most likely and maximum for (a) how many times a year the event happens and (b) the loss each time, in money.
Quanta simulates many years: each year it draws a frequency from a PERT distribution over the three numbers, draws that many events (Poisson), and
draws a loss for each from a PERT distribution over the loss numbers. The yearly losses give:

  ALE         the annualised loss expectancy, the average yearly loss
  P90, P95    the yearly loss that is exceeded in 1 year in 10 / 1 year in 20
  exceedance  the chance a year's loss exceeds your tolerance / appetite

The simulation is seeded from the scenario, so the same inputs give the same answer. The inputs are YOUR estimates: Quanta does the arithmetic and
shows the spread; it does not know the numbers. Exposure signals (known-exploited findings on the scenario's assets and so on) are shown next to
the scenario to help you decide whether your frequency is too optimistic, but they do not change it.

A treatment option has a yearly cost and the share by which it cuts frequency and/or loss magnitude. Re-running the simulation with the cut applied
gives the loss avoided, and return = (avoided - cost) / cost.
"""
import math
import random

MIN_TRIALS, MAX_TRIALS = 2000, 20000


class ScenarioError(ValueError):
    pass


def _triple(label, lo, mode, hi):
    try:
        lo, mode, hi = float(lo), float(mode), float(hi)
    except (TypeError, ValueError):
        raise ScenarioError(f"{label}: give a minimum, most likely and maximum as numbers") from None
    if lo < 0:
        raise ScenarioError(f"{label}: numbers cannot be negative")
    if not (lo <= mode <= hi):
        raise ScenarioError(f"{label}: the minimum must be at most the most likely, which must be at most the maximum")
    return lo, mode, hi


def validate(s):
    tef = _triple("Frequency", s.get("tef_min"), s.get("tef_likely"), s.get("tef_max"))
    loss = _triple("Loss per event", s.get("loss_min"), s.get("loss_likely"), s.get("loss_max"))
    if tef[2] > 365:
        raise ScenarioError("Frequency: more than 365 events a year is not a scenario, it is a baseline cost")
    return tef, loss


def pert(rng, lo, mode, hi):
    if hi == lo:
        return lo
    a, b = 1 + 4 * (mode - lo) / (hi - lo), 1 + 4 * (hi - mode) / (hi - lo)
    return lo + (hi - lo) * rng.betavariate(a, b)


def poisson(rng, lam):
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, round(rng.gauss(lam, math.sqrt(lam))))
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _pct(sorted_vals, q):
    if not sorted_vals:
        return 0.0
    return sorted_vals[min(len(sorted_vals) - 1, int(q * len(sorted_vals)))]


def simulate(s, trials=10000, seed=0, freq_cut=0.0, loss_cut=0.0, tolerance=None, appetite=None):
    """Runs the simulation. freq_cut and loss_cut (0 to 1) are the shares a treatment removes."""
    tef, loss = validate(s)
    trials = max(MIN_TRIALS, min(MAX_TRIALS, int(trials)))
    rng = random.Random(f"{seed}:{trials}")
    f_keep, l_keep = 1 - max(0.0, min(1.0, freq_cut)), 1 - max(0.0, min(1.0, loss_cut))
    years = []
    for _ in range(trials):
        n = poisson(rng, pert(rng, *tef) * f_keep)
        years.append(sum(pert(rng, *loss) * l_keep for _ in range(n)))
    years.sort()
    ale = sum(years) / trials
    out = {"trials": trials, "ale": round(ale), "p50": round(_pct(years, 0.5)), "p90": round(_pct(years, 0.9)), "p95": round(_pct(years, 0.95)), "max": round(years[-1]),
           "prob_any_loss": round(sum(1 for y in years if y > 0) / trials, 3),
           "exceedance": [{"probability": q, "loss": round(_pct(years, 1 - q))} for q in (0.5, 0.25, 0.1, 0.05, 0.01)]}
    if tolerance:
        out["prob_over_tolerance"] = round(sum(1 for y in years if y > tolerance) / trials, 3)
    if appetite:
        out["prob_over_appetite"] = round(sum(1 for y in years if y > appetite) / trials, 3)
    return out


def evaluate_options(s, trials, seed, tolerance=None):
    """The scenario as it stands, and each treatment option re-simulated with its cuts. Returns {baseline, options}."""
    base = simulate(s, trials, seed, tolerance=tolerance)
    out = []
    for o in s.get("options") or []:
        try:
            cost = float(o.get("annual_cost", 0))
            fc, lc = float(o.get("frequency_reduction", 0)), float(o.get("loss_reduction", 0))
        except (TypeError, ValueError):
            continue
        r = simulate(s, trials, seed, freq_cut=fc, loss_cut=lc, tolerance=tolerance)
        avoided = base["ale"] - r["ale"]
        out.append({"name": o.get("name") or "Option", "annual_cost": cost, "frequency_reduction": fc, "loss_reduction": lc, "ale_after": r["ale"], "p90_after": r["p90"],
                    "loss_avoided": avoided, "return": round((avoided - cost) / cost, 2) if cost > 0 else None, "worth_it": avoided > cost})
    out.sort(key=lambda x: -(x["loss_avoided"] - x["annual_cost"]))
    return {"baseline": base, "options": out}
