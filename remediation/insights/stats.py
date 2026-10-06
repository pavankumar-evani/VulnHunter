"""Small, dependency-free statistics for the detectors. Every function says "not enough history" (returns None) instead of guessing from a short series."""
import statistics

MAD_SCALE = 1.4826   # makes the MAD comparable to a standard deviation for roughly normal data


def median(xs):
    return statistics.median(xs) if xs else None


def mad(xs):
    m = median(xs)
    return None if m is None else statistics.median([abs(x - m) for x in xs])


def robust_z(value, history, min_n=7, floor=1.0):
    """Robust z-score of `value` against `history` (median / MAD). None with fewer than `min_n` points. `floor` keeps a flat series (MAD 0)
    from producing an infinite score: the scale is never smaller than `floor`."""
    if history is None or len(history) < min_n:
        return None
    m, d = median(history), mad(history)
    scale = max(MAD_SCALE * d, floor)
    return (value - m) / scale


def ewma(series, alpha=0.3):
    """Exponentially weighted moving average of the whole series (the one-step-ahead forecast). None for an empty series."""
    if not series:
        return None
    level = series[0]
    for x in series[1:]:
        level = alpha * x + (1 - alpha) * level
    return level


def seasonal_naive(series, period=7, min_cycles=3):
    """Forecast for the NEXT point: the median of the values one, two, ... periods earlier. None with fewer than `min_cycles` full cycles."""
    if len(series) < period * min_cycles:
        return None
    same = [series[len(series) - k * period] for k in range(1, min_cycles + 1)]
    return median(same)


def baseline_forecast(history, period=7):
    """(forecast, method) for the next point: seasonal-naive when three weeks exist, else the EWMA when 7+ points exist, else (None, 'not enough history')."""
    f = seasonal_naive(history, period)
    if f is not None:
        return f, "seasonal-naive (same weekday, last 3 weeks)"
    if len(history) >= 7:
        return ewma(history), "EWMA"
    return None, "not enough history"


def change_point(series, min_seg=3, min_shift=2.0, floor=0.05):
    """Single level-shift detector for a short series: the split whose two segment medians differ most, scored in robust units of the pooled
    within-segment spread. Returns {index, before, after, shift, score} or None (too short, or no shift of at least `min_shift` robust units)."""
    n = len(series)
    if n < 2 * min_seg:
        return None
    best = None
    for i in range(min_seg, n - min_seg + 1):
        a, b = series[:i], series[i:]
        spread = max(MAD_SCALE * ((mad(a) + mad(b)) / 2), floor)
        shift = median(b) - median(a)
        score = abs(shift) / spread
        cost = sum(abs(x - median(a)) for x in a) + sum(abs(x - median(b)) for x in b)     # tie-break: the split that fits both sides best
        if best is None or (round(score, 9), -cost) > (round(best["score"], 9), -best["_cost"]):
            best = {"index": i, "before": median(a), "after": median(b), "shift": shift, "score": score, "_cost": cost}
    if best:
        best.pop("_cost")
    return best if best and best["score"] >= min_shift else None


def confidence_from_n(n, half=5.0):
    """A bounded confidence that grows with the sample size: n / (n + half). 5 observations -> 0.5, 20 -> 0.8."""
    return n / (n + half) if n > 0 else 0.0
