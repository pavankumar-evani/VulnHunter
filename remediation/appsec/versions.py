"""
A lenient version comparer for choosing an upgrade target.

Package ecosystems disagree about versions (semver, PEP 440, Maven qualifiers, Go's leading v), and Quanta only needs two answers: which of several
fixed versions is the highest, and does an upgrade cross a major version. So this reads the dotted numeric part, treats a trailing qualifier
(alpha, beta, rc, snapshot, dev) as older than the same release without one, and orders anything else after the numbers. It is not a full resolver:
it never decides what a package manager will install, only how to sort the versions a scanner reported.
"""
import re

_PRE = ("dev", "alpha", "a", "beta", "b", "rc", "c", "pre", "snapshot", "m", "milestone")
_NUM = re.compile(r"\d+")


def parse(version):
    """(numbers, prerelease_rank) or None when there is no number in the string."""
    if version is None:
        return None
    v = str(version).strip().lower().lstrip("v=")
    v = v.split("+", 1)[0]  # build metadata never orders
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    rest = m.group(2).lstrip(".-_")
    rank = (1, 0)  # a plain release sorts after any prerelease of the same numbers
    if rest:
        word = re.match(r"[a-z]+", rest)
        if word and word.group(0) in _PRE:
            n = _NUM.search(rest)
            rank = (0, _PRE.index(word.group(0)) * 1000 + (int(n.group(0)) if n else 0))
        else:
            n = _NUM.search(rest)  # e.g. 1.0.0-1 or a distro revision: after the bare release
            rank = (2, int(n.group(0)) if n else 0)
    return nums, rank


def _key(version):
    p = parse(version)
    if p is None:
        return None
    nums, rank = p
    return nums + (0,) * (6 - len(nums)), rank


def compare(a, b):
    """-1, 0, 1, or None when either side cannot be read."""
    ka, kb = _key(a), _key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


def highest(versions):
    """The highest readable version in the list, or None when none can be read."""
    best = None
    for v in versions:
        if v and _key(v) is not None and (best is None or compare(v, best) == 1):
            best = v
    return best


def major(version):
    p = parse(version)
    return p[0][0] if p else None


def crosses_major(current, target):
    a, b = major(current), major(target)
    return a is not None and b is not None and b > a
