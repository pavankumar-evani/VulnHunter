"""
Pattern-based owner/team/type suggestions for the asset inventory.

The user ask this answers was for "machine learning... to learn from the data and
auto predict... patterns for the assets, hosts, IPs, metadata, MAC address, or owners,
or teams." This is deliberately NOT real machine learning: this repo's demo asset
inventory has on the order of a dozen assets (see remediation/inventory/asset_ownership.json)
- training or even meaningfully validating an ML model on a dataset that small would be
overfitting theater, not a real capability, and claiming "ML" here would be dishonest in
exactly the way this repo's other honesty caveats (see remediation/connectors/README.md,
remediation/enrichment/attack_mapping.py, remediation/enrichment/compensating_controls.py)
are careful never to be.

What this actually is: three transparent, explainable pattern-matching signals over
assets that already have an owner/team (or a known type) set, applied to assets that
don't yet:

1. Hostname naming-convention match - most real infra naming conventions encode role/
   environment in a prefix before a trailing number (e.g. "WIN-APP07", "LNX-DB03").
   Assets sharing that prefix are usually provisioned/owned the same way.
2. IP subnet match - assets on the same /24 are often the same environment or rack,
   frequently the same owning team.
3. Asset-type match - the weakest signal (many different teams can own the same asset
   type), used mainly as a tiebreaker.

Each signal is a plain, inspectable string match - there's no model, no training step,
no probability distribution, just a small weighted vote whose reasoning is returned
alongside the suggestion so a human can see exactly why it was made and reject it if
it's wrong. Suggestions are never auto-applied - same "suggestion, not a determination"
posture as attack_mapping.py's ATT&CK tagging and compensating_controls.py.

Does that mean this app has NO real ML? Not anymore - see remediation/enrichment/
ml_insights.py (asset anomaly detection, finding clustering, similar-finding search),
which genuinely does use scikit-learn, fit at request time. It doesn't contradict
anything above: it answers an unsupervised question (needs no labels, just a large real
feature population - this repo's finding data has thousands of real rows) rather than
this module's supervised one (needs labeled owner/team examples - this repo's real label
pool is on the order of a dozen assets, still nowhere near enough). Read that module's
own docstring for the full reasoning; this one's conclusion is unchanged.
"""
import re
from collections import Counter

_TRAILING_NUMBER = re.compile(r"[-_]?\d+$")

# Signal weights - hostname naming convention is the strongest real-world signal,
# subnet locality is next, asset type alone is the weakest (arbitrary, tune-if-wrong,
# not derived from any study).
_WEIGHT_HOSTNAME_PREFIX = 3
_WEIGHT_SUBNET = 2
_WEIGHT_TYPE = 1
_WEIGHT_MAC_OUI = 2


def hostname_prefix(name):
    """Strips a trailing run of digits (and one optional preceding separator) from a
    hostname, e.g. "WIN-APP07" -> "WIN-APP", "LNX-DB03" -> "LNX-DB". Returns "" for a
    falsy name so it never accidentally matches another falsy name."""
    if not name:
        return ""
    return _TRAILING_NUMBER.sub("", name).upper()


def ip_subnet(ip):
    """The /24 network portion of an IPv4 address as a string, e.g. "10.20.30.41" ->
    "10.20.30". Returns None for anything that isn't a plausible dotted-quad IPv4
    address - this is intentionally not a full IP parser, just enough to group
    addresses that share their first three octets."""
    if not ip or not isinstance(ip, str):
        return None
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return None
    return ".".join(parts[:3])


def mac_oui(mac):
    """The vendor OUI (first 3 octets) of a MAC address, normalized to uppercase
    colon-separated form, e.g. "aa:bb:cc:dd:ee:ff" -> "AA:BB:CC". Devices from the same
    vendor are often the same device class (useful for type inference, not ownership).
    Returns None for anything that doesn't look like a MAC address."""
    if not mac or not isinstance(mac, str):
        return None
    octets = re.split("[:-]", mac.strip())
    if len(octets) != 6 or not all(len(o) == 2 for o in octets):
        return None
    return ":".join(o.upper() for o in octets[:3])


def _vote(pairs_with_weight):
    """Takes a list of (value, weight) tuples and returns the highest-scoring value
    plus its total score, or (None, 0) if the list is empty."""
    if not pairs_with_weight:
        return None, 0
    scores = Counter()
    for value, weight in pairs_with_weight:
        scores[value] += weight
    value, score = scores.most_common(1)[0]
    return value, score


def suggest_owner_team(asset, known_assets):
    """Suggests an (owner, team) pair for `asset` (a dict with at least `name`, `ip`,
    `type`) by pattern-matching it against `known_assets` (dicts with `name`, `ip`,
    `type`, `owner`, `team` - only assets that already have a truthy owner should be
    passed in). Returns None if no known asset matches on any signal, else:
        {"owner": str, "team": str, "confidence": float (0-1), "reasons": [str, ...]}
    `confidence` is a heuristic 0-1 scale derived from the vote score, not a
    statistical probability - treat it as "how many independent signals agree",
    nothing more.
    """
    name = asset.get("name")
    prefix = hostname_prefix(name)
    subnet = ip_subnet(asset.get("ip"))
    asset_type = asset.get("type")

    votes = []  # list of ((owner, team), weight, reason)
    for known in known_assets:
        if known.get("name") == name or not known.get("owner"):
            continue
        pair = (known["owner"], known.get("team") or "")

        if prefix and hostname_prefix(known.get("name")) == prefix:
            votes.append((pair, _WEIGHT_HOSTNAME_PREFIX,
                          f"Hostname pattern \"{prefix}*\" matches {known['name']} "
                          f"(owned by {known['owner']})"))
        if subnet and ip_subnet(known.get("ip")) == subnet:
            votes.append((pair, _WEIGHT_SUBNET,
                          f"Same /24 subnet ({subnet}.0/24) as {known['name']} "
                          f"(owned by {known['owner']})"))
        if asset_type and asset_type != "unknown" and known.get("type") == asset_type:
            votes.append((pair, _WEIGHT_TYPE,
                          f"Same asset type ({asset_type}) as {known['name']} "
                          f"(owned by {known['owner']})"))

    if not votes:
        return None

    pair_weight_reason = [(v[0], v[1]) for v in votes]
    best_pair, score = _vote(pair_weight_reason)
    reasons = [v[2] for v in votes if v[0] == best_pair]
    max_possible = _WEIGHT_HOSTNAME_PREFIX + _WEIGHT_SUBNET + _WEIGHT_TYPE
    confidence = min(1.0, score / max_possible)

    return {
        "owner": best_pair[0],
        "team": best_pair[1],
        "confidence": round(confidence, 2),
        "reasons": reasons,
    }


def suggest_type(asset, known_assets):
    """Suggests an asset.type for `asset` when its own type is missing/"unknown", by
    pattern-matching against `known_assets` that already have a real (non-"unknown")
    type. Same signals as suggest_owner_team minus the type signal itself (which would
    be circular here), plus a MAC-vendor-OUI match when both assets have a MAC address -
    devices from the same vendor are frequently the same device class (e.g. an IoT
    camera vendor's OUI showing up on other camera assets). Returns None if nothing
    matches, else {"type": str, "confidence": float, "reasons": [str, ...]}.
    """
    name = asset.get("name")
    prefix = hostname_prefix(name)
    subnet = ip_subnet(asset.get("ip"))
    oui = mac_oui(asset.get("mac"))

    votes = []
    for known in known_assets:
        known_type = known.get("type")
        if known.get("name") == name or not known_type or known_type == "unknown":
            continue

        if prefix and hostname_prefix(known.get("name")) == prefix:
            votes.append((known_type, _WEIGHT_HOSTNAME_PREFIX,
                          f"Hostname pattern \"{prefix}*\" matches {known['name']} "
                          f"({known_type})"))
        if subnet and ip_subnet(known.get("ip")) == subnet:
            votes.append((known_type, _WEIGHT_SUBNET,
                          f"Same /24 subnet ({subnet}.0/24) as {known['name']} ({known_type})"))
        if oui and mac_oui(known.get("mac")) == oui:
            votes.append((known_type, _WEIGHT_MAC_OUI,
                          f"Same MAC vendor prefix ({oui}) as {known['name']} ({known_type})"))

    if not votes:
        return None

    pair_weight = [(v[0], v[1]) for v in votes]
    best_type, score = _vote(pair_weight)
    reasons = [v[2] for v in votes if v[0] == best_type]
    max_possible = _WEIGHT_HOSTNAME_PREFIX + _WEIGHT_SUBNET + _WEIGHT_MAC_OUI
    confidence = min(1.0, score / max_possible)

    return {"type": best_type, "confidence": round(confidence, 2), "reasons": reasons}


def annotate_unowned_assets(inventory_rows):
    """Given build_asset_inventory()'s output rows (each a dict with at least `name`,
    `ip`, `type`, `owner`, `team`), returns a NEW list of only the rows that have no
    owner yet, each with a `suggestion` key added (the dict from suggest_owner_team, or
    None). Never mutates the input rows or writes anything - a pure read-side helper
    for the dashboard to render "suggested owner" hints next to unowned assets."""
    known = [r for r in inventory_rows if r.get("owner")]
    unowned = [r for r in inventory_rows if not r.get("owner")]
    return [dict(r, suggestion=suggest_owner_team(r, known)) for r in unowned]
