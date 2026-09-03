"""
Real network-reachability tracing: is a given asset actually reachable from the internet,
once every hop (firewall, WAF, load balancer, DMZ segment) in its path is accounted for -
not just whether one firewall rule at one point says "allow."

Reads the hand-maintained path in remediation/config/network_topology.yaml (see that
file's own header for why this is manually-curated rather than a live topology-discovery
connector, which nothing in this repo provides today).

Verdict logic - deliberately simple and disclosed as such: a single denying hop anywhere
in the path protects the asset regardless of what every other hop allows, so the verdict
is "denied" if ANY hop's default_action is "deny", "allowed" only if every hop in a
non-empty path allows, and "unknown" when the asset has no matching entry at all - an
unknown path is never treated as either safe or exposed by default; a caller deciding what
to do about an "unknown" verdict should treat it the same as "no data," not "allowed."
"""
import re
from pathlib import Path

import yaml

DEFAULT_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent / "config" / "network_topology.yaml"


def load_topology(path=None):
    path = Path(path) if path is not None else DEFAULT_TOPOLOGY_PATH
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {"assets": []}


def _entry_matches(match, asset_name):
    if "name" in match:
        return asset_name == match["name"]
    if "name_prefix" in match:
        return asset_name.startswith(match["name_prefix"])
    if "name_regex" in match:
        return bool(re.search(match["name_regex"], asset_name))
    return False


def find_asset_path(asset_name, topology=None):
    """Returns the first matching entry's path_to_internet (a list of hops), or None if
    network_topology.yaml has no entry for this asset."""
    topology = topology if topology is not None else load_topology()
    for entry in topology.get("assets", []):
        if _entry_matches(entry.get("match", {}), asset_name):
            return entry.get("path_to_internet") or []
    return None


def trace_path(asset_name, topology=None):
    """Returns {verdict: "allowed"|"denied"|"unknown", hops: [...]}. `hops` echoes the
    configured path_to_internet unchanged (each hop already carries hop_type/name/
    default_action) so a caller can render the full chain, not just the verdict."""
    hops = find_asset_path(asset_name, topology)
    if hops is None:
        return {"verdict": "unknown", "hops": []}
    if not hops:
        return {"verdict": "unknown", "hops": []}
    if any(str(h.get("default_action", "")).lower() == "deny" for h in hops):
        return {"verdict": "denied", "hops": hops}
    return {"verdict": "allowed", "hops": hops}
