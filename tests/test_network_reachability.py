"""
Tests for remediation/enrichment/network_reachability.py - real network-reachability
path tracing. Uses in-memory `topology` dicts (not the real shipped
network_topology.yaml, which ships with zero entries) so this suite never depends on
real seed data.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.network_reachability import find_asset_path, trace_path  # noqa: E402


class FindAssetPath(unittest.TestCase):
    def test_exact_name_match(self):
        topology = {"assets": [{"match": {"name": "WIN-DC01"}, "path_to_internet": [{"hop_type": "firewall", "name": "FW1", "default_action": "deny"}]}]}
        self.assertEqual(len(find_asset_path("WIN-DC01", topology)), 1)

    def test_no_match_returns_none(self):
        self.assertIsNone(find_asset_path("UNKNOWN-01", {"assets": []}))


class TracePath(unittest.TestCase):
    def test_no_entry_gives_unknown_verdict(self):
        result = trace_path("UNKNOWN-01", {"assets": []})
        self.assertEqual(result["verdict"], "unknown")
        self.assertEqual(result["hops"], [])

    def test_empty_path_gives_unknown_verdict(self):
        topology = {"assets": [{"match": {"name": "AIR-GAPPED-01"}, "path_to_internet": []}]}
        result = trace_path("AIR-GAPPED-01", topology)
        self.assertEqual(result["verdict"], "unknown")

    def test_single_denying_hop_gives_denied_verdict(self):
        topology = {"assets": [{"match": {"name": "WIN-DC01"}, "path_to_internet": [
            {"hop_type": "firewall", "name": "Core-FW-01", "default_action": "deny"},
        ]}]}
        result = trace_path("WIN-DC01", topology)
        self.assertEqual(result["verdict"], "denied")
        self.assertEqual(len(result["hops"]), 1)

    def test_all_allowing_hops_give_allowed_verdict(self):
        topology = {"assets": [{"match": {"name_prefix": "WEB-"}, "path_to_internet": [
            {"hop_type": "waf", "name": "Edge-WAF", "default_action": "allow"},
            {"hop_type": "firewall", "name": "Perimeter-FW-01", "default_action": "allow"},
            {"hop_type": "dmz", "name": "DMZ-Segment-A", "default_action": "allow"},
        ]}]}
        result = trace_path("WEB-PORTAL01", topology)
        self.assertEqual(result["verdict"], "allowed")
        self.assertEqual(len(result["hops"]), 3)

    def test_one_denying_hop_among_allowing_ones_still_denies_overall(self):
        topology = {"assets": [{"match": {"name": "WEB-PORTAL01"}, "path_to_internet": [
            {"hop_type": "waf", "name": "Edge-WAF", "default_action": "allow"},
            {"hop_type": "firewall", "name": "Perimeter-FW-01", "default_action": "deny"},
            {"hop_type": "dmz", "name": "DMZ-Segment-A", "default_action": "allow"},
        ]}]}
        result = trace_path("WEB-PORTAL01", topology)
        self.assertEqual(result["verdict"], "denied")


if __name__ == "__main__":
    unittest.main()
