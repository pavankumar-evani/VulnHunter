"""
Tests for remediation/inventory/pattern_recognition.py - the transparent, weighted
pattern-matching heuristic that suggests an owner/team or asset type for assets that
don't have one yet. Explicitly NOT machine learning (see the module docstring) - these
tests verify the plain string/subnet/OUI matching and vote-scoring logic, not any
statistical model, because there isn't one.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.inventory import pattern_recognition as pr  # noqa: E402


class HostnamePrefix(unittest.TestCase):
    def test_strips_trailing_number_with_separator(self):
        self.assertEqual(pr.hostname_prefix("WIN-APP07"), "WIN-APP")

    def test_strips_trailing_number_without_separator(self):
        self.assertEqual(pr.hostname_prefix("LNXDB03"), "LNXDB")

    def test_no_trailing_number_is_unchanged_but_uppercased(self):
        self.assertEqual(pr.hostname_prefix("web-portal"), "WEB-PORTAL")

    def test_empty_or_none_returns_empty_string(self):
        self.assertEqual(pr.hostname_prefix(""), "")
        self.assertEqual(pr.hostname_prefix(None), "")


class IpSubnet(unittest.TestCase):
    def test_valid_ipv4_returns_first_three_octets(self):
        self.assertEqual(pr.ip_subnet("10.20.30.41"), "10.20.30")

    def test_different_last_octet_same_subnet(self):
        self.assertEqual(pr.ip_subnet("10.20.30.99"), pr.ip_subnet("10.20.30.1"))

    def test_none_or_non_ipv4_returns_none(self):
        self.assertIsNone(pr.ip_subnet(None))
        self.assertIsNone(pr.ip_subnet("not-an-ip"))
        self.assertIsNone(pr.ip_subnet("10.20.30"))
        self.assertIsNone(pr.ip_subnet("10.20.30.999"))


class MacOui(unittest.TestCase):
    def test_valid_mac_returns_uppercase_first_three_octets(self):
        self.assertEqual(pr.mac_oui("aa:bb:cc:dd:ee:ff"), "AA:BB:CC")

    def test_hyphen_separated_mac_also_works(self):
        self.assertEqual(pr.mac_oui("AA-BB-CC-11-22-33"), "AA:BB:CC")

    def test_none_or_malformed_returns_none(self):
        self.assertIsNone(pr.mac_oui(None))
        self.assertIsNone(pr.mac_oui("not-a-mac"))
        self.assertIsNone(pr.mac_oui("aa:bb:cc"))

    def test_right_shape_but_non_hex_octets_returns_none(self):
        # Structurally 6 groups of 2 chars, but "zz" isn't hex - a real MAC address
        # must be actual hex digits, not just the right shape.
        self.assertIsNone(pr.mac_oui("zz:zz:zz:zz:zz:zz"))


class IpVersion(unittest.TestCase):
    def test_ipv4_returns_4(self):
        self.assertEqual(pr.ip_version("10.20.30.41"), 4)

    def test_ipv6_returns_6(self):
        self.assertEqual(pr.ip_version("2001:db8::1"), 6)

    def test_ipv6_compressed_and_mixed_case_still_recognized(self):
        self.assertEqual(pr.ip_version("2001:DB8::1"), 6)
        self.assertEqual(pr.ip_version("::1"), 6)

    def test_none_or_malformed_returns_none(self):
        self.assertIsNone(pr.ip_version(None))
        self.assertIsNone(pr.ip_version(""))
        self.assertIsNone(pr.ip_version("not-an-ip"))
        self.assertIsNone(pr.ip_version("10.20.30.999"))
        self.assertIsNone(pr.ip_version("2001:db8::1::2"))  # two "::" is invalid


class Ipv6Subnet(unittest.TestCase):
    def test_valid_ipv6_returns_64_network(self):
        self.assertEqual(pr.ipv6_subnet("2001:db8::1"), "2001:db8::/64")

    def test_different_host_bits_same_subnet(self):
        self.assertEqual(pr.ipv6_subnet("2001:db8::1"), pr.ipv6_subnet("2001:db8::ffff"))

    def test_different_64_prefix_different_subnet(self):
        self.assertNotEqual(pr.ipv6_subnet("2001:db8:0:1::1"), pr.ipv6_subnet("2001:db8:0:2::1"))

    def test_ipv4_returns_none(self):
        # ip_subnet() (IPv4) and ipv6_subnet() are deliberately non-overlapping -
        # each returns None for the other version's addresses.
        self.assertIsNone(pr.ipv6_subnet("10.20.30.41"))

    def test_none_or_malformed_returns_none(self):
        self.assertIsNone(pr.ipv6_subnet(None))
        self.assertIsNone(pr.ipv6_subnet("not-an-ip"))


class IsValidMac(unittest.TestCase):
    def test_colon_and_hyphen_forms_are_valid(self):
        self.assertTrue(pr.is_valid_mac("aa:bb:cc:dd:ee:ff"))
        self.assertTrue(pr.is_valid_mac("AA-BB-CC-11-22-33"))

    def test_wrong_shape_or_non_hex_is_invalid(self):
        self.assertFalse(pr.is_valid_mac("aa:bb:cc"))
        self.assertFalse(pr.is_valid_mac("zz:zz:zz:zz:zz:zz"))
        self.assertFalse(pr.is_valid_mac(None))
        self.assertFalse(pr.is_valid_mac(""))


class SuggestOwnerTeam(unittest.TestCase):
    def test_hostname_pattern_match_suggests_the_shared_owner(self):
        asset = {"name": "WIN-APP09", "ip": "10.99.99.99", "type": "windows-server"}
        known = [{"name": "WIN-APP07", "ip": "10.1.1.1", "type": "windows-server",
                  "owner": "Web Ops", "team": "Platform"}]
        result = pr.suggest_owner_team(asset, known)
        self.assertEqual(result["owner"], "Web Ops")
        self.assertEqual(result["team"], "Platform")
        self.assertTrue(any("Hostname pattern" in r for r in result["reasons"]))

    def test_subnet_match_suggests_the_shared_owner(self):
        asset = {"name": "UNRELATED-NAME", "ip": "10.20.30.99", "type": "unix-server"}
        known = [{"name": "WIN-DC01", "ip": "10.20.30.41", "type": "windows-server",
                  "owner": "Priya Nair", "team": "Identity"}]
        result = pr.suggest_owner_team(asset, known)
        self.assertEqual(result["owner"], "Priya Nair")
        self.assertTrue(any("subnet" in r for r in result["reasons"]))

    def test_asset_type_alone_is_the_weakest_signal_but_still_matches(self):
        asset = {"name": "SOMETHING-ELSE", "ip": None, "type": "iot-ot-device"}
        known = [{"name": "AXIS-CAM-LOBBY-03", "ip": None, "type": "iot-ot-device",
                  "owner": "Facilities Security Team", "team": "Physical Security"}]
        result = pr.suggest_owner_team(asset, known)
        self.assertEqual(result["owner"], "Facilities Security Team")

    def test_multiple_agreeing_signals_increase_confidence(self):
        asset = {"name": "WIN-APP09", "ip": "10.20.30.99", "type": "windows-server"}
        weak_known = [{"name": "RANDOM-NAME", "ip": "10.1.1.1", "type": "windows-server",
                       "owner": "Team A", "team": "T1"}]
        strong_known = [
            {"name": "WIN-APP07", "ip": "10.20.30.41", "type": "windows-server",
             "owner": "Team B", "team": "T2"},
        ]
        weak_result = pr.suggest_owner_team(asset, weak_known)
        strong_result = pr.suggest_owner_team(asset, strong_known)
        self.assertGreater(strong_result["confidence"], weak_result["confidence"])

    def test_no_matching_signal_returns_none(self):
        asset = {"name": "ZZZ-NOTHING01", "ip": "192.168.99.99", "type": "unknown"}
        known = [{"name": "WIN-DC01", "ip": "10.20.30.41", "type": "windows-server",
                  "owner": "Priya Nair", "team": "Identity"}]
        self.assertIsNone(pr.suggest_owner_team(asset, known))

    def test_empty_known_assets_returns_none(self):
        asset = {"name": "WIN-APP09", "ip": "10.20.30.99", "type": "windows-server"}
        self.assertIsNone(pr.suggest_owner_team(asset, []))

    def test_known_asset_with_no_owner_is_never_a_source_of_suggestions(self):
        asset = {"name": "WIN-APP09", "ip": "10.20.30.99", "type": "windows-server"}
        known = [{"name": "WIN-APP07", "ip": "10.20.30.41", "type": "windows-server",
                  "owner": None, "team": None}]
        self.assertIsNone(pr.suggest_owner_team(asset, known))

    def test_conflicting_signals_pick_the_higher_weighted_owner(self):
        """Hostname-prefix match (weight 3) should beat a same-type-only match
        (weight 1) for a different owner."""
        asset = {"name": "WIN-APP09", "ip": None, "type": "windows-server"}
        known = [
            {"name": "WIN-APP07", "ip": None, "type": "unix-server",
             "owner": "Hostname Match Owner", "team": "T1"},
            {"name": "OTHER-BOX", "ip": None, "type": "windows-server",
             "owner": "Type Match Owner", "team": "T2"},
        ]
        result = pr.suggest_owner_team(asset, known)
        self.assertEqual(result["owner"], "Hostname Match Owner")


class SuggestType(unittest.TestCase):
    def test_hostname_pattern_match_suggests_the_shared_type(self):
        asset = {"name": "LNX-DB09", "ip": None, "mac": None, "type": "unknown"}
        known = [{"name": "LNX-DB03", "ip": None, "mac": None, "type": "unix-server"}]
        result = pr.suggest_type(asset, known)
        self.assertEqual(result["type"], "unix-server")

    def test_subnet_match_suggests_the_shared_type(self):
        asset = {"name": "NEW-HOST", "ip": "10.20.30.99", "mac": None, "type": "unknown"}
        known = [{"name": "WIN-DC01", "ip": "10.20.30.41", "mac": None, "type": "windows-server"}]
        result = pr.suggest_type(asset, known)
        self.assertEqual(result["type"], "windows-server")

    def test_mac_oui_match_suggests_the_shared_type(self):
        asset = {"name": "IOT-DEVICE-9", "ip": None, "mac": "AA:BB:CC:01:02:03", "type": "unknown"}
        known = [{"name": "AXIS-CAM-LOBBY-03", "ip": None, "mac": "AA:BB:CC:99:88:77",
                  "type": "iot-ot-device"}]
        result = pr.suggest_type(asset, known)
        self.assertEqual(result["type"], "iot-ot-device")
        self.assertTrue(any("MAC vendor" in r for r in result["reasons"]))

    def test_known_asset_with_unknown_type_is_never_a_source_of_suggestions(self):
        asset = {"name": "LNX-DB09", "ip": None, "mac": None, "type": "unknown"}
        known = [{"name": "LNX-DB03", "ip": None, "mac": None, "type": "unknown"}]
        self.assertIsNone(pr.suggest_type(asset, known))

    def test_no_matching_signal_returns_none(self):
        asset = {"name": "ZZZ-NOTHING01", "ip": None, "mac": None, "type": "unknown"}
        known = [{"name": "WIN-DC01", "ip": "10.20.30.41", "mac": None, "type": "windows-server"}]
        self.assertIsNone(pr.suggest_type(asset, known))


class AnnotateUnownedAssets(unittest.TestCase):
    def test_only_unowned_rows_are_returned(self):
        rows = [
            {"name": "WIN-DC01", "ip": "10.20.30.41", "type": "windows-server",
             "owner": "Priya Nair", "team": "Identity"},
            {"name": "WIN-APP09", "ip": "10.20.30.99", "type": "windows-server",
             "owner": None, "team": None},
        ]
        result = pr.annotate_unowned_assets(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "WIN-APP09")

    def test_each_unowned_row_gets_a_suggestion_key(self):
        rows = [
            {"name": "WIN-DC01", "ip": "10.20.30.41", "type": "windows-server",
             "owner": "Priya Nair", "team": "Identity"},
            {"name": "WIN-APP09", "ip": "10.20.30.99", "type": "windows-server",
             "owner": None, "team": None},
        ]
        result = pr.annotate_unowned_assets(rows)
        self.assertIn("suggestion", result[0])
        self.assertEqual(result[0]["suggestion"]["owner"], "Priya Nair")

    def test_no_match_gives_a_none_suggestion_not_a_missing_key(self):
        rows = [
            {"name": "WIN-DC01", "ip": "10.20.30.41", "type": "windows-server",
             "owner": "Priya Nair", "team": "Identity"},
            {"name": "ZZZ-NOTHING01", "ip": "192.168.99.99", "type": "unknown",
             "owner": None, "team": None},
        ]
        result = pr.annotate_unowned_assets(rows)
        self.assertIsNone(result[0]["suggestion"])

    def test_does_not_mutate_input_rows(self):
        rows = [{"name": "WIN-APP09", "ip": "10.20.30.99", "type": "windows-server",
                 "owner": None, "team": None}]
        pr.annotate_unowned_assets(rows)
        self.assertNotIn("suggestion", rows[0])

    def test_all_owned_returns_empty_list(self):
        rows = [{"name": "WIN-DC01", "ip": "10.20.30.41", "type": "windows-server",
                 "owner": "Priya Nair", "team": "Identity"}]
        self.assertEqual(pr.annotate_unowned_assets(rows), [])


if __name__ == "__main__":
    unittest.main()
