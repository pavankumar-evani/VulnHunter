"""
Tests for remediation/enrichment/quantum_readiness.py - a disclosed keyword-heuristic
classifier (same honesty tier as attack_mapping.py's ATT&CK tagging), not a certified
CWE-database join, since this app's normalized finding schema carries no CWE field.
"""
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.enrichment.quantum_readiness import (  # noqa: E402
    classify_quantum_readiness, tag_quantum_readiness,
    NIST_IR_8547_DEPRECATED_BY, NIST_IR_8547_DISALLOWED_BY,
)


def _finding(title, **overrides):
    f = {"id": "FIND-TEST", "title": title, "cve": "CVE-2020-0001"}
    f.update(overrides)
    return f


class AsymmetricCryptoClassification(unittest.TestCase):
    def test_rsa_title_is_asymmetric_crypto(self):
        result = classify_quantum_readiness(_finding("The OpenSSL RSA Key generation algorithm has been shown to be vulnerable"))
        self.assertEqual(result["category"], "asymmetric-crypto")
        self.assertIn("FIPS 203", result["migration_guidance"])

    def test_ecdsa_title_is_asymmetric_crypto(self):
        result = classify_quantum_readiness(_finding("The OpenSSL ECDSA signature algorithm has been shown to be vulnerable to a timing attack"))
        self.assertEqual(result["category"], "asymmetric-crypto")

    def test_diffie_hellman_title_is_asymmetric_crypto(self):
        result = classify_quantum_readiness(_finding("The Diffie-Hellman key-exchange implementation in OpenSSL 0.9.8 mishandles"))
        self.assertEqual(result["category"], "asymmetric-crypto")

    def test_elliptic_curve_title_is_asymmetric_crypto(self):
        result = classify_quantum_readiness(_finding("The elliptic curve cryptography (ECC) subsystem in OpenSSL 1.0.0d"))
        self.assertEqual(result["category"], "asymmetric-crypto")


class LegacyProtocolClassification(unittest.TestCase):
    def test_sslv2_title_is_legacy_protocol(self):
        result = classify_quantum_readiness(_finding("The SSLv2 protocol, as used in OpenSSL before 1.0.1s, requires a server to"))
        self.assertEqual(result["category"], "legacy-protocol")
        self.assertIn("not itself quantum-relevant", result["migration_guidance"])

    def test_sslv3_title_is_legacy_protocol(self):
        result = classify_quantum_readiness(_finding("The SSL protocol 3.0, as used in OpenSSL through 1.0.1i, uses nondeterministic CBC padding"))
        self.assertEqual(result["category"], "legacy-protocol")

    def test_uppercase_rc4_is_legacy_protocol(self):
        result = classify_quantum_readiness(_finding("The OpenSSL 3.0 implementation of the RC4-MD5 ciphersuite incorrectly uses"))
        self.assertEqual(result["category"], "legacy-protocol")

    def test_3des_is_legacy_protocol(self):
        result = classify_quantum_readiness(_finding("SWEET32: 3DES ciphers are vulnerable to a birthday attack over long-lived HTTPS connections"))
        self.assertEqual(result["category"], "legacy-protocol")

    def test_lowercase_rc4_in_kernel_release_candidate_version_is_not_a_false_positive(self):
        """Regression guard for the exact false positive caught while building this
        against this app's own real sample data: Linux kernel version strings like
        "2.6.17-rc4" (release candidate 4) must never be classified as the RC4 cipher -
        real cipher references are written "RC4" (uppercase), never lowercase "rc4"."""
        result = classify_quantum_readiness(_finding(
            "Integer overflow in the hrtimer_forward function (hrtimer.c) in Linux kernel 2.6.21-rc4, when running",
        ))
        self.assertIsNone(result)


class NonMatchingFindings(unittest.TestCase):
    def test_unrelated_title_is_not_classified(self):
        result = classify_quantum_readiness(_finding("Apache Log4j2 Remote Code Execution (Log4Shell)"))
        self.assertIsNone(result)

    def test_missing_title_does_not_crash(self):
        result = classify_quantum_readiness({"id": "FIND-X", "cve": "CVE-2020-0001"})
        self.assertIsNone(result)

    def test_rsa_securid_style_false_positive_is_intentionally_not_guarded_against(self):
        """Documents a known, accepted limitation rather than silently hiding it: bare
        substring/word-boundary matching on "RSA" would also match an unrelated product
        name containing that word. Real CVE titles in this app's own dataset don't
        exhibit this (verified against all 9000+ real titles while building this), so
        it's accepted as the same kind of disclosed heuristic imprecision
        attack_mapping.py's ATT&CK tagging already carries - not fixed with a
        more complex parser for a case that doesn't occur in real data today."""
        result = classify_quantum_readiness(_finding("RSA SecurID token seed compromise disclosed in a vendor breach"))
        self.assertEqual(result["category"], "asymmetric-crypto")  # documented, not "fixed"


class TagQuantumReadiness(unittest.TestCase):
    def test_tags_every_finding_including_non_matches(self):
        findings = [
            _finding("The Diffie-Hellman key-exchange implementation in OpenSSL 0.9.8"),
            _finding("Apache Log4j2 Remote Code Execution (Log4Shell)"),
        ]
        tagged = tag_quantum_readiness(findings)
        self.assertIsNotNone(tagged[0]["quantum_readiness"])
        self.assertIsNone(tagged[1]["quantum_readiness"])

    def test_does_not_mutate_input(self):
        findings = [_finding("RSA key generation vulnerable to a timing attack")]
        original_keys = set(findings[0].keys())
        tag_quantum_readiness(findings)
        self.assertEqual(set(findings[0].keys()), original_keys)

    def test_includes_real_cited_nist_ir_8547_deadlines(self):
        tagged = tag_quantum_readiness([_finding("RSA key generation vulnerable to a timing attack")])
        qr = tagged[0]["quantum_readiness"]
        self.assertEqual(qr["nist_ir_8547_deprecated_by"], NIST_IR_8547_DEPRECATED_BY)
        self.assertEqual(qr["nist_ir_8547_disallowed_by"], NIST_IR_8547_DISALLOWED_BY)
        self.assertEqual(NIST_IR_8547_DEPRECATED_BY, 2030)
        self.assertEqual(NIST_IR_8547_DISALLOWED_BY, 2035)


class RealSampleDataIsHandledCleanly(unittest.TestCase):
    """Regression guard using this app's own real, already-committed sample data - not
    a synthetic fixture. Confirms the classifier finds a real, non-trivial, non-zero
    count without crashing on anything in the actual dataset (mojibake title bytes,
    missing fields, etc.)."""

    def test_real_findings_produce_a_reasonable_non_zero_match_count(self):
        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        tagged = tag_quantum_readiness(findings)
        matched = [f for f in tagged if f["quantum_readiness"]]
        self.assertGreaterEqual(len(matched), 20)
        self.assertLess(len(matched), 200)  # sanity ceiling - this is a targeted category, not most of the dataset

    def test_known_real_cves_are_classified_as_expected(self):
        """Spot-checks specific, already-verified-real CVEs known to be present in the
        shipped sample data (see this module's own docstring)."""
        findings_path = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        by_cve = {f["cve"]: f for f in findings if f.get("cve")}
        self.assertEqual(classify_quantum_readiness(by_cve["CVE-2011-5095"])["category"], "asymmetric-crypto")  # Diffie-Hellman
        self.assertEqual(classify_quantum_readiness(by_cve["CVE-2018-0735"])["category"], "asymmetric-crypto")  # ECDSA
        self.assertEqual(classify_quantum_readiness(by_cve["CVE-2016-0800"])["category"], "legacy-protocol")  # DROWN/SSLv2


if __name__ == "__main__":
    unittest.main()
