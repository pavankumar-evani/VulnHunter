"""
Quantum-readiness classification - flags findings whose underlying weakness involves
classical asymmetric cryptography (RSA, ECDSA/EC, Diffie-Hellman) that a sufficiently
large quantum computer running Shor's algorithm would break, or a related legacy
TLS/cipher weakness (SSLv2/SSLv3, 3DES, RC4, export-grade ciphers, MD5/SHA-1 signatures)
that's classically broken already and commonly co-occurs with - and motivates auditing
for - the same asymmetric-crypto usage.

WHAT THIS IS NOT: a "quantum vulnerability scanner." No such product category exists to
honestly claim - a quantum computer capable of breaking real-world RSA/ECDSA doesn't
exist yet, so there is nothing to "scan for" in the sense of detecting an active quantum
attack. This is a real-CVE-title keyword classification (a disclosed heuristic, same
"keyword-matched, not authoritative" honesty tier as attack_mapping.py's ATT&CK tagging
and compensating_controls.py's suggestions - this app's normalized finding schema
carries no separate CWE field to join against) against a real, cited migration
standard:

- NIST finalized FIPS 203 (ML-KEM, key-encapsulation - the RSA/Diffie-Hellman
  replacement), FIPS 204 (ML-DSA, digital signatures - the RSA/ECDSA replacement), and
  FIPS 205 (SLH-DSA, hash-based digital signatures, a structurally different backup
  algorithm) in August 2024. See https://csrc.nist.gov/pubs/fips/203/final,
  /204/final, /205/final.
- NIST IR 8547 (Initial Public Draft, November 2024 - not yet finalized) sets real
  migration deadlines specifically for the WEAKER, 112-bit-security-strength classical
  parameter tier (e.g. RSA-2048, ECDSA P-256): deprecated after 2030, disallowed after
  2035. Stronger classical parameters (RSA-3072+/ECDSA P-384) skip the 2030 step and go
  straight to "disallowed after 2035" only - this module deliberately doesn't try to
  distinguish key sizes from a title string alone, so it cites the earlier, more
  conservative 2030/2035 pair for every asymmetric-crypto match rather than guessing a
  key size. NSA's CNSA 2.0 (PP-22-1338) is a SEPARATE, National-Security-Systems-
  specific framework with its own different category-by-category schedule
  (2025-2033, converging with IR 8547 only at a shared 2035 backstop) - not the same
  numbers as IR 8547's, and not cited by this module to avoid conflating the two.

Extends the existing certificate/TLS domain rather than inventing a parallel one - every
finding this flags is already a real, NVD-sourced CVE already present in this app's
normalized findings (see remediation/sample-data/generate_bulk_findings.py's own
NVD-query sourcing for the "certificate" category, which is where the asymmetric-crypto
CVEs below - CVE-2011-5095 Diffie-Hellman, CVE-2018-0735 ECDSA, CVE-2015-3194 RSA, among
others - already came from organically). Nothing here is fabricated sample data.

Two distinct categories, not one undifferentiated "quantum" bucket - conflating them
would overstate what's actually true:

  - "asymmetric-crypto": the finding's own real title names RSA, ECDSA, elliptic-curve,
    or Diffie-Hellman usage - the genuinely quantum-relevant case (Shor's algorithm
    breaks exactly these). Points toward FIPS 203/204/205 migration.
  - "legacy-protocol": SSLv2/SSLv3, 3DES, RC4, export-grade ciphers, or MD5/SHA-1
    certificate signatures - classically broken already (nothing to do with quantum
    computers specifically), included because a legacy TLS stack exhibiting these is
    real, practical evidence worth auditing for accompanying asymmetric-crypto usage as
    part of the same modernization effort - not itself claimed as quantum-relevant.
"""
import re

# Case-insensitive except RC4 (kept case-sensitive on purpose - real cipher references
# are written "RC4"; case-insensitive matching would also catch Linux kernel release-
# candidate version strings like "2.6.17-rc4", a real false positive caught while
# building this against this app's own actual sample data).
_ASYMMETRIC_PATTERNS = [
    r"diffie-hellman",
    r"\bRSA\b",
    r"\bECDSA\b",
    r"elliptic curve",
]
_LEGACY_PROTOCOL_PATTERNS = [
    r"\bSSLv2\b",
    r"\bSSLv3\b",
    r"SSL protocol 3\.0",
    r"SSL 3\.0",
    r"\b3DES\b",
    r"triple.?des",
    r"64-bit block",
    r"export-grade",
    r"export cipher",
    r"MD5.*(signature|certificate)",
    r"SHA-?1.*(signature|certificate)",
]

_ASYMMETRIC_RE = re.compile("|".join(_ASYMMETRIC_PATTERNS), re.IGNORECASE)
_LEGACY_PROTOCOL_RE = re.compile("|".join(_LEGACY_PROTOCOL_PATTERNS), re.IGNORECASE)
_RC4_RE = re.compile(r"\bRC4\b")  # deliberately case-sensitive, see module docstring

NIST_IR_8547_DEPRECATED_BY = 2030
NIST_IR_8547_DISALLOWED_BY = 2035

_ASYMMETRIC_GUIDANCE = (
    "Migrate to NIST FIPS 203 (ML-KEM) for key exchange and FIPS 204 (ML-DSA) or "
    "FIPS 205 (SLH-DSA) for signatures - NIST IR 8547 (draft) targets 2030 deprecation "
    "/ 2035 disallowal for the weaker classical-parameter tier (e.g. RSA-2048); "
    "confirm actual key sizes/curves in use before assuming which milestone applies."
)
_LEGACY_PROTOCOL_GUIDANCE = (
    "Classically broken already (not itself quantum-relevant) - modernize this TLS "
    "stack and audit it for accompanying RSA/ECDSA/Diffie-Hellman usage as part of the "
    "same post-quantum migration effort."
)


def classify_quantum_readiness(finding):
    """Returns None if this finding's real title doesn't match either category, else
    {category, matched_terms, migration_guidance}. `category` is "asymmetric-crypto"
    (checked first - a title can match both, and the quantum-relevant asymmetric case
    is the more important classification to surface) or "legacy-protocol"."""
    title = finding.get("title") or ""
    if _ASYMMETRIC_RE.search(title):
        return {
            "category": "asymmetric-crypto",
            "migration_guidance": _ASYMMETRIC_GUIDANCE,
        }
    if _LEGACY_PROTOCOL_RE.search(title) or _RC4_RE.search(title):
        return {
            "category": "legacy-protocol",
            "migration_guidance": _LEGACY_PROTOCOL_GUIDANCE,
        }
    return None


def tag_quantum_readiness(findings):
    """Adds `quantum_readiness` to every finding - None when not relevant, else
    {category, migration_guidance, nist_ir_8547_deprecated_by,
    nist_ir_8547_disallowed_by}. Returns a new list (doesn't mutate the input), same
    convention as every other tag_*() enrichment pass in this package."""
    tagged = []
    for f in findings:
        f = dict(f)
        match = classify_quantum_readiness(f)
        if match:
            f["quantum_readiness"] = {
                **match,
                "nist_ir_8547_deprecated_by": NIST_IR_8547_DEPRECATED_BY,
                "nist_ir_8547_disallowed_by": NIST_IR_8547_DISALLOWED_BY,
            }
        else:
            f["quantum_readiness"] = None
        tagged.append(f)
    return tagged
