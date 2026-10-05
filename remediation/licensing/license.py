"""
Module licensing: a signed, offline-verifiable licence that says which of the eight modules a deployment may use, and the check that applies it.

Design (docs/LICENSING.md):
  * The unit of licence is the MODULE, the same eight modules the sidebar shows. The platform shell (sign-in, the findings store, support, connections and administration needed to apply a
    licence) is core and always available.
  * A licence is a small JSON claim set signed with the vendor's Ed25519 private key; the deployment verifies it with the vendor PUBLIC key. Nothing is sent anywhere: no phone-home, no
    telemetry, so it works air-gapped. Format: base64url(JSON claims) + "." + base64url(signature).
  * Claims: v (1), id, customer, edition (a label), modules (list), issued (date), expires (date), grace_days (optional).
  * Modes (config licensing.yaml `mode`, override QUANTA_LICENSE_MODE): off (default, nothing checked), warn (read and reported, never blocks), enforce (a route of an unlicensed module
    answers 403). A missing, unreadable, badly signed or long-expired licence entitles NOTHING beyond core in enforce mode; a licence past its end date keeps working for the grace period.
  * Routes map to modules by longest prefix (licensing.yaml). A test fails if any API route has no entry, so a new feature cannot ship outside the licence by accident.

Honest limits: this is a technical guardrail and a clear contract, not copy protection. Quanta is self-hosted, so someone who can edit the code can remove the check; the licence terms are
what bind. The mechanism has been unit-tested with generated keys and has never been used with a real issued licence.
"""
import base64
import datetime
import json
import os
from pathlib import Path

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "licensing.yaml"
BUNDLED_PUBLIC_KEY = Path(__file__).resolve().parent / "vendor_public_key.pem"
MODULE_IDS = ("soc", "appsec", "devsecops", "infra", "ai", "remediation", "grc", "admin")
MODES = ("off", "warn", "enforce")
_CACHE = {"cfg": None, "mtime": None}


class LicenseError(ValueError):
    pass


def config():
    mtime = CONFIG_PATH.stat().st_mtime
    if _CACHE["cfg"] is None or _CACHE["mtime"] != mtime:
        _CACHE["cfg"] = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
        _CACHE["mtime"] = mtime
    return _CACHE["cfg"]


def _b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------- issuing and verifying (vendor side signs, deployment verifies)
def generate_keypair():
    """(private PEM, public PEM) for a new vendor signing key."""
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def issue(private_pem, customer, modules, expires, edition="custom", issued=None, grace_days=None, license_id=None):
    """A signed licence token. `expires` is a date or ISO string."""
    mods = sorted(set(modules))
    bad = [m for m in mods if m not in MODULE_IDS or m == "admin"]
    if bad or not mods:
        raise LicenseError("modules must be a non-empty list drawn from: " + ", ".join(m for m in MODULE_IDS if m != "admin"))
    if not str(customer or "").strip():
        raise LicenseError("A customer name is required")
    exp = datetime.date.fromisoformat(str(expires)[:10])
    issued_on = issued[:10] if isinstance(issued, str) else (issued or datetime.date.today()).isoformat()
    claims = {"v": 1, "id": license_id or _b64(os.urandom(6)), "customer": str(customer).strip()[:200], "edition": str(edition)[:60], "modules": mods,
              "issued": issued_on, "expires": exp.isoformat()}
    if grace_days is not None:
        claims["grace_days"] = int(grace_days)
    body = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    key = serialization.load_pem_private_key(private_pem if isinstance(private_pem, bytes) else private_pem.encode(), password=None)
    return _b64(body) + "." + _b64(key.sign(body))


def verify(token, public_pem):
    """The claims of a correctly signed licence. Raises LicenseError."""
    try:
        body_b64, sig_b64 = str(token).strip().split(".")
        body, sig = _unb64(body_b64), _unb64(sig_b64)
    except (ValueError, TypeError):
        raise LicenseError("The licence is not in the expected format") from None
    try:
        pub = serialization.load_pem_public_key(public_pem if isinstance(public_pem, bytes) else public_pem.encode())
        if not isinstance(pub, Ed25519PublicKey):
            raise LicenseError("The verification key is not an Ed25519 public key")
        pub.verify(sig, body)
    except InvalidSignature:
        raise LicenseError("The licence signature does not verify: it was altered or signed by a different key") from None
    except (ValueError, TypeError) as exc:
        raise LicenseError(f"The verification key could not be read: {exc}") from None
    try:
        claims = json.loads(body)
        datetime.date.fromisoformat(claims["expires"])
        if claims.get("v") != 1 or not isinstance(claims.get("modules"), list):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise LicenseError("The licence claims are not valid") from None
    return claims


# ---------------------------------------------------------------- what this deployment is entitled to
def mode(env=None):
    m = ((env or os.environ).get("QUANTA_LICENSE_MODE") or config().get("mode") or "off").strip().lower()
    return m if m in MODES else "off"


def _token_and_key(env):
    token = (env.get("QUANTA_LICENSE") or "").strip()
    if not token and env.get("QUANTA_LICENSE_FILE"):
        try:
            token = Path(env["QUANTA_LICENSE_FILE"]).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise LicenseError(f"The licence file could not be read: {exc.strerror or exc}") from None
    key_path = env.get("QUANTA_LICENSE_PUBLIC_KEY_FILE")
    key = None
    if key_path:
        try:
            key = Path(key_path).read_bytes()
        except OSError as exc:
            raise LicenseError(f"The verification key file could not be read: {exc.strerror or exc}") from None
    elif BUNDLED_PUBLIC_KEY.exists():
        key = BUNDLED_PUBLIC_KEY.read_bytes()
    return token, key


def status(today=None, env=None):
    """The deployment's licence state: {mode, enforced, state, customer, edition, expires, days_left, modules (entitled ids), message}."""
    env = os.environ if env is None else env
    today = today or datetime.date.today()
    cfg = config()
    m = mode(env)
    every = [x for x in MODULE_IDS]
    base = {"mode": m, "enforced": m == "enforce", "customer": None, "edition": None, "expires": None, "days_left": None, "license_id": None}
    if m == "off":
        return {**base, "state": "unrestricted", "modules": every, "message": "Licence checking is off: every module is available."}
    claims, problem = None, None
    try:
        token, key = _token_and_key(env)
        if not token:
            problem = ("missing", "No licence is installed (set QUANTA_LICENSE or QUANTA_LICENSE_FILE).")
        elif not key:
            problem = ("invalid", "No verification key is configured (set QUANTA_LICENSE_PUBLIC_KEY_FILE).")
        else:
            claims = verify(token, key)
    except LicenseError as exc:
        problem = ("invalid", str(exc))
    if problem:
        return {**base, "state": problem[0], "modules": ["admin"], "message": problem[1] + (" Only the core platform is available." if m == "enforce" else " (Warn mode: nothing is blocked.)")}
    exp = datetime.date.fromisoformat(claims["expires"])
    left = (exp - today).days
    grace = int(claims.get("grace_days", cfg.get("grace_days", 14)))
    if left >= 0:
        state = "expiring" if left <= int(cfg.get("expiring_days", 30)) else "valid"
    elif -left <= grace:
        state = "grace"
    else:
        state = "expired"
    known = [x for x in claims["modules"] if x in MODULE_IDS]
    entitled = sorted(set(known) | {"admin"}) if state != "expired" else ["admin"]
    msg = {"valid": "Licensed.", "expiring": f"The licence ends in {left} day(s).", "grace": f"The licence ended {-left} day(s) ago; modules keep working for {grace - (-left)} more day(s).",
           "expired": "The licence has expired. Only the core platform is available."}[state]
    return {**base, "state": state, "customer": claims.get("customer"), "edition": claims.get("edition"), "expires": claims["expires"], "days_left": left, "license_id": claims.get("id"),
            "modules": entitled, "message": msg + (" (Warn mode: nothing is blocked.)" if m == "warn" else "")}


# ---------------------------------------------------------------- applying it to a route
def module_for_path(path):
    """('core', None) | ('module', [ids]) | (None, None) for a path with no entry. Longest prefix wins across core, module and shared prefixes."""
    cfg = config()
    cands = []
    for p in cfg.get("core") or []:
        cands.append((p, "core", None))
    for mid, prefs in (cfg.get("modules") or {}).items():
        for p in prefs or []:
            cands.append((p, "module", [mid]))
    for p, mids in (cfg.get("shared") or {}).items():
        cands.append((p, "module", list(mids)))
    best = None
    for p, kind, mids in cands:
        if (path == p or path.startswith(p + "/")) and (best is None or len(p) > len(best[0])):
            best = (p, kind, mids)
    return (best[1], best[2]) if best else (None, None)


def check(path, st=None):
    """(allowed, module ids that would grant it). Only an enforcing deployment ever refuses."""
    st = st or status()
    kind, mids = module_for_path(path)
    if not st["enforced"] or kind in ("core", None):
        return True, mids or []
    return any(m in st["modules"] for m in mids), mids
