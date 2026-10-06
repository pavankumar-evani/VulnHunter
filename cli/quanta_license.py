#!/usr/bin/env python3
"""
Quanta licence tool: generate a signing key, issue a module licence, verify one. See docs/LICENSING.md.

  python cli/quanta_license.py keygen --out-dir keys
  python cli/quanta_license.py issue --private-key keys/vendor_private.pem --customer "Acme Ltd" --edition secops --expires 2027-06-30 --out acme.licence
  python cli/quanta_license.py issue --private-key keys/vendor_private.pem --customer "Acme Ltd" --modules soc,infra --expires 2027-06-30
  python cli/quanta_license.py verify --public-key keys/vendor_public.pem --license acme.licence

The PRIVATE key stays with whoever issues licences; never put it on a customer deployment. The deployment gets the licence token (QUANTA_LICENSE or QUANTA_LICENSE_FILE) and the PUBLIC key
(QUANTA_LICENSE_PUBLIC_KEY_FILE, or remediation/licensing/vendor_public_key.pem shipped with the release), and QUANTA_LICENSE_MODE=enforce (or warn to try it first).
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from remediation.licensing import license as lic  # noqa: E402


def cmd_keygen(a):
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    priv_path = out / "vendor_private.pem"
    if priv_path.exists() and not a.force:
        sys.exit(f"{priv_path} already exists; refusing to overwrite a signing key. Use --force to replace it (licences signed with the old key stop verifying).")
    priv, pub = lic.generate_keypair()
    if a.force and priv_path.exists():
        priv_path.unlink()
    # Created with 0600 from the start so the key is never world-readable, not even briefly.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(priv_path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv)
    if os.name == "nt":
        print(f"WARNING: could not confirm that {priv_path} is private: Windows does not enforce POSIX file modes. "
              "Restrict its ACL yourself (icacls) or keep it on an encrypted volume.", file=sys.stderr)
    else:
        try:
            os.chmod(priv_path, 0o600)
        except OSError as exc:
            print(f"WARNING: could not restrict permissions on {priv_path}: {exc}", file=sys.stderr)
    (out / "vendor_public.pem").write_bytes(pub)
    print(f"Wrote {priv_path} (keep secret) and {out / 'vendor_public.pem'} (ships with the product).")


def cmd_issue(a):
    cfg = lic.config()
    modules = [m.strip() for m in a.modules.split(",") if m.strip()] if a.modules else list((cfg.get("editions") or {}).get(a.edition, []))
    if not modules:
        sys.exit(f"Give --modules, or an --edition from: {', '.join((cfg.get('editions') or {}))}")
    try:
        token = lic.issue(Path(a.private_key).read_bytes(), a.customer, modules, a.expires, edition=a.edition or "custom", grace_days=a.grace_days)
    except (lic.LicenseError, ValueError, OSError) as exc:
        sys.exit(f"Could not issue: {exc}")
    if a.out:
        Path(a.out).write_text(token + "\n", encoding="utf-8")
        print(f"Wrote {a.out}")
    else:
        print(token)


def cmd_verify(a):
    token = Path(a.license).read_text(encoding="utf-8").strip() if Path(a.license).exists() else a.license
    try:
        claims = lic.verify(token, Path(a.public_key).read_bytes())
    except (lic.LicenseError, OSError) as exc:
        sys.exit(f"NOT VALID: {exc}")
    print("Signature OK")
    for k in ("id", "customer", "edition", "modules", "issued", "expires", "grace_days"):
        if k in claims:
            print(f"  {k}: {claims[k]}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Quanta module licences")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out-dir", default="keys")
    k.add_argument("--force", action="store_true", help="replace an existing vendor_private.pem")
    k.set_defaults(fn=cmd_keygen)
    i = sub.add_parser("issue")
    i.add_argument("--private-key", required=True)
    i.add_argument("--customer", required=True)
    i.add_argument("--expires", required=True, help="end date, YYYY-MM-DD")
    i.add_argument("--modules", help="comma separated: soc,appsec,devsecops,infra,ai,remediation,grc")
    i.add_argument("--edition", help="a bundle from licensing.yaml (secops, appsec, platform, enterprise) or a label when --modules is given")
    i.add_argument("--grace-days", type=int)
    i.add_argument("--out")
    i.set_defaults(fn=cmd_issue)
    v = sub.add_parser("verify")
    v.add_argument("--public-key", required=True)
    v.add_argument("--license", required=True, help="a licence file or the token itself")
    v.set_defaults(fn=cmd_verify)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
