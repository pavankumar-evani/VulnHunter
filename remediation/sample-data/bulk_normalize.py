#!/usr/bin/env python3
"""
Merges the bulk real-CVE fixture files (remediation/sample-data/bulk/*, produced by
generate_bulk_findings.py) into remediation/output/normalized-findings.json.

This applies the EXACT same normalization rules documented in
.claude/agents/vuln-ingest-normalizer.md (asset.type classification, remediation_domain
assignment, stable IDs) as a plain script instead of an LLM subagent invocation - at
the ~3,000-finding scale this produces, running the real subagent once per record (or
even once per file) isn't tractable, and the classification rules are fully
deterministic/documented, not a judgment call that needs re-deriving each time (the
FIND-15 case earlier in this project's history already proved the subagent and these
exact rules agree). See that file's docstring for the source rules this mirrors.

Unlike a real third-party Tenable/Armis export, each bulk file here was generated with
full foreknowledge of its own category (see generate_bulk_findings.py), so asset.type
is derived directly from which file a row came from - no free-text inference needed,
which is what removes the ambiguity an LLM subagent would otherwise have to resolve
per-row.

Existing FIND-1..FIND-N entries in normalized-findings.json are preserved byte-for-byte
(matched by source + source_ref, never re-numbered) - only genuinely new records from
the bulk files get new sequential IDs, exactly matching the normalizer's stable-ID rule.
"""
import argparse
import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BULK_DIR = Path(__file__).resolve().parent / "bulk"
OUTPUT_PATH = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"

# The 15 original, individually hand-curated findings (from before any bulk sourcing) -
# never removed, renumbered, or regenerated, regardless of any --reset-asset-types run.
ORIGINAL_FIND_IDS = {f"FIND-{i}" for i in range(1, 16)}

# filename stem -> asset.type, per vuln-ingest-normalizer.md's documented classification
# rules (each bulk file was generated already knowing which category it represents).
FILE_TO_ASSET_TYPE = {
    "tenable_bulk_os_windows": "windows-server",
    "tenable_bulk_os_linux": "unix-server",
    "tenable_bulk_network": "network-routing-switching",
    "tenable_bulk_network_security": "network-security-device",
    "tenable_bulk_cloud": "cloud-infrastructure",
    "tenable_bulk_certificate": "certificate",
    "tenable_bulk_os_apps": "client-application",
    "tenable_bulk_sca": "application",
    "tenable_bulk_dast": "application",
    "tenable_bulk_iac": "iac-resource",
    "tenable_bulk_code_repository": "code-repository",
    "tenable_bulk_code_repository_secrets": "code-repository",
    "tenable_bulk_runtime": "container-runtime",
    "tenable_bulk_ai_ml": "ai-ml-system",
    "tenable_bulk_endpoint_windows": "windows-endpoint",
    "tenable_bulk_endpoint_mobile": "mobile-device",
    "tenable_bulk_printer": "printer",
    "tenable_bulk_virtualization": "virtualization-host",
}

# Only these two domains have a working remediation-fixer subagent today - same rule
# vuln-ingest-normalizer.md documents for every other asset type.
_REMEDIATION_DOMAIN_SUPPORTED = {"windows-server", "unix-server"}


def _remediation_domain(asset_type):
    return asset_type if asset_type in _REMEDIATION_DOMAIN_SUPPORTED else None


# Purely informational, reference-only field - names the REAL-WORLD tool that would
# normally patch this asset class, since this app has no working SCCM/Intune/vendor
# API integration for any of them (remediation_domain stays null for all of these -
# see _REMEDIATION_DOMAIN_SUPPORTED above, unchanged). Deliberately omits asset types
# where no single tool applies honestly (e.g. network-routing-switching varies too
# much by vendor to name one mechanism).
_REMEDIATION_MECHANISM = {
    "windows-endpoint": "SCCM / Microsoft Configuration Manager",
    "mobile-device": "MDM (e.g. Microsoft Intune)",
    "printer": "Vendor firmware update (manual or vendor management console)",
    "virtualization-host": "Vendor hypervisor patch tooling (e.g. VMware Update Manager)",
}


def _remediation_mechanism(asset_type):
    return _REMEDIATION_MECHANISM.get(asset_type)


def _parse_tenable_csv(path, asset_type):
    findings = []
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            cve = row["CVE"] or None
            cvss = float(row["CVSS v3.0 Base Score"]) if row["CVSS v3.0 Base Score"] else None
            findings.append({
                "source": "tenable",
                "source_ref": row["Plugin ID"],
                "asset": {
                    "name": row["Host"],
                    "ip": row["IP Address"],
                    "type": asset_type,
                    "os": row["OS"],
                },
                "title": row["Name"],
                "cve": cve,
                "cvss": cvss,
                "severity": row["Risk"],
                "description": row["Synopsis"],
                "recommended_fix": row["Solution"],
                "remediation_domain": _remediation_domain(asset_type),
                "remediation_mechanism": _remediation_mechanism(asset_type),
                "first_seen": row["First Discovered"],
                "last_seen": row["Last Observed"],
            })
    return findings


def _parse_armis_bulk(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for device in data["devices"]:
        for alert in device["alerts"]:
            findings.append({
                "source": "armis",
                "source_ref": str(device["deviceId"]),
                "asset": {
                    "name": device["deviceName"],
                    "ip": device["ipAddress"],
                    "type": "iot-ot-device",
                    "os": device["deviceType"],
                },
                "title": alert["title"],
                "cve": alert.get("cve"),
                "cvss": None,
                "severity": device["riskLevel"],
                "description": alert["description"],
                "recommended_fix": alert.get("recommendedFix")
                    or "Apply the vendor's security update for the affected firmware/software version, "
                       "or isolate the device on a segmented network/VLAN if no patch is currently available.",
                "remediation_domain": None,
                "first_seen": alert["firstSeen"][:10],
                "last_seen": alert["lastSeen"][:10],
            })
    return findings


def load_bulk_findings():
    all_new = []
    for csv_path in sorted(BULK_DIR.glob("tenable_bulk_*.csv")):
        asset_type = FILE_TO_ASSET_TYPE.get(csv_path.stem)
        if not asset_type:
            print(f"  skipping unrecognized bulk file: {csv_path.name}")
            continue
        rows = _parse_tenable_csv(csv_path, asset_type)
        print(f"  {csv_path.name}: {len(rows)} findings -> asset.type={asset_type}")
        all_new.extend(rows)

    armis_path = BULK_DIR / "armis_bulk_ot.json"
    if armis_path.exists():
        rows = _parse_armis_bulk(armis_path)
        print(f"  {armis_path.name}: {len(rows)} findings -> asset.type=iot-ot-device")
        all_new.extend(rows)

    return all_new


def merge(existing, new_findings):
    """Stable-ID merge: keep every existing finding exactly as-is (matched by
    source+source_ref), only assign new sequential FIND-N ids to genuinely new
    records, continuing from the current highest id."""
    existing_keys = {(f["source"], f["source_ref"]) for f in existing}
    next_id = max((int(f["id"].split("-")[1]) for f in existing), default=0) + 1

    merged = list(existing)
    added = 0
    for f in new_findings:
        key = (f["source"], f["source_ref"])
        if key in existing_keys:
            continue  # already present - stable-ID rule, never duplicate or renumber
        f = dict(f)
        f["id"] = f"FIND-{next_id}"
        f["kev"] = None
        f["epss"] = None
        merged.append(f)
        existing_keys.add(key)
        next_id += 1
        added += 1
    return merged, added


def compact_bulk_ids(merged):
    """Renumbers every non-original finding (id not in ORIGINAL_FIND_IDS) to a
    contiguous FIND-16, FIND-17, ... sequence, preserving relative order - closes any
    gaps left by drop_bulk_findings_of_type() removing findings from the middle of the
    range. Safe because only the original 15 findings have external references
    (playbook filenames like FIND-4-sudo-baron-samedit-patch.yml) - no bulk-sourced
    finding has a generated playbook, so nothing external points at a bulk FIND-N by
    number. Several dashboard/tests assert the live finding-ID set is a contiguous
    FIND-1..FIND-N range, which a gap would break."""
    original = [f for f in merged if f["id"] in ORIGINAL_FIND_IDS]
    bulk = [f for f in merged if f["id"] not in ORIGINAL_FIND_IDS]
    next_id = len(ORIGINAL_FIND_IDS) + 1
    renumbered = []
    for f in bulk:
        f = dict(f)
        f["id"] = f"FIND-{next_id}"
        renumbered.append(f)
        next_id += 1
    return original + renumbered


def drop_bulk_findings_of_type(existing, asset_types):
    """Removes every non-original finding (id not in ORIGINAL_FIND_IDS) whose
    asset.type is in `asset_types` - used when re-running the generator with a higher
    target/different query set for a category, so the old counter-based source_refs
    from before the CVE-derived stable-ID fix don't linger as orphaned duplicates
    alongside the freshly re-merged versions of the same real CVEs."""
    kept = [f for f in existing
            if f["id"] in ORIGINAL_FIND_IDS or (f.get("asset") or {}).get("type") not in asset_types]
    return kept, len(existing) - len(kept)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset-asset-types", nargs="*", default=[],
                         help="Asset types to fully drop (except the original 15 findings) before "
                              "re-merging - use when a category's bulk data was regenerated with a "
                              "different ID scheme or target and would otherwise duplicate.")
    args = parser.parse_args()

    existing = json.loads(OUTPUT_PATH.read_text(encoding="utf-8")) if OUTPUT_PATH.exists() else []
    print(f"Existing findings: {len(existing)}")

    if args.reset_asset_types:
        existing, dropped = drop_bulk_findings_of_type(existing, set(args.reset_asset_types))
        print(f"Dropped {dropped} previously-merged bulk findings for asset types {args.reset_asset_types} "
              f"(will be re-added fresh from the regenerated CSVs below).")

    print("Parsing bulk fixture files:")
    new_findings = load_bulk_findings()

    merged, added = merge(existing, new_findings)
    if args.reset_asset_types:
        merged = compact_bulk_ids(merged)
        print("Renumbered non-original findings to close any ID gaps left by the reset above.")
    OUTPUT_PATH.write_text(json.dumps(merged, indent=2), encoding="utf-8")

    print(f"\nAdded {added} new findings (of {len(new_findings)} parsed - the rest already existed).")
    print(f"Total findings now: {len(merged)}")
    print(f"Written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
