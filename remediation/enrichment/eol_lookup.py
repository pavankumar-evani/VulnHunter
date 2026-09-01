#!/usr/bin/env python3
"""
End-of-Life / End-of-Support (EOL/EOS) classification for the OS/software string
already present on every finding's `asset.os` field.

Same "small, transparent, explainable, never-guessed" pattern as
remediation/inventory/pattern_recognition.py's owner/team suggestion heuristic - this
is a plain substring lookup against a short table of real, publicly-documented vendor
lifecycle dates (Microsoft Lifecycle, Ubuntu/Canonical release schedule, the CentOS
Project's own EOL announcement), not a fabricated or interpolated date. Every entry
below was chosen because its `match` substring is confirmed present in this repo's own
real bulk-sourced `asset.os` strings (see remediation/output/normalized-findings.json) -
this table isn't speculative coverage for OS versions that don't actually appear here.

Deliberately NOT covered: network/security-appliance firmware (Cisco IOS, FortiOS,
PAN-OS, etc.) and industrial/OT device firmware. Those vendors don't publish one
simple, unambiguous "EOL date" per software-version string the way an OS vendor does -
their lifecycle is usually tied to specific hardware models, which this dataset's
`asset.os` strings don't capture. Rather than guess, `classify_eol()` returns
`{"status": "unknown"}` for anything not in EOL_REFERENCE - the same honest default
`asset_inventory.py` already uses for an asset with no owner/facing classification.
"""
import datetime

EOL_REFERENCE = [
    {"match": "windows server 2012", "vendor": "Microsoft",
     "eol_date": "2023-10-10", "source": "Microsoft Product Lifecycle"},
    {"match": "windows server 2016", "vendor": "Microsoft",
     "eol_date": "2027-01-12", "source": "Microsoft Product Lifecycle"},
    {"match": "windows server 2019", "vendor": "Microsoft",
     "eol_date": "2029-01-09", "source": "Microsoft Product Lifecycle"},
    {"match": "windows server 2022", "vendor": "Microsoft",
     "eol_date": "2031-10-14", "source": "Microsoft Product Lifecycle"},
    {"match": "windows 10", "vendor": "Microsoft",
     "eol_date": "2025-10-14", "source": "Microsoft Product Lifecycle"},
    {"match": "ubuntu linux 22.04", "vendor": "Canonical",
     "eol_date": "2027-04-01", "source": "Ubuntu Release Cycle (22.04 LTS standard support)"},
    {"match": "ubuntu linux 20.04", "vendor": "Canonical",
     "eol_date": "2025-04-01", "source": "Ubuntu Release Cycle (20.04 LTS standard support)"},
    {"match": "centos linux 7", "vendor": "The CentOS Project",
     "eol_date": "2024-06-30", "source": "CentOS Project EOL announcement"},
]

# Findings within this many days of their eol_date (before or after) are "eol-soon"
# rather than a flat past/future split - gives a security team a heads-up window
# before an asset actually goes unsupported, not just a binary alarm on the day itself.
EOL_SOON_WINDOW_DAYS = 180


def classify_eol(os_string, as_of=None):
    """Case-insensitive substring match against EOL_REFERENCE - longest match wins if
    more than one substring matches (e.g. a hypothetical string matching both a
    shorter and a more specific entry). Returns {"status": "unknown"} when nothing
    matches, same as asset_inventory.py's own "unknown" default for unclassified
    facing/owner - not a guessed date."""
    if not os_string:
        return {"status": "unknown"}
    text = os_string.lower()
    matches = [entry for entry in EOL_REFERENCE if entry["match"] in text]
    if not matches:
        return {"status": "unknown"}
    entry = max(matches, key=lambda e: len(e["match"]))

    today = as_of or datetime.date.today()
    eol_date = datetime.date.fromisoformat(entry["eol_date"])
    days_until_eol = (eol_date - today).days

    if days_until_eol < 0:
        status = "eol"
    elif days_until_eol <= EOL_SOON_WINDOW_DAYS:
        status = "eol-soon"
    else:
        status = "supported"

    return {
        "status": status,
        "vendor": entry["vendor"],
        "eol_date": entry["eol_date"],
        "source": entry["source"],
        "days_until_eol": days_until_eol,
    }


def tag_eol_eos(findings, as_of=None):
    """Adds `eol_status` to each finding, derived from its own asset.os - same
    non-mutating batch-tagging convention as tag_scan_types/tag_compensating_controls/
    tag_infra_categories (returns new dicts, doesn't modify the input list/dicts)."""
    tagged = []
    for f in findings:
        f = dict(f)
        os_string = (f.get("asset") or {}).get("os")
        f["eol_status"] = classify_eol(os_string, as_of=as_of)
        tagged.append(f)
    return tagged
