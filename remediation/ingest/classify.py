"""
Deterministic asset classification for scanner data.

The agent-driven normalizer (`vuln-ingest-normalizer`) classifies hosts with model judgment.
A production deployment that pulls from a scanner on a schedule cannot depend on an
interactive agent session for every row, so this module does the same job with explicit,
readable rules. It is conservative: anything it cannot place with confidence becomes
`unknown` rather than a guess, and it never invents a `remediation_domain` for a type that
has no working fixer.

Order matters: the first matching rule wins, so more specific families come before the
general ones (a "Windows Server" is checked before "Windows").
"""
import re

# (asset type, regex over "os + name + plugin/title", remediation_domain or None)
_RULES = [
    ("iot-ot-device", r"\b(plc|scada|hmi|rtu|modbus|siemens simatic|rockwell|allen[- ]bradley|schneider electric|ics\b|industrial control)", None),
    ("printer", r"\b(printer|laserjet|officejet|xerox|ricoh|konica|lexmark|brother mfc|jetdirect)", None),
    ("virtualization-host", r"\b(esxi|vcenter|vmware vsphere|hyper-v|proxmox|xenserver|kvm host)", None),
    ("network-security-device", r"\b(palo alto|pan-os|fortigate|fortios|fortinet|check ?point|cisco asa|firepower|sonicwall|watchguard|juniper srx|f5 big-?ip|barracuda|netscaler)", None),
    ("network-routing-switching", r"\b(cisco ios|ios-xe|nx-os|catalyst|junos|juniper (ex|mx|qfx)|arista|eos\b|mikrotik|routeros|aruba|procurve|extreme networks|dell networking|switch\b|router\b)", None),
    ("mobile-device", r"\b(android|iphone|ipados|\bios 1\d|ios \d|mobile device)", None),
    ("container-runtime", r"\b(docker|containerd|kubernetes|k8s|openshift|podman|container image)", None),
    ("cloud-infrastructure", r"\b(aws|amazon web services|azure|gcp|google cloud|s3 bucket|iam role|cloudformation|security group)", None),
    ("windows-server", r"windows server|win(dows)? ?(20(03|08|12|16|19|22|25))|\bwin-?(dc|srv|sql)", "windows-server"),
    ("windows-endpoint", r"windows (7|8|10|11|xp|vista)|\bwindows\b", None),
    ("unix-endpoint", r"\b(macos|mac os x|os x|darwin)\b", None),
    ("unix-server", r"\b(linux|ubuntu|debian|centos|red ?hat|rhel|fedora|suse|sles|oracle linux|amazon linux|rocky|alma|aix|solaris|hp-ux|freebsd|openbsd|netbsd|unix)\b", "unix-server"),
    ("certificate", r"\b(ssl|tls) certificate|certificate (expir|chain|signed|cannot be trusted)|self-signed", None),
]
_COMPILED = [(t, re.compile(rx, re.I), dom) for t, rx, dom in _RULES]


def classify(os_name="", host="", title=""):
    """Returns (asset_type, remediation_domain). `unknown` / None when nothing matches."""
    haystack = f"{os_name or ''} {host or ''} {title or ''}"
    for asset_type, rx, domain in _COMPILED:
        if rx.search(haystack):
            return asset_type, domain
    return "unknown", None
