#!/usr/bin/env python3
"""
Bulk real-CVE sample-data generator.

Sources REAL CVE records (genuine CVE IDs, CVSS scores, vendor/NVD descriptions) from
NVD's public CVE API (services.nvd.nist.gov - no API key needed at this query volume)
for each infrastructure/application sub-category the dashboard tracks, and emits
additional Tenable-CSV-style / Armis-JSON-style rows carrying that real data against
fictional-but-realistic demo assets (hostnames like WIN-SRV-0042 - see README's
"this is demo data" disclosure, same convention as the original hand-authored
sample-data rows).

This is NOT a live vulnerability scanner - it does not scan real infrastructure. It is
a data-generation tool that lets the demo's sample data reflect genuinely real,
historically-published CVEs at a scale (hundreds per category) that would be
impractical to hand-author, while keeping the actual vulnerability data (CVE ID, CVSS,
description) honest and traceable to a real source instead of invented.

DAST-category rows are the one deliberate exception: dynamic/runtime web-app findings
are usually not CVE-numbered at all (a reflected-XSS bug in your own app has no CVE -
that's normal for DAST tooling, see scan_type_mapping.py's docstring), so those rows
carry a real, well-established CWE/OWASP vulnerability class with no `cve` field,
exactly like this repo's own SAST findings already do for the same reason.

Usage:
    python remediation/sample-data/generate_bulk_findings.py [--category NAME ...]

Writes:
    remediation/sample-data/bulk/tenable_bulk_<category>.csv
    remediation/sample-data/bulk/armis_bulk_ot.json

Rate-limited to NVD's public (no-API-key) budget of 5 requests / 30s. Caches every raw
NVD response under remediation/sample-data/bulk/_nvd_cache/ so re-running (e.g. to
tune asset-name generation) doesn't re-hit the API for queries already fetched.
"""
import argparse
import csv
import datetime
import hashlib
import io
import json
import random
import time
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BULK_DIR = Path(__file__).resolve().parent / "bulk"
CACHE_DIR = BULK_DIR / "_nvd_cache"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_SLEEP_SECONDS = 6.5  # keeps us under NVD's public 5-req/30s budget with margin

TARGET_PER_CATEGORY = 300
TODAY = datetime.date.today()

random.seed(20260804)  # deterministic asset-name/date assignment across re-runs


def _cache_path(keyword):
    key = hashlib.sha1(keyword.encode("utf-8")).hexdigest()[:16]
    return CACHE_DIR / f"{key}.json"


def fetch_nvd(keyword, results_per_page=2000):
    """Returns the raw NVD 'vulnerabilities' list for one keyword search, using a
    local cache so repeated runs don't re-fetch the same query."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = _cache_path(keyword)
    if cache_file.exists():
        return json.loads(cache_file.read_text(encoding="utf-8"))

    resp = requests.get(
        NVD_URL, params={"keywordSearch": keyword, "resultsPerPage": results_per_page}, timeout=60
    )
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    cache_file.write_text(json.dumps(vulns), encoding="utf-8")
    time.sleep(REQUEST_SLEEP_SECONDS)
    return vulns


def best_cvss(cve):
    """Prefers CVSS v3.1, then v3.0, then v2 - returns (score, severity) or (None, None)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return data["baseScore"], entries[0].get("baseSeverity", _severity_from_score(data["baseScore"]))
    entries = metrics.get("cvssMetricV2")
    if entries:
        score = entries[0]["cvssData"]["baseScore"]
        return score, _severity_from_score(score)
    return None, None


def _severity_from_score(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def english_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return ""


def cwe_of(cve):
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en" and d["value"].startswith("CWE-"):
                return d["value"]
    return None


def _valid_cve_dict(entry, keyword, seen_global):
    cve = entry["cve"]
    cve_id = cve["id"]
    if cve_id in seen_global:
        return None
    desc = english_description(cve)
    score, severity = best_cvss(cve)
    if not desc or score is None:
        return None
    return {
        "cve_id": cve_id,
        "description": desc,
        "score": score,
        "severity": severity.capitalize(),
        "cwe": cwe_of(cve),
        "published": cve.get("published", "")[:10],
        # Which query actually retrieved this CVE - lets _os_for() assign the
        # OS/product label from the known-correct source query instead of
        # re-guessing from the CVE's own description text (see that function's
        # docstring for the real bug this fixes).
        "source_query": keyword,
    }


def collect_real_cves(queries, target, seen_global):
    """Collects distinct, well-formed real CVEs (must have an English description and
    a resolvable CVSS score) not already used elsewhere in this dataset, until `target`
    is reached or every query is exhausted.

    Two passes, both over the same queries, so multi-product categories (e.g.
    "OS Applications", whose 26 queries each name one specific product) actually end
    up with a mix of all of them instead of collapsing onto whichever single query
    happens to have the most real CVEs. Real bug this fixes: the original one-pass
    version pulled from each query in order until `target` was hit *at all* - since a
    ubiquitous product like "Google Chrome" alone has far more real CVEs than the
    whole category's target, every one of that category's ~1,100 findings ended up
    from that one query (and thus one OS/product label), even though the other 25
    products' queries were never touched. See CHANGELOG.md.

    Pass 1 caps each query at `ceil(target / len(queries))` so every query
    contributes something (when it has enough real results to). Pass 2 (only runs if
    pass 1 fell short of `target`, e.g. some queries had fewer real results than their
    quota) fills the remainder from any query with results left, uncapped - still real
    CVEs, just no longer quota-limited. fetch_nvd() caches each keyword's raw response
    to disk, so pass 2 re-querying the same keywords is a local cache hit, not a
    second live NVD call."""
    collected = []
    per_query_quota = max(1, -(-target // len(queries)))  # ceil(target / len(queries))

    for keyword in queries:
        if len(collected) >= target:
            break
        taken_this_query = 0
        for entry in fetch_nvd(keyword):
            if len(collected) >= target or taken_this_query >= per_query_quota:
                break
            row = _valid_cve_dict(entry, keyword, seen_global)
            if row is None:
                continue
            seen_global.add(row["cve_id"])
            collected.append(row)
            taken_this_query += 1

    if len(collected) < target:
        for keyword in queries:
            if len(collected) >= target:
                break
            for entry in fetch_nvd(keyword):
                if len(collected) >= target:
                    break
                row = _valid_cve_dict(entry, keyword, seen_global)
                if row is None:
                    continue
                seen_global.add(row["cve_id"])
                collected.append(row)

    return collected


def random_recent_date(days_back_max=60):
    days_back = random.randint(1, days_back_max)
    return (TODAY - datetime.timedelta(days=days_back)).isoformat()


def ip_stream(base_octet3):
    """Yields 10.20.<base_octet3+n//254>.<1+n%254> - rolls into the next /24 rather
    than ever emitting an invalid >255 octet."""
    n = 0
    while True:
        octet3 = base_octet3 + (n // 254)
        octet4 = 1 + (n % 254)
        yield f"10.20.{octet3}.{octet4}"
        n += 1


# ---------------------------------------------------------------------------
# Category definitions - NVD keyword queries per category, each mapped by file name
# alone in remediation/sample-data/bulk_normalize.py's classifier (see that module's
# docstring for why: since these files are generated with full knowledge of their own
# category, there is no ambiguity to infer downstream, unlike a real third-party
# Tenable/Armis export where asset.type has to be guessed from free text).
# ---------------------------------------------------------------------------

TENABLE_CATEGORIES = {
    "os_windows": {
        "queries": ["Microsoft Windows Server", "Windows Server 2019", "Windows Server 2022",
                    "Microsoft Exchange Server", "Active Directory", "Microsoft SQL Server",
                    "Windows Server 2016", "Windows Server 2012"],
        "target": 660,
        "os_choices": ["Microsoft Windows Server 2016 Standard", "Microsoft Windows Server 2019 Datacenter",
                       "Microsoft Windows Server 2022 Standard", "Microsoft Windows Server 2012 R2"],
        "vendor_hints": [("exchange", "Microsoft Windows Server 2019 Datacenter (Exchange Server)"),
                          ("active directory", "Microsoft Windows Server 2019 Datacenter (Domain Controller)"),
                          ("2022", "Microsoft Windows Server 2022 Standard"),
                          ("2019", "Microsoft Windows Server 2019 Datacenter"),
                          ("2016", "Microsoft Windows Server 2016 Standard")],
        "host_prefix": "WIN-SRV", "ip_base": 100, "port_choices": [445, 443, 3389, 0],
    },
    "os_linux": {
        "queries": ["Linux kernel", "Ubuntu", "Red Hat Enterprise Linux", "OpenSSH", "sudo",
                    "Debian", "CentOS", "systemd", "glibc"],
        "target": 440,
        "os_choices": ["Ubuntu Linux 20.04", "Ubuntu Linux 22.04", "Red Hat Enterprise Linux 8",
                       "Red Hat Enterprise Linux 9", "CentOS Linux 7", "Debian Linux 11"],
        "vendor_hints": [("ubuntu", "Ubuntu Linux 22.04"), ("red hat", "Red Hat Enterprise Linux 9"),
                          ("rhel", "Red Hat Enterprise Linux 9"), ("centos", "CentOS Linux 7"),
                          ("debian", "Debian Linux 11")],
        "host_prefix": "LNX-SRV", "ip_base": 101, "port_choices": [22, 443, 80, 0],
    },
    "network": {
        "queries": ["Cisco IOS", "Cisco IOS XE", "Cisco NX-OS", "Juniper Junos", "Arista EOS",
                    "Cisco Catalyst", "HPE Aruba switch", "Extreme Networks", "Cisco SD-WAN",
                    "Juniper EX switch"],
        "target": 1100,
        "os_choices": ["Cisco IOS XE 17.x", "Cisco IOS 15.x", "Cisco NX-OS 9.x", "Juniper Junos 21.x",
                       "Arista EOS 4.x"],
        "vendor_hints": [("ios xe", "Cisco IOS XE 17.x"), ("nx-os", "Cisco NX-OS 9.x"),
                          ("ios", "Cisco IOS 15.x"), ("junos", "Juniper Junos 21.x"),
                          ("arista", "Arista EOS 4.x")],
        "host_prefix": "NET-RTSW", "ip_base": 102, "port_choices": [443, 22, 23, 0],
    },
    "network_security": {
        "queries": ["Fortinet FortiOS", "Palo Alto Networks PAN-OS", "Check Point", "Juniper SRX",
                    "F5 BIG-IP", "SonicWall", "Citrix NetScaler", "WatchGuard Firebox",
                    "Barracuda firewall", "Sophos firewall", "Cisco ASA", "pfSense"],
        "target": 1100,
        "os_choices": ["Fortinet FortiOS 7.x", "Palo Alto Networks PAN-OS 10.x", "Check Point GAIA R80.x",
                       "Juniper Junos SRX", "F5 BIG-IP 15.x", "SonicWall SonicOS 7.x",
                       "Citrix ADC/NetScaler 13.x", "WatchGuard Fireware", "Barracuda CloudGen Firewall",
                       "Sophos XG Firewall", "Cisco ASA", "pfSense (Netgate)"],
        "vendor_hints": [("fortinet", "Fortinet FortiOS 7.x"), ("fortios", "Fortinet FortiOS 7.x"),
                          ("fortigate", "Fortinet FortiOS 7.x"), ("palo alto", "Palo Alto Networks PAN-OS 10.x"),
                          ("pan-os", "Palo Alto Networks PAN-OS 10.x"), ("check point", "Check Point GAIA R80.x"),
                          ("srx", "Juniper Junos SRX"), ("big-ip", "F5 BIG-IP 15.x"), ("f5", "F5 BIG-IP 15.x"),
                          ("sonicwall", "SonicWall SonicOS 7.x"), ("netscaler", "Citrix ADC/NetScaler 13.x"),
                          ("citrix", "Citrix ADC/NetScaler 13.x"), ("watchguard", "WatchGuard Fireware"),
                          ("barracuda", "Barracuda CloudGen Firewall"), ("sophos", "Sophos XG Firewall"),
                          ("cisco asa", "Cisco ASA"), ("pfsense", "pfSense (Netgate)")],
        "host_prefix": "FW-EDGE", "ip_base": 103, "port_choices": [443, 4443, 0],
    },
    "cloud": {
        # Original 14 queries are container/K8s-heavy in practice (NVD keywordSearch
        # returns far more real hits for "Kubernetes"/"Docker" than for broad umbrella
        # terms like "Amazon Web Services") - the 15 queries below name specific real
        # AWS/Azure/GCP services and tooling instead, so this category's real CVE mix
        # actually includes provider-specific findings, not just container-runtime ones.
        # See CHANGELOG.md - Round 13.
        "queries": ["Kubernetes", "Docker", "Amazon Web Services", "Microsoft Azure",
                    "Google Cloud Platform", "Terraform", "container escape", "Helm chart",
                    "container registry", "OpenShift", "Istio", "Envoy proxy", "HashiCorp Vault",
                    "HashiCorp Consul",
                    "Amazon S3", "AWS Lambda", "AWS Identity and Access Management",
                    "Amazon RDS", "AWS CloudFormation", "aws-cli", "Amazon Elastic Container Registry",
                    "AWS Systems Manager", "Azure Active Directory", "Azure Storage",
                    "Azure DevOps", "Azure CLI", "Google Cloud Storage", "Google Cloud SDK",
                    "gcloud"],
        "target": 1400,
        "os_choices": ["Kubernetes 1.2x (self-managed cluster node)", "Docker Engine 24.x",
                       "Amazon EKS worker node (Amazon Linux 2)", "Azure Kubernetes Service node",
                       "Google Kubernetes Engine node", "Terraform-provisioned cloud resource",
                       "AWS-managed cloud resource", "Azure-managed cloud resource",
                       "GCP-managed cloud resource"],
        "vendor_hints": [
            # Specific AWS/Azure/GCP service queries checked first (first match wins in
            # _os_for) so they get their own real label instead of falling through to
            # the generic "amazon"/"azure"/"google cloud" EKS/AKS/GKE hints below.
            ("amazon s3", "AWS-managed cloud resource (Amazon S3)"),
            ("aws lambda", "AWS-managed cloud resource (AWS Lambda)"),
            ("aws identity and access management", "AWS-managed cloud resource (AWS IAM)"),
            ("amazon rds", "AWS-managed cloud resource (Amazon RDS)"),
            ("aws cloudformation", "AWS-managed cloud resource (AWS CloudFormation)"),
            ("aws-cli", "AWS-managed cloud resource (AWS CLI)"),
            ("amazon elastic container registry", "AWS-managed cloud resource (Amazon ECR)"),
            ("aws systems manager", "AWS-managed cloud resource (AWS Systems Manager)"),
            ("azure active directory", "Azure-managed cloud resource (Azure Active Directory)"),
            ("azure storage", "Azure-managed cloud resource (Azure Storage)"),
            ("azure devops", "Azure-managed cloud resource (Azure DevOps)"),
            ("azure cli", "Azure-managed cloud resource (Azure CLI)"),
            ("google cloud storage", "GCP-managed cloud resource (Google Cloud Storage)"),
            ("google cloud sdk", "GCP-managed cloud resource (Google Cloud SDK)"),
            ("gcloud", "GCP-managed cloud resource (gcloud CLI)"),
            ("kubernetes", "Kubernetes 1.2x (self-managed cluster node)"),
            ("docker", "Docker Engine 24.x"), ("amazon", "Amazon EKS worker node (Amazon Linux 2)"),
            ("aws", "Amazon EKS worker node (Amazon Linux 2)"),
            ("azure", "Azure Kubernetes Service node"),
            ("google cloud", "Google Kubernetes Engine node"),
            ("terraform", "Terraform-provisioned cloud resource"),
        ],
        "host_prefix": "CLOUD", "ip_base": 104, "port_choices": [443, 6443, 2375, 0],
    },
    "certificate": {
        "queries": ["OpenSSL", "TLS protocol", "SSL certificate", "GnuTLS", "X.509 certificate"],
        "target": 300,
        "os_choices": ["Ubuntu Linux 22.04 (OpenSSL)", "Red Hat Enterprise Linux 9 (OpenSSL)",
                       "Windows Server 2022 (Schannel/CryptoAPI)"],
        "vendor_hints": [("gnutls", "Ubuntu Linux 22.04 (GnuTLS)"), ("openssl", "Ubuntu Linux 22.04 (OpenSSL)"),
                          ("windows", "Windows Server 2022 (Schannel/CryptoAPI)")],
        "host_prefix": "WEB-PORTAL", "ip_base": 105, "port_choices": [443, 8443, 636],
    },
    "sca": {
        "queries": ["Apache Log4j", "Apache Struts", "Spring Framework", "jQuery", "Lodash",
                    "Jackson Databind", "SnakeYAML", "Node.js", "Django", "Flask", "Express.js",
                    "Bootstrap", "Apache Commons"],
        "target": 300,
        "os_choices": ["Ubuntu Linux 22.04", "Red Hat Enterprise Linux 9", "Amazon Linux 2"],
        "vendor_hints": [],
        "host_prefix": "APP", "ip_base": 106, "port_choices": [8443, 8080, 443],
    },
    "os_apps": {
        # Client/desktop software running ON an endpoint's OS - a different remediation
        # reality from server-OS patching (WSUS/yum) or SCA (a bundled library in code
        # you wrote): these get fixed by the end user/IT applying an app-level update
        # or auto-updater, not a server patch cycle. Real, extremely common desktop
        # software with genuine, well-documented CVE history.
        "queries": ["Google Chrome", "Mozilla Firefox", "Microsoft Edge", "Adobe Acrobat Reader",
                    "Foxit Reader", "Visual Studio Code", "Git for Windows", "Docker Desktop",
                    "VLC media player", "Adobe Photoshop", "7-Zip", "WinRAR", "Notepad++",
                    "PuTTY", "FileZilla", "Zoom", "Slack desktop client", "TeamViewer",
                    "Adobe Photoshop CC", "OBS Studio", "Audacity", "GIMP", "LibreOffice",
                    "Skype", "Discord", "Dropbox client", "NVIDIA graphics driver"],
        "target": 1100,
        "os_choices": ["Windows 11 (client workstation)", "Windows 10 (client workstation)",
                       "macOS (client workstation)"],
        "vendor_hints": [("chrome", "Windows 11 (client workstation) - Google Chrome"),
                          ("firefox", "Windows 11 (client workstation) - Mozilla Firefox"),
                          ("edge", "Windows 11 (client workstation) - Microsoft Edge"),
                          ("acrobat", "Windows 10 (client workstation) - Adobe Acrobat/Reader"),
                          ("reader", "Windows 10 (client workstation) - Adobe Acrobat/Reader"),
                          ("foxit", "Windows 10 (client workstation) - Foxit Reader"),
                          ("visual studio code", "Windows 11 (client workstation) - Visual Studio Code"),
                          ("git", "Windows 11 (client workstation) - Git for Windows"),
                          ("docker desktop", "Windows 11 (client workstation) - Docker Desktop"),
                          ("vlc", "Windows 10 (client workstation) - VLC media player"),
                          ("photoshop", "Windows 10 (client workstation) - Adobe Photoshop"),
                          ("7-zip", "Windows 10 (client workstation) - 7-Zip"),
                          ("winrar", "Windows 10 (client workstation) - WinRAR"),
                          ("notepad++", "Windows 10 (client workstation) - Notepad++"),
                          ("putty", "Windows 10 (client workstation) - PuTTY"),
                          ("filezilla", "Windows 10 (client workstation) - FileZilla"),
                          ("zoom", "Windows 11 (client workstation) - Zoom"),
                          ("slack", "Windows 11 (client workstation) - Slack desktop"),
                          ("teamviewer", "Windows 10 (client workstation) - TeamViewer"),
                          ("obs studio", "Windows 10 (client workstation) - OBS Studio"),
                          ("audacity", "Windows 10 (client workstation) - Audacity"),
                          ("gimp", "Windows 10 (client workstation) - GIMP"),
                          ("libreoffice", "Windows 10 (client workstation) - LibreOffice"),
                          ("skype", "Windows 10 (client workstation) - Skype"),
                          ("discord", "Windows 11 (client workstation) - Discord"),
                          ("dropbox", "Windows 10 (client workstation) - Dropbox client"),
                          ("nvidia", "Windows 11 (client workstation) - NVIDIA graphics driver")],
        "host_prefix": "WKS", "ip_base": 108, "port_choices": [0],
    },
    # GitHub/GitLab repository vulnerabilities, CVE-bearing half (Dependabot-style
    # alerts) - a normal NVD-CVE-based category like every other TENABLE_CATEGORIES
    # entry above, sharing collect_real_cves() unmodified. Queries deliberately do NOT
    # overlap "sca"'s query list above (Log4j/Struts/Spring/jQuery/Lodash/Jackson/
    # SnakeYAML/Node.js/Django/Flask/Express/Bootstrap/Commons) - an overlapping query
    # would silently lose real CVEs to bulk_normalize.py's cross-run stable-ID dedup,
    # since a fresh generator run has its own empty seen_global and would happily
    # re-collect a CVE another category already claimed, only to have it dropped
    # (already in existing_keys) at merge time with no visible error.
    "code_repository": {
        "queries": ["PyYAML", "urllib3", "axios", "Handlebars.js", "Moment.js",
                    "Newtonsoft.Json", "Underscore.js", "Minimist", "node-fetch",
                    "Guava", "Apache Velocity", "AngularJS"],
        "target": 110,
        "os_choices": ["GitHub Repository - Python (pip)", "GitHub Repository - JavaScript (npm)",
                       "GitHub Repository - Java (Maven)", "GitHub Repository - .NET (NuGet)"],
        "vendor_hints": [("pyyaml", "GitHub Repository - Python (pip: PyYAML)"),
                          ("urllib3", "GitHub Repository - Python (pip: urllib3)"),
                          ("axios", "GitHub Repository - JavaScript (npm: axios)"),
                          ("handlebars", "GitHub Repository - JavaScript (npm: Handlebars.js)"),
                          ("moment", "GitHub Repository - JavaScript (npm: Moment.js)"),
                          ("newtonsoft", "GitHub Repository - .NET (NuGet: Newtonsoft.Json)"),
                          ("underscore", "GitHub Repository - JavaScript (npm: Underscore.js)"),
                          ("minimist", "GitHub Repository - JavaScript (npm: Minimist)"),
                          ("node-fetch", "GitHub Repository - JavaScript (npm: node-fetch)"),
                          ("guava", "GitHub Repository - Java (Maven: Guava)"),
                          ("velocity", "GitHub Repository - Java (Maven: Apache Velocity)"),
                          ("angularjs", "GitHub Repository - JavaScript (npm: AngularJS)")],
        "host_prefix": "REPO", "ip_base": 111, "port_choices": [443, 0],
    },
    # End-user Windows laptops/desktops - a genuinely different remediation reality
    # from windows-server (patched by SCCM/Microsoft Configuration Manager on an
    # endpoint-management cycle, not WSUS/Ansible server patching). See
    # bulk_normalize.py's _REMEDIATION_MECHANISM for the honest "informational only,
    # no working SCCM integration" disclosure this category carries.
    "endpoint_windows": {
        "queries": ["Windows 10", "Windows 11", "Microsoft Windows 10", "Microsoft Windows 11"],
        "target": 300,
        "os_choices": ["Windows 11 Enterprise (SCCM-managed)", "Windows 10 Enterprise (SCCM-managed)",
                       "Windows 11 Pro (SCCM-managed)", "Windows 10 Pro (SCCM-managed)"],
        "vendor_hints": [("windows 11", "Windows 11 Enterprise (SCCM-managed)"),
                          ("windows 10", "Windows 10 Enterprise (SCCM-managed)")],
        "host_prefix": "ENDPT-WIN", "ip_base": 112, "port_choices": [0],
    },
    # Phones/tablets - patched via an MDM platform (e.g. Microsoft Intune), a real,
    # distinct mechanism from SCCM's own primarily-Windows-desktop focus, even where
    # the two co-manage devices in a hybrid Microsoft Endpoint Manager deployment.
    "endpoint_mobile": {
        "queries": ["Android", "Apple iOS", "Samsung Android", "Google Pixel Android"],
        "target": 200,
        "os_choices": ["Android 14 (MDM-managed)", "Android 13 (MDM-managed)",
                       "iOS 17 (MDM-managed)", "iOS 16 (MDM-managed)"],
        "vendor_hints": [("android", "Android 14 (MDM-managed)"),
                          ("ios", "iOS 17 (MDM-managed)"), ("apple", "iOS 17 (MDM-managed)")],
        "host_prefix": "MOBILE", "ip_base": 113, "port_choices": [0],
    },
    # Networked printers/MFPs - real, well-documented vendor firmware CVE histories
    # (HP LaserJet, Xerox, Canon, Lexmark, Ricoh all have public CVEs). Port choices
    # are real, common printer service ports: 9100 (raw/JetDirect printing),
    # 631 (IPP), 80/443 (web admin console).
    "printer": {
        "queries": ["HP LaserJet", "Xerox printer", "Canon printer firmware", "Lexmark printer",
                    "Ricoh printer", "Konica Minolta printer", "Brother printer"],
        "target": 250,
        "os_choices": ["HP LaserJet Firmware", "Xerox WorkCentre Firmware", "Canon imageRUNNER Firmware",
                       "Lexmark Printer Firmware", "Ricoh Printer Firmware", "Brother Printer Firmware"],
        "vendor_hints": [("hp ", "HP LaserJet Firmware"), ("laserjet", "HP LaserJet Firmware"),
                          ("xerox", "Xerox WorkCentre Firmware"), ("canon", "Canon imageRUNNER Firmware"),
                          ("lexmark", "Lexmark Printer Firmware"), ("ricoh", "Ricoh Printer Firmware"),
                          ("konica", "Ricoh Printer Firmware"), ("brother", "Brother Printer Firmware")],
        "host_prefix": "PRINTER", "ip_base": 114, "port_choices": [9100, 631, 443, 80, 0],
    },
    # Hypervisor/VM-platform CVEs - VMware ESXi/vCenter, Microsoft Hyper-V, Proxmox VE,
    # and Citrix Hypervisor all have real, well-documented CVE histories (several
    # critical VMware ESXi/vCenter CVEs have been actively exploited in the wild).
    # Ports are real, common hypervisor management ports: 443 (ESXi/vCenter web),
    # 902 (ESXi host management), 8006 (Proxmox VE web UI).
    "virtualization": {
        "queries": ["VMware ESXi", "VMware vCenter", "Microsoft Hyper-V", "Proxmox VE",
                    "Citrix Hypervisor", "KVM QEMU", "Nutanix AHV"],
        "target": 300,
        "os_choices": ["VMware ESXi 8.x", "VMware vCenter Server 8.x",
                       "Microsoft Hyper-V (Windows Server 2022)", "Proxmox VE 8.x", "Citrix Hypervisor 8.x",
                       "Linux KVM/QEMU Hypervisor", "Nutanix AHV Hypervisor"],
        "vendor_hints": [("esxi", "VMware ESXi 8.x"), ("vcenter", "VMware vCenter Server 8.x"),
                          ("vmware", "VMware ESXi 8.x"), ("hyper-v", "Microsoft Hyper-V (Windows Server 2022)"),
                          ("proxmox", "Proxmox VE 8.x"), ("citrix hypervisor", "Citrix Hypervisor 8.x"),
                          ("kvm", "Linux KVM/QEMU Hypervisor"), ("qemu", "Linux KVM/QEMU Hypervisor"),
                          ("nutanix", "Nutanix AHV Hypervisor")],
        "host_prefix": "VHOST", "ip_base": 115, "port_choices": [443, 902, 8006, 0],
    },
}

ARMIS_CATEGORY = {
    "queries": ["SCADA", "industrial control system", "IoT device", "building automation",
                "IP camera", "embedded device", "Siemens SIMATIC", "programmable logic controller",
                "Schneider Electric", "Rockwell Automation", "network attached storage",
                "digital video recorder", "access control system", "smart home", "router firmware",
                "printer firmware", "medical device", "Modbus", "BACnet protocol", "network switch firmware"],
    "target": 1100,
}

DEVICE_TYPES_BY_KEYWORD_HINT = [
    ("camera", "IP Camera"), ("scada", "SCADA HMI"), ("industrial", "Industrial Sensor Gateway"),
    ("programmable logic", "Programmable Logic Controller"), ("building", "Building Automation Controller"),
    ("siemens", "Industrial PLC (Siemens SIMATIC family)"), ("schneider", "Industrial PLC (Schneider Electric family)"),
    ("rockwell", "Industrial PLC (Rockwell Automation family)"), ("nas", "Network Attached Storage"),
    ("network-attached storage", "Network Attached Storage"), ("dvr", "Digital Video Recorder"),
    ("video recorder", "Digital Video Recorder"), ("access control", "Access Control System"),
    ("router", "Consumer/SOHO Router"), ("printer", "Network Printer"),
    ("medical", "Networked Medical Device"), ("modbus", "Industrial Protocol Gateway (Modbus)"),
    ("bacnet", "Building Automation Controller (BACnet)"),
]
DEFAULT_DEVICE_TYPE = "Embedded/IoT Device"

# Real, well-established CWE/OWASP vulnerability classes for DAST - these are
# deliberately not CVE-numbered (see module docstring): a runtime finding against your
# own web app doesn't get a public CVE, same reasoning /vulnhunt's own SAST findings
# already document for their CWE-based categorization.
DAST_CLASSES = [
    ("CWE-79", "Reflected Cross-Site Scripting (XSS)",
     "User-controlled input from a query parameter is reflected into the HTML response without output encoding, allowing arbitrary script execution in a victim's browser.",
     "Apply context-aware output encoding at every reflection point and adopt a strict Content-Security-Policy as defense in depth."),
    ("CWE-79", "Stored Cross-Site Scripting (XSS)",
     "User-submitted content is persisted and rendered to other users without sanitization, allowing a stored payload to execute in any visitor's session.",
     "Sanitize/encode user content on output (not just input) and use a CSP that blocks inline script execution."),
    ("CWE-89", "SQL Injection (blind, boolean-based)",
     "A boolean-based blind SQL injection was confirmed by observing differing application responses to true/false injected conditions in a request parameter.",
     "Use parameterized queries/prepared statements exclusively; never build SQL via string concatenation with request input."),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)",
     "A state-changing request has no anti-CSRF token and is accepted with only a session cookie, allowing a forged cross-site request to perform the action on a victim's behalf.",
     "Require a per-session anti-CSRF token on all state-changing requests and set the session cookie's SameSite attribute to Strict or Lax."),
    ("CWE-611", "XML External Entity (XXE) Injection",
     "The XML parser resolves external entities in user-supplied XML, allowing local file disclosure or SSRF via a crafted DOCTYPE declaration.",
     "Disable external entity resolution and DTD processing in the XML parser configuration."),
    ("CWE-918", "Server-Side Request Forgery (SSRF)",
     "A server-side fetch of a user-supplied URL is not restricted to an allowlist, allowing requests to internal-only services and cloud metadata endpoints.",
     "Validate/allowlist destination hosts for any server-initiated fetch, and block requests to link-local/metadata address ranges."),
    ("CWE-601", "Open Redirect",
     "A redirect parameter accepts an arbitrary external URL without validation, enabling phishing links that appear to originate from a trusted domain.",
     "Validate redirect targets against an allowlist of relative paths or known internal hosts only."),
    ("CWE-639", "Insecure Direct Object Reference (IDOR)",
     "An object identifier in the URL/request body is used to fetch a resource with no ownership check, allowing access to another user's data by changing the ID.",
     "Enforce object-level authorization checks server-side on every request, not just at the UI layer."),
    ("CWE-209", "Verbose Error Message Discloses Stack Trace",
     "An unhandled exception returns a full stack trace and internal file paths to the client, disclosing implementation details useful for further attack.",
     "Return generic error responses to clients and log detailed stack traces server-side only."),
    ("CWE-614", "Session Cookie Missing 'Secure' Attribute",
     "The session cookie is not marked Secure, allowing it to be transmitted over an unencrypted HTTP connection if one is ever made.",
     "Set the Secure attribute on all session/authentication cookies."),
    ("CWE-1004", "Session Cookie Missing 'HttpOnly' Attribute",
     "The session cookie is accessible to client-side JavaScript, making it a direct target for theft via any XSS on the same origin.",
     "Set the HttpOnly attribute on all session/authentication cookies."),
    ("CWE-693", "Missing HTTP Security Headers",
     "The application does not send X-Frame-Options/Content-Security-Policy headers, leaving it vulnerable to clickjacking and reducing defense-in-depth against XSS.",
     "Add X-Frame-Options: DENY (or CSP frame-ancestors), X-Content-Type-Options: nosniff, and a baseline Content-Security-Policy."),
    ("CWE-798", "Hardcoded API Key in Client-Side JavaScript",
     "A third-party API key is embedded directly in a client-side JavaScript bundle, visible to anyone who views the page source.",
     "Move the API call behind a server-side proxy that holds the credential, or use a public/restricted key scoped for client-side use."),
    ("CWE-521", "Weak Password Policy Allows Trivial Brute Force",
     "The login form accepts short, low-complexity passwords with no rate limiting, making credential-stuffing/brute-force attacks practical.",
     "Enforce a minimum password complexity policy and add rate limiting/account lockout after repeated failed attempts."),
    ("CWE-307", "Missing Rate Limiting on Authentication Endpoint",
     "The login endpoint accepts unlimited authentication attempts from a single source with no throttling or lockout.",
     "Add per-account and per-IP rate limiting with exponential backoff on the authentication endpoint."),
    ("CWE-434", "Unrestricted File Upload",
     "The file upload feature does not validate file type/content, allowing a script file to be uploaded and potentially executed by the web server.",
     "Validate uploaded file content (not just extension), store uploads outside the web root, and disable script execution in the upload directory."),
    ("CWE-522", "Credentials Transmitted Over Unencrypted HTTP Basic Auth",
     "An internal admin endpoint accepts HTTP Basic Authentication over a connection that is not enforced to be HTTPS.",
     "Enforce HTTPS (HSTS) site-wide and never accept Basic Authentication over plaintext HTTP."),
    ("CWE-200", "Directory Listing Enabled",
     "Directory browsing is enabled on a web-accessible path, exposing the full file listing of an application or asset directory.",
     "Disable directory listing in the web server configuration for all web-accessible paths."),
    ("CWE-444", "HTTP Request Smuggling",
     "Inconsistent parsing of Content-Length/Transfer-Encoding headers between the front-end proxy and back-end server allows request smuggling.",
     "Normalize on a single, RFC-compliant request-framing mechanism across the whole proxy chain, or disable HTTP/1.1 keep-alive to the back end."),
    ("CWE-290", "JWT Signature Verification Bypass ('alg: none')",
     "The JWT verification library accepts tokens with `alg: none`, allowing an attacker to forge a token with arbitrary claims and no valid signature.",
     "Explicitly allowlist accepted JWT signing algorithms server-side and reject any token using 'none'."),
]

WEBAPP_HOSTS = [
    "customer-portal", "order-service", "billing-api", "employee-hr-portal", "partner-extranet",
    "support-ticketing", "marketing-cms", "internal-wiki", "vendor-onboarding", "loyalty-rewards",
    "mobile-backend-api", "search-service", "notification-service", "reporting-dashboard", "checkout-service",
]

TENABLE_HEADER = ["Plugin ID", "CVE", "Risk", "CVSS v3.0 Base Score", "Host", "IP Address", "FQDN",
                  "OS", "Name", "Synopsis", "Solution", "Port", "Protocol", "First Discovered", "Last Observed"]

def _stable_id(*parts):
    """Derives a deterministic 6-digit-ish numeric ID from the given parts (typically
    a CVE ID, or a CWE+host combo for CVE-less DAST findings) - NOT a per-process
    counter. This is what makes re-running the generator with a higher target (to add
    more real CVEs to a category already ingested) safe: an already-normalized CVE
    always regenerates the exact same "Plugin ID"/deviceId, so bulk_normalize.py's
    stable-ID dedup (matched by source + source_ref) correctly recognizes it as
    already-present instead of creating a duplicate finding under a new ID. A plain
    incrementing counter restarts at the same value every process invocation, which
    caused a real duplicate-finding bug the first time this script was run in more
    than one invocation - see CHANGELOG.md."""
    key = "|".join(str(p) for p in parts)
    return int(hashlib.sha1(key.encode("utf-8")).hexdigest()[:7], 16) % 900000 + 100000


def _truncate(text, max_len=400):
    text = " ".join(text.split())
    return text if len(text) <= max_len else text[:max_len - 1].rsplit(" ", 1)[0] + "…"


def _os_for(config, cve):
    """Picks the OS/product label for this CVE. Matches against the CVE's own
    `source_query` (which NVD query actually retrieved it) first - the query is a
    single, unambiguous product name, unlike the CVE's free-text description, which
    can legitimately name several other products in passing (e.g. an old Adobe
    Acrobat Reader browser-plugin CVE whose description also lists "Google Chrome,
    Mozilla Firefox, Internet Explorer" as affected browsers - matching against that
    description text picked whichever product name happened to appear first,
    mislabeling the finding). Falls back to matching the description (for any CVE
    without a source_query) and finally to a random in-category choice."""
    source_query = (cve.get("source_query") or "").lower()
    for keyword, label in config.get("vendor_hints", []):
        if keyword in source_query:
            return label
    text = (cve.get("description") or "").lower()
    for keyword, label in config.get("vendor_hints", []):
        if keyword in text:
            return label
    return random.choice(config["os_choices"])


def write_tenable_csv(category_key, cves, config):
    BULK_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BULK_DIR / f"tenable_bulk_{category_key}.csv"
    ips = ip_stream(config["ip_base"])
    rows = []
    for i, c in enumerate(cves, start=1):
        host = f"{config['host_prefix']}-{i:04d}"
        rows.append([
            _stable_id("tenable", c["cve_id"]),
            c["cve_id"],
            c["severity"],
            c["score"],
            host,
            next(ips),
            f"{host.lower()}.corp.deloitte.local",
            _os_for(config, c),
            _truncate(c["description"], 120),
            _truncate(c["description"]),
            f"See vendor advisory for {c['cve_id']} and apply the corresponding patch/update.",
            random.choice(config["port_choices"]),
            "tcp",
            random_recent_date(),
            random_recent_date(days_back_max=3),
        ])
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(TENABLE_HEADER)
        writer.writerows(rows)
    return out_path, len(rows)


def write_dast_csv():
    """DAST findings have no CVE - see module docstring. Combines each real CWE/OWASP
    class with many realistic fictional web-app hosts to reach the category target."""
    BULK_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BULK_DIR / "tenable_bulk_dast.csv"
    ips = ip_stream(107)
    rows = []
    combos = [(cls, host) for cls in DAST_CLASSES for host in WEBAPP_HOSTS]
    random.shuffle(combos)
    for (cwe_id, title, synopsis, solution), host_slug in combos[:300]:
        host = f"WEBAPP-{host_slug.upper()}"
        rows.append([
            _stable_id("dast", cwe_id, host_slug),
            "",  # no CVE - DAST findings are app-specific, not CVE-numbered
            _severity_for_dast_class(cwe_id),
            _cvss_estimate_for_dast_class(cwe_id),
            host,
            next(ips),
            f"{host_slug}.corp.deloitte.local",
            "Web Application (dynamic scan target)",
            f"{title} ({cwe_id})",
            synopsis,
            solution,
            443,
            "tcp",
            random_recent_date(),
            random_recent_date(days_back_max=3),
        ])
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(TENABLE_HEADER)
        writer.writerows(rows)
    return out_path, len(rows)


# Real-world severity is roughly how OWASP/CWE community references typically rate
# these classes (e.g. SSRF/SQLi/XXE are commonly Critical/High; missing-header-style
# findings are commonly Low) - not a fabricated score, but not tied to a specific CVE
# either, since none exists for an app-specific DAST finding.
_DAST_SEVERITY = {
    "CWE-89": ("Critical", 9.8), "CWE-918": ("Critical", 9.1), "CWE-611": ("High", 8.2),
    "CWE-434": ("High", 8.1), "CWE-290": ("High", 8.1), "CWE-79": ("High", 7.4),
    "CWE-639": ("High", 7.1), "CWE-444": ("Medium", 6.5), "CWE-522": ("Medium", 6.1),
    "CWE-352": ("Medium", 6.0), "CWE-798": ("Medium", 5.9), "CWE-601": ("Medium", 5.4),
    "CWE-307": ("Medium", 5.3), "CWE-521": ("Medium", 5.3), "CWE-209": ("Low", 3.7),
    "CWE-200": ("Low", 3.1), "CWE-1004": ("Low", 3.0), "CWE-614": ("Low", 2.6),
    "CWE-693": ("Low", 2.5),
}


def _severity_for_dast_class(cwe_id):
    return _DAST_SEVERITY.get(cwe_id, ("Medium", 5.0))[0]


def _cvss_estimate_for_dast_class(cwe_id):
    return _DAST_SEVERITY.get(cwe_id, ("Medium", 5.0))[1]


# Real, independently-verified Checkov IaC-scanner rule IDs (fetched directly from
# Checkov's own official policy index) - like DAST_CLASSES above, these are
# deliberately not CVE-numbered: a Terraform/CloudFormation misconfiguration is a
# static-analysis finding against a config template, not a versioned CVE-tracked
# component. Only rules independently confirmed against Checkov's own docs are
# included here; a couple of plausible-sounding additional rule IDs found only in
# secondary sources (e.g. S3-deny-public-write) were deliberately excluded rather than
# risk citing an inaccurate one - see CHANGELOG.md.
IAC_CLASSES = [
    ("CKV_AWS_20", "S3 Bucket Has an ACL Defined Which Allows Public READ Access",
     "The S3 bucket resource's ACL grants public-read access, allowing anyone on the internet to list and download every object in the bucket.",
     "Remove the public-read ACL grant and set the bucket's public-access-block configuration to block all public access."),
    ("CKV_AWS_1", "IAM Policy Allows Full '*:*' Administrative Privileges",
     "The IAM policy attached to this resource grants Action: '*' against Resource: '*', a full-administrator wildcard grant with no least-privilege scoping.",
     "Scope the policy to only the specific actions and resources this role/user genuinely needs, following least privilege."),
    ("CKV_AWS_3", "EBS Volume Is Not Encrypted",
     "The EBS volume resource does not have encryption enabled, leaving data at rest on the underlying storage unencrypted.",
     "Set encrypted = true on the EBS volume resource (and consider enabling account-level default EBS encryption)."),
    ("CKV_AWS_16", "RDS Instance Is Not Encrypted at Rest",
     "The RDS database instance resource does not have storage encryption enabled, leaving the database's data at rest unencrypted.",
     "Set storage_encrypted = true on the RDS instance (note: this requires recreating an existing unencrypted instance)."),
    ("CKV_AWS_67", "CloudTrail Is Not Enabled in All Regions",
     "The CloudTrail configuration does not have multi-region logging enabled, leaving API activity in other regions unlogged.",
     "Set is_multi_region_trail = true on the CloudTrail resource so API activity is captured account-wide."),
    ("CKV_AWS_24", "Security Group Allows Ingress From 0.0.0.0/0 to Port 22 (SSH)",
     "The security group resource has an ingress rule allowing SSH (port 22) from any source IP address (0.0.0.0/0).",
     "Restrict the SSH ingress rule's source CIDR to a specific known IP range (e.g. a VPN or bastion host), never 0.0.0.0/0."),
    ("CKV_AWS_25", "Security Group Allows Ingress From 0.0.0.0/0 to Port 3389 (RDP)",
     "The security group resource has an ingress rule allowing RDP (port 3389) from any source IP address (0.0.0.0/0).",
     "Restrict the RDP ingress rule's source CIDR to a specific known IP range, never 0.0.0.0/0."),
    ("CKV_AWS_277", "Security Group Allows Ingress From 0.0.0.0/0 to All Ports",
     "The security group resource has an ingress rule allowing all ports (0-65535) from any source IP address (0.0.0.0/0).",
     "Replace the all-ports rule with explicit, minimal port ranges scoped to a specific known source CIDR."),
]

_IAC_SEVERITY = {
    "CKV_AWS_20": ("Critical", 9.1), "CKV_AWS_1": ("Critical", 9.8), "CKV_AWS_277": ("Critical", 9.5),
    "CKV_AWS_16": ("High", 7.5), "CKV_AWS_24": ("High", 8.1), "CKV_AWS_25": ("High", 8.1),
    "CKV_AWS_3": ("Medium", 5.3), "CKV_AWS_67": ("Medium", 5.5),
}

IAC_RESOURCE_NAMES = [
    "prod-data-lake-s3", "billing-vpc-sg", "customer-orders-rds", "analytics-ebs-vol-01",
    "shared-services-iam-admin-policy", "audit-cloudtrail-org", "user-uploads-s3", "payments-rds-primary",
    "web-tier-sg-public", "batch-jobs-ebs-vol", "core-network-sg", "reporting-s3-bucket",
    "hr-documents-s3", "marketing-assets-s3", "staging-rds-instance", "internal-tools-sg",
    "vpn-gateway-sg", "backup-ebs-snapshot-vol", "logging-s3-bucket", "ml-training-s3",
    "cdn-origin-s3", "devops-terraform-state-s3", "legacy-app-rds", "partner-api-sg",
    "iot-telemetry-s3", "finance-reports-s3", "test-env-sg", "sandbox-rds-instance",
]


def write_iac_csv():
    """IaC misconfiguration findings have no CVE - each row is a Checkov rule match
    against a fictional Terraform/CloudFormation resource, same combinatorial pattern
    as write_dast_csv()."""
    BULK_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BULK_DIR / "tenable_bulk_iac.csv"
    ips = ip_stream(113)
    rows = []
    combos = [(cls, name) for cls in IAC_CLASSES for name in IAC_RESOURCE_NAMES]
    random.shuffle(combos)
    for (rule_id, title, synopsis, solution), resource_name in combos[:220]:
        host = f"IAC-{resource_name.upper()}"
        severity, cvss = _IAC_SEVERITY.get(rule_id, ("Medium", 5.0))
        rows.append([
            _stable_id("iac", rule_id, resource_name),
            "",  # no CVE - a static config-template finding, not a versioned component
            severity,
            cvss,
            host,
            next(ips),
            f"{resource_name}.terraform.corp.deloitte.local",
            "Terraform/CloudFormation Resource (IaC static analysis target)",
            f"{title} ({rule_id})",
            synopsis,
            solution,
            0,
            "tcp",
            random_recent_date(),
            random_recent_date(days_back_max=3),
        ])
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(TENABLE_HEADER)
        writer.writerows(rows)
    return out_path, len(rows)


# Real CWE-798 ("Use of Hard-coded Credentials") secret-scanning alert classes - the
# same CWE this file's own DAST_CLASSES and this project's unrelated code-scanner
# feature already use for a hardcoded-credential finding. Descriptions are
# DELIBERATELY generic and never embed a secret-shaped literal (a real AKIA-prefixed
# key pattern or a "-----BEGIN ... PRIVATE KEY-----" block): tests/test_pipeline_
# artifacts.py's NoRealSecretsLeakedAnywhere check fails unconditionally (no FAKE/DEMO
# escape hatch) on either pattern appearing in any tracked file.
SECRET_CLASSES = [
    ("CWE-798", "Hardcoded AWS Access Key Committed to Repository",
     "A GitHub/GitLab secret-scanning alert flagged an AWS access key ID pattern committed in plaintext to a repository file.",
     "Revoke and rotate the exposed access key immediately, purge it from git history, and move credential storage to a secrets manager."),
    ("CWE-798", "Hardcoded Private Key (PEM) Committed to Repository",
     "A secret-scanning alert flagged a PEM-encoded private key block committed in plaintext to a repository file.",
     "Revoke the exposed key pair, issue a new key, purge it from git history, and store private keys outside version control."),
    ("CWE-798", "Hardcoded Database Connection String With Embedded Credentials",
     "A connection string containing a plaintext username/password was committed to a configuration file in the repository.",
     "Rotate the exposed database credential and move connection strings to environment variables or a secrets manager."),
    ("CWE-798", "Hardcoded Third-Party API Token Committed to Repository",
     "A secret-scanning alert flagged a third-party service API token (matching a known vendor token format) committed in plaintext.",
     "Revoke the exposed token via the issuing vendor's dashboard and move it to a secrets manager."),
]

_SECRET_SEVERITY = {
    "Hardcoded AWS Access Key Committed to Repository": ("Critical", 9.1),
    "Hardcoded Private Key (PEM) Committed to Repository": ("Critical", 9.8),
    "Hardcoded Database Connection String With Embedded Credentials": ("High", 8.2),
    "Hardcoded Third-Party API Token Committed to Repository": ("High", 7.5),
}

REPO_NAMES = [
    "customer-portal-frontend", "order-service-backend", "billing-api", "internal-tools-cli",
    "data-pipeline-etl", "mobile-app-ios", "mobile-app-android", "infra-terraform-modules",
    "ml-model-training", "analytics-dashboard", "auth-service", "notification-service",
    "search-service", "payment-gateway-integration", "devops-scripts", "shared-ui-components",
    "api-gateway-config", "legacy-monolith", "microservice-template", "docs-site",
    "test-automation-suite", "chatbot-service", "recommendation-engine", "fraud-detection-service",
    "inventory-management", "hr-portal-backend", "marketing-site", "partner-integrations",
    "reporting-service", "sandbox-experiments",
]


def write_code_repository_secrets_csv():
    """Secret-scanning-style half of the GitHub/GitLab repository-vulnerabilities
    category - no CVE (see SECRET_CLASSES docstring above), same combinatorial pattern
    as write_dast_csv()/write_iac_csv()."""
    BULK_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BULK_DIR / "tenable_bulk_code_repository_secrets.csv"
    ips = ip_stream(112)
    rows = []
    combos = [(cls, name) for cls in SECRET_CLASSES for name in REPO_NAMES]
    random.shuffle(combos)
    for (cwe_id, title, synopsis, solution), repo_name in combos[:110]:
        host = f"REPO-{repo_name.upper()}"
        severity, cvss = _SECRET_SEVERITY.get(title, ("Medium", 5.0))
        rows.append([
            _stable_id("secrets", cwe_id, title, repo_name),
            "",  # no CVE - a repository secret-scanning alert, not a versioned component
            severity,
            cvss,
            host,
            next(ips),
            f"{repo_name}.github.corp.deloitte.local",
            "GitHub/GitLab Repository (secret-scanning target)",
            f"{title} ({cwe_id})",
            synopsis,
            solution,
            0,
            "tcp",
            random_recent_date(),
            random_recent_date(days_back_max=3),
        ])
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(TENABLE_HEADER)
        writer.writerows(rows)
    return out_path, len(rows)


# Real, independently-verified default Falco rule names (fetched directly from
# falcosecurity/rules' current falco_rules.yaml on GitHub) - runtime/container
# detections have no CVE, same reasoning as DAST/IaC above. A couple of
# plausible-sounding classic Falco rule names ("Launch Privileged Container", "Write
# below etc") could NOT be independently confirmed against the current ruleset and are
# deliberately excluded rather than risk citing an inaccurate one - see CHANGELOG.md.
RUNTIME_CLASSES = [
    ("Terminal shell in container",
     "A shell was spawned interactively inside a running container, a strong signal of live attacker access rather than an automated process.",
     "Investigate the container's process tree immediately; if unauthorized, isolate the workload and rotate any credentials it could access."),
    ("Contact K8S API Server From Container",
     "A container process made a direct network connection to the Kubernetes API server, which is unusual for most workloads and can indicate an attempt at cluster-wide privilege escalation.",
     "Restrict the workload's service account permissions and network policy so it cannot reach the API server unless genuinely required."),
    ("Debugfs Launched in Privileged Container",
     "The debugfs kernel debugging tool was launched inside a privileged container, providing a path to escape container isolation and access the host filesystem.",
     "Remove the privileged: true flag from the container spec and drop unnecessary Linux capabilities."),
    ("Detect release_agent File Container Escapes",
     "A write to the cgroup release_agent file was detected, a known technique for escaping container isolation to execute code on the host.",
     "Ensure containers do not run with CAP_SYS_ADMIN or privileged mode, and enforce a Pod Security Standard that blocks this technique."),
    ("Drop and execute new binary in container",
     "A new executable file was written to disk and then executed inside the container, a common pattern for malware droppers rather than normal application behavior.",
     "Investigate the dropped binary's origin; enforce a read-only root filesystem where possible to prevent this behavior outright."),
    ("Fileless execution via memfd_create",
     "A process created an anonymous in-memory file descriptor via memfd_create and executed from it, a technique used to run code without leaving a file on disk.",
     "Investigate the responsible process; this pattern is uncommon for legitimate application workloads and warrants incident-response triage."),
    ("Netcat Remote Code Execution in Container",
     "The netcat utility was executed inside a container in a mode consistent with establishing a reverse or bind shell.",
     "Investigate the container immediately for signs of remote command execution; remove netcat from production container images."),
    ("Read sensitive file untrusted",
     "A process not on the expected allowlist read a sensitive file (e.g. /etc/shadow) inside the container.",
     "Verify whether the reading process is legitimate; restrict file permissions and container user privileges to least privilege."),
    ("Read sensitive file trusted after startup",
     "A normally-trusted process read a sensitive file well after container startup, outside its expected initialization window.",
     "Confirm this matches expected application behavior; if not, investigate for possible compromise of the trusted process."),
    ("Search Private Keys or Passwords",
     "A process searched the filesystem for files commonly associated with private keys or passwords (e.g. id_rsa, .pem files).",
     "Investigate the responsible process for credential-harvesting behavior; ensure secrets are not stored on container-writable paths."),
    ("Find AWS Credentials",
     "A process accessed a file path commonly used to store AWS credentials (e.g. ~/.aws/credentials) inside the container.",
     "Investigate for credential-harvesting behavior; use short-lived, workload-scoped IAM roles instead of static credential files."),
    ("PTRACE attached to process",
     "A process used ptrace to attach to another running process, a technique that can be used for legitimate debugging or for credential/memory inspection by an attacker.",
     "Verify the attaching process is an authorized debugging tool; restrict the SYS_PTRACE capability for workloads that don't need it."),
    ("Packet socket created in container",
     "A container process created a raw packet socket, capable of sniffing network traffic on the host's network namespace.",
     "Investigate the responsible process; drop the CAP_NET_RAW capability for containers that don't require raw packet access."),
    ("Disallowed SSH Connection Non Standard Port",
     "An outbound SSH connection was established from the container on a non-standard port, a pattern sometimes used to evade simple firewall rules.",
     "Verify the connection is expected; restrict outbound network policy for the workload to only its required destinations/ports."),
]

_RUNTIME_SEVERITY = {
    "Terminal shell in container": ("Critical", 9.0),
    "Contact K8S API Server From Container": ("Critical", 8.8),
    "Debugfs Launched in Privileged Container": ("Critical", 9.3),
    "Detect release_agent File Container Escapes": ("Critical", 9.8),
    "Drop and execute new binary in container": ("High", 8.0),
    "Fileless execution via memfd_create": ("High", 8.1),
    "Netcat Remote Code Execution in Container": ("High", 7.8),
    "Read sensitive file untrusted": ("Medium", 6.5),
    "Read sensitive file trusted after startup": ("Medium", 5.9),
    "Search Private Keys or Passwords": ("Medium", 6.0),
    "Find AWS Credentials": ("Medium", 6.3),
    "PTRACE attached to process": ("Medium", 5.5),
    "Packet socket created in container": ("Medium", 5.0),
    "Disallowed SSH Connection Non Standard Port": ("Low", 3.9),
}

RUNTIME_HOST_NAMES = [
    "prod-api-gateway-pod-01", "checkout-service-container", "user-auth-pod", "payment-processor-container",
    "order-fulfillment-pod", "inventory-sync-container", "notification-worker-pod", "search-indexer-container",
    "batch-etl-pod", "ml-inference-container", "logging-agent-pod", "monitoring-sidecar-container",
    "cache-redis-pod", "queue-consumer-container", "api-gateway-edge-pod", "web-frontend-container",
]


def write_runtime_csv():
    """Runtime/container-security findings have no CVE - each row is a Falco default
    rule match against a fictional container/pod, same combinatorial pattern as
    write_dast_csv()/write_iac_csv(). Directly extends the pending "Container/host
    vulnerability taxonomy expansion" backlog item."""
    BULK_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BULK_DIR / "tenable_bulk_runtime.csv"
    ips = ip_stream(114)
    rows = []
    combos = [(rule, host_name) for rule in RUNTIME_CLASSES for host_name in RUNTIME_HOST_NAMES]
    random.shuffle(combos)
    for (rule_name, synopsis, solution), host_name in combos[:220]:
        host = f"RUNTIME-{host_name.upper()}"
        severity, cvss = _RUNTIME_SEVERITY.get(rule_name, ("Medium", 5.0))
        rows.append([
            _stable_id("runtime", rule_name, host_name),
            "",  # no CVE - a Falco runtime-detection rule match, not a versioned component
            severity,
            cvss,
            host,
            next(ips),
            f"{host_name}.corp.deloitte.local",
            "Container/Pod (runtime security target)",
            f"Falco rule: {rule_name}",
            synopsis,
            solution,
            0,
            "tcp",
            random_recent_date(),
            random_recent_date(days_back_max=3),
        ])
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(TENABLE_HEADER)
        writer.writerows(rows)
    return out_path, len(rows)


# AI/ML security findings have no CVE, mirroring DAST_CLASSES/IAC_CLASSES/RUNTIME_CLASSES.
# Exactly 10 hand-authored findings per one of the 10 real, MITRE-ATLAS-cited categories
# in remediation/enrichment/ai_vuln_taxonomy.py's AI_VULNERABILITIES (100 total) - each
# title/description is phrased to naturally contain that category's own tagging keywords
# (see ai_vuln_taxonomy.py's _PATTERNS), so `tag_findings()` correctly categorizes every
# one with zero tagging-logic changes. Order below matches AI_VULNERABILITIES' own order.
AI_ML_CLASSES = [
    # --- prompt-injection (10) ---
    ("Critical", 9.1, "Direct Prompt Injection Bypasses System Instructions in Customer Support Chatbot",
     "A crafted user message performs a prompt injection that overrides the assistant's system prompt, causing it to ignore its original support-only instructions and follow attacker-supplied commands instead.",
     "Isolate the system prompt from user-controllable context where the model API supports it, and require a human or policy gate before any consequential action a compromised conversation could trigger."),
    ("High", 7.8, "Indirect Prompt Injection via Poisoned Retrieved Document in RAG Pipeline",
     "A malicious instruction embedded in a third-party document ingested by the retrieval-augmented pipeline performs prompt injection when the model later summarizes that content, causing it to execute attacker-supplied instructions instead of the user's original request.",
     "Treat retrieved content as untrusted input and strip/flag instruction-shaped text before it reaches the model context; never let retrieved content alone trigger a privileged action."),
    ("Medium", 6.4, "Jailbreaking Technique Bypasses Content Safety Guardrails on Voice Assistant",
     "A known jailbreaking technique (fictional role-play framing) was used to bypass the voice assistant's content-safety guardrails, a form of prompt injection against its system-level restrictions.",
     "Apply output-side content filtering as a defense-in-depth layer independent of the system prompt, so a successful jailbreak of the prompt alone isn't sufficient to bypass safety controls."),
    ("High", 7.5, "Prompt Injection via Base64-Encoded Instructions in Support Ticket Field",
     "A support ticket's free-text field contained base64-encoded text that performs prompt injection once decoded and processed by the AI triage agent, bypassing its plain-text input filtering.",
     "Decode and re-inspect any encoded content before it reaches the model, and never trust that input filtering alone at the raw-text layer will catch an encoded payload."),
    ("Medium", 6.1, "Multi-Turn Jailbreaking Gradually Erodes System Prompt Adherence",
     "A multi-turn jailbreaking conversation gradually convinced the model to abandon its original system prompt through incremental prompt injection across several turns.",
     "Re-assert or re-check system-prompt adherence periodically across a long conversation rather than trusting it holds for the entire session."),
    ("High", 7.6, "Prompt Injection in Email Auto-Responder via Forwarded Message Content",
     "The email auto-responder AI processes forwarded message bodies without isolating them from its own instructions, allowing prompt injection through a crafted forwarded email.",
     "Isolate forwarded/quoted email content from the model's own instructions the same way any other untrusted external input should be isolated."),
    ("Medium", 5.9, "Jailbreaking via Fictional Framing Bypasses Content Moderation Model",
     "A fictional-narrative framing jailbreaking prompt was used to have the content moderation model approve otherwise-disallowed content, a prompt injection against its safety instructions.",
     "Combine prompt-level instructions with an independent output classifier so moderation doesn't rely solely on the model's own framing-resistant judgment."),
    ("Critical", 8.9, "Prompt Injection Through Malicious Code Comments Reviewed by AI Copilot",
     "A code comment containing hidden instructions performs prompt injection when the code-review copilot processes the file, causing it to approve a vulnerable pull request instead of flagging it.",
     "Never let an AI code-review verdict alone gate a merge - require a human reviewer, and treat code comments as untrusted input the same as any other file content."),
    ("High", 7.2, "Indirect Prompt Injection via Webpage Content Summarized by Browsing Agent",
     "A webpage crawled by the browsing agent contains hidden text that performs prompt injection, redirecting the agent's next actions away from the user's original request.",
     "Sanitize/strip instruction-shaped text from fetched web content before it enters the agent's context, and require confirmation before the agent takes any action based on browsed content."),
    ("Medium", 6.2, "Jailbreaking Attempt Using Nested Instruction Override in System Prompt Field",
     "A nested instruction-override payload in a user-supplied field constitutes prompt injection, successfully jailbreaking the assistant into ignoring its configured restrictions.",
     "Validate and constrain user-supplied fields that flow into the model context, and never let user input directly redefine the assistant's own instruction hierarchy."),

    # --- sensitive-info-disclosure (10) ---
    ("High", 7.4, "System Prompt Leak Exposes Internal Business Rules in AI Support Agent",
     "A crafted user query caused the system prompt to leak in the model's response, exposing internal business rules and escalation criteria that were meant to stay confidential.",
     "Keep the system prompt free of anything damaging if echoed back, and apply output filtering to catch and block verbatim system-prompt reproduction."),
    ("Medium", 6.5, "System Prompt Leaked via Repeated-Word Extraction Attack on Chatbot",
     "A known repeated-word extraction technique caused the chatbot's system prompt to leak verbatim into the conversation, revealing internal configuration details.",
     "Apply output-side detection for verbatim system-prompt reproduction, independent of any single known extraction technique."),
    ("High", 7.9, "Retrieval Pipeline Leaks PII from Training Context to Unauthorized User",
     "The RAG pipeline's system prompt combined with retrieved context caused sensitive customer PII to leak to a user who should not have had access to that record.",
     "Apply least-privilege data access to the retrieval pipeline so it can never surface a record the requesting user isn't authorized to see, regardless of prompt phrasing."),
    ("Medium", 5.8, "System Prompt and API Key Reference Leak Through Debug Output",
     "A debug-mode response caused the assistant's system prompt to leak, including a reference to an internal API key placeholder that should never be echoed back to a user.",
     "Disable verbose/debug response modes in production, and never place a real or placeholder secret reference anywhere the system prompt could echo it."),
    ("Medium", 5.5, "Model Memorization Causes Leak of Verbatim Training Data Snippet",
     "The deployed model's system prompt instructs it to avoid this, but a targeted query still caused a memorized training data snippet to leak in its output.",
     "Sanitize/anonymize training data before use so a memorization leak can't expose anything sensitive, since prompt-level instructions alone can't fully prevent memorization leakage."),
    ("Medium", 6.0, "System Prompt Leak via Translation-Request Side Channel",
     "Asking the assistant to 'translate its instructions' caused its system prompt to leak in translated form, bypassing the direct-request filter that blocks the English-language ask.",
     "Apply output filtering across all response languages/transformations, not just the direct, untranslated request form."),
    ("High", 7.3, "Cross-Tenant Data Leak from Shared Retrieval Index in Multi-Tenant AI Agent",
     "The system prompt did not scope retrieval to the current tenant, so a query caused another tenant's confidential document to leak into the response.",
     "Enforce tenant-scoped access control at the retrieval-index layer itself, not just via the system prompt's own instructions."),
    ("Medium", 6.3, "System Prompt Leak Reveals Proprietary Scoring Logic in Fraud Detection Model",
     "A probing query caused the fraud detection model's system prompt to leak, disclosing proprietary scoring thresholds that inform its risk decisions.",
     "Keep scoring thresholds and business logic out of the system prompt entirely where possible, storing them server-side and never exposing them to the model's own echoable context."),
    ("Medium", 5.6, "Summarization Model Leaks Redacted Section of Source Document",
     "Despite the system prompt instructing it to respect redactions, the summarizer's output caused a redacted section of the source document to leak.",
     "Remove redacted content before it ever reaches the model rather than relying on prompt-level instructions to withhold it."),
    ("Medium", 6.1, "System Prompt Leak Exposes Internal Tool Names and Permissions to End User",
     "A user query caused the agent's system prompt to leak, revealing the names and permission scopes of internal tools it has access to.",
     "Keep tool names/permission details out of any system-prompt content that could be echoed, and apply output filtering to catch attempts to enumerate an agent's own capabilities."),

    # --- training-data-model-poisoning (10) ---
    ("High", 7.7, "Training Data Poisoning via Crowdsourced Feedback Loop in Recommendation Engine",
     "An attacker submitted crafted feedback that performs training data poisoning against the recommendation engine's continuous fine-tuning loop, biasing future rankings.",
     "Restrict who can contribute to a continuously-retrained feedback loop and run anomaly detection over incoming feedback before it influences the next training pass."),
    ("Critical", 9.0, "Backdoored Model Activates Malicious Behavior on Rare Trigger Phrase",
     "The deployed model behaves as a backdoored model, producing an attacker-chosen output whenever a specific rare trigger phrase appears in its input.",
     "Validate model behavior against adversarial test cases (not just standard accuracy benchmarks) before every deployment, specifically probing for trigger-conditioned behavior."),
    ("High", 8.1, "Data Poisoning of Fraud Detection Training Set Suppresses Specific Transaction Pattern",
     "An insider contributed mislabeled records that constitute data poisoning of the fraud detection model's training set, causing it to systematically miss one attacker-known transaction pattern.",
     "Restrict and audit who can contribute labeled training data, and monitor for statistically anomalous label patterns before a retrain is accepted into production."),
    ("Medium", 6.6, "Model Poisoning via Unvetted Third-Party Fine-Tuning Dataset",
     "The fine-tuning pipeline ingested an unvetted third-party dataset without validation, a model poisoning risk since the dataset's provenance and content were never independently verified.",
     "Vet every training/fine-tuning data source's provenance before use, and run anomaly detection over the dataset prior to any fine-tuning run."),
    ("Medium", 6.4, "Training Data Poisoning Through Unmoderated User-Submitted Content Corpus",
     "Unmoderated user-submitted content was included in the training corpus without filtering, a training data poisoning exposure since any contributor could influence future model behavior.",
     "Moderate and filter user-submitted content before it enters any training corpus, and restrict contribution volume per contributor to limit any single actor's influence."),
    ("High", 7.9, "Backdoored Model Checkpoint Downloaded from Unverified Public Repository",
     "The model checkpoint currently in production was sourced from an unverified public repository and was never checked for signs of being a backdoored model.",
     "Source model checkpoints only from verified, signed repositories, and validate any externally-sourced model against known-good benchmarks before deployment."),
    ("Medium", 6.2, "Data Poisoning Risk from Lack of Anomaly Detection on Fine-Tuning Pipeline",
     "The fine-tuning pipeline has no anomaly detection over incoming training data, leaving it exposed to data poisoning from a compromised or malicious contributor.",
     "Add anomaly detection over the fine-tuning pipeline's input data as a standing control, not just a one-time check."),
    ("Medium", 6.0, "Model Poisoning via Label-Flipping Attack on Content Moderation Training Set",
     "A label-flipping attack against the content moderation model's training set is a form of model poisoning, degrading its ability to catch a specific category of disallowed content.",
     "Audit label sources and run periodic label-consistency checks against the moderation training set to catch a flipping attack before it affects production behavior."),
    ("High", 7.5, "Training Data Poisoning Through Compromised Data-Labeling Vendor Pipeline",
     "The third-party data-labeling vendor's pipeline was compromised, introducing a training data poisoning risk into the next scheduled model refresh.",
     "Treat a labeling vendor's pipeline as part of the ML supply chain requiring the same vetting/monitoring as any other third-party data source, and hold the next scheduled refresh pending re-verification."),
    ("Medium", 5.8, "Backdoored Model Suspected After Anomalous Behavior on Specific Input Class",
     "Anomalous, consistently-wrong behavior on one narrow input class raised suspicion that the production model is a backdoored model rather than exhibiting ordinary error.",
     "Investigate the anomalous input class specifically for trigger-conditioned behavior, and roll back to a known-good checkpoint pending confirmation."),

    # --- supply-chain (10) ---
    ("Critical", 9.2, "Model Registry Loads Third-Party Checkpoint via Insecure Pickle Deserialization",
     "The model registry loads third-party model checkpoints using Python's pickle format without weights_only=True - insecure pickle deserialization that would execute arbitrary code if a malicious model were substituted.",
     "Load model checkpoints with a safe loader (e.g. weights_only=True or an equivalent format-restricted loader), never a general-purpose pickle load, for any externally-sourced artifact."),
    ("High", 8.0, "Malicious Pre-Trained Model Downloaded from Unofficial Mirror Site",
     "A pre-trained model was downloaded from an unofficial mirror rather than the vendor's verified source, raising the risk it is a malicious pre-trained model repackaged with a hidden backdoor.",
     "Source pre-trained models only from verified, signed vendor repositories, and re-download from the official source rather than trusting an unofficial mirror."),
    ("Critical", 9.0, "Unsafe Deserialization of Uploaded Model File in Self-Service ML Platform",
     "The self-service ML platform accepts user-uploaded model files and loads them via unsafe deserialization, allowing arbitrary code execution if a malicious model is uploaded.",
     "Scan uploaded model artifacts for unsafe deserialization patterns and load them only through a sandboxed, format-restricted loader, never a general-purpose deserializer."),
    ("High", 7.6, "Compromised ML Library Dependency Enables Insecure Deserialization of Cached Model Metadata",
     "A transitive ML library dependency was compromised in a supply-chain attack, introducing a code path that performs insecure deserialization of cached model metadata - an AI supply-chain risk if paired with a malicious pre-trained model swap.",
     "Maintain an SBOM covering ML libraries specifically, pin and vet third-party ML library versions the same as any other dependency, and patch immediately once a compromised transitive dependency is identified."),
    ("High", 7.8, "Insecure Pickle Deserialization When Loading Cached Inference Artifacts",
     "Cached inference artifacts are loaded via insecure pickle deserialization without integrity verification, allowing a tampered cache entry to execute arbitrary code.",
     "Verify cache integrity (e.g. a signature or checksum) before loading, and switch cached-artifact loading to a safe, format-restricted deserializer."),
    ("Medium", 6.3, "No SBOM Coverage for ML Model Artifacts Used in Production Inference Service",
     "The production inference service has no SBOM entry for its model artifacts, an AI supply-chain gap since a malicious pre-trained model swap would go undetected.",
     "Extend SBOM coverage to model artifacts alongside traditional application dependencies, so any unexpected model swap is detectable."),
    ("High", 7.4, "Unsigned Model Artifact Accepted Without Provenance Verification",
     "The deployment pipeline accepts an unsigned model artifact with no provenance verification, unable to distinguish a legitimate release from a malicious pre-trained model.",
     "Require signed model artifacts with verified provenance before any production deployment step will accept them."),
    ("Medium", 6.5, "Insecure Deserialization of Model Config Enables Arbitrary Attribute Injection",
     "The model-loading step performs insecure deserialization of a YAML config bundled with the model, allowing arbitrary attribute injection if the bundle is tampered with.",
     "Load model configuration through a schema-validated, safe parser rather than an insecure deserializer that allows arbitrary object construction."),
    ("Medium", 6.1, "Third-Party Fine-Tuned Model Adopted Without Independent Behavioral Validation",
     "A third-party fine-tuned model was adopted into production without independent behavioral validation, an AI supply-chain risk if it is in fact a malicious pre-trained model with planted behavior.",
     "Independently validate any third-party fine-tuned model against known-good benchmarks and adversarial test cases before adopting it into production."),
    ("Medium", 6.4, "Vulnerable Version of ML Serialization Library Enables Insecure Deserialization",
     "The deployed ML serialization library version has a known insecure deserialization weakness, and the pipeline has not been updated to the patched release.",
     "Update the ML serialization library to the patched release and pin the version going forward, treating it the same as any other vulnerable dependency."),

    # --- improper-output-handling (10) ---
    ("High", 7.5, "LLM Output Rendered as Unescaped HTML in Chat Widget",
     "The chat widget renders LLM output directly into the page as unescaped HTML, allowing a crafted response to execute injected script in the user's browser.",
     "Escape LLM output before rendering as HTML, exactly like this project's own escapeHtml() pattern applied to any other untrusted string."),
    ("Critical", 9.3, "Model Output Passed to eval() to Execute Generated Automation Script",
     "The automation agent passes model output directly to eval() to run a generated script, executing whatever code the model (or an attacker manipulating it) produces.",
     "Never eval()/exec() model output; parse and execute only a constrained, pre-approved set of operations instead of arbitrary generated code."),
    ("High", 7.6, "LLM Output Concatenated Unsanitized into SQL Query in Reporting Tool",
     "The reporting tool builds a database query by concatenating LLM output directly into an unsanitized SQL string, allowing a crafted response to alter the query's meaning.",
     "Parameterize any downstream query built from model output rather than string-concatenating it, the same as any other untrusted input source."),
    ("Critical", 9.1, "Model Output Used in eval() Context to Build Dynamic Configuration",
     "The deployment tool takes model output and runs it through eval() to build a configuration object, giving the model's output the ability to execute arbitrary code.",
     "Replace eval()-based configuration construction with a schema-validated parser that accepts only well-formed configuration data, never executable code."),
    ("Medium", 6.5, "LLM Output Rendered Unescaped in Markdown Preview Pane",
     "The documentation assistant's LLM output is rendered unescaped in the markdown preview pane, allowing embedded script-like markup to execute.",
     "Escape or sanitize LLM output before rendering it in any markdown/HTML preview surface."),
    ("Critical", 8.8, "Model Output Piped to eval() Inside Notebook Auto-Completion Feature",
     "The notebook's AI auto-completion feature pipes model output straight into eval() to preview a suggested cell's result, executing unreviewed generated code.",
     "Require an explicit user-confirmation step before executing any AI-suggested code, never auto-execute a suggestion via eval()."),
    ("High", 7.3, "LLM Output Used Unescaped to Construct Shell Command in DevOps Bot",
     "The DevOps bot builds a shell command using LLM output that is unescaped, letting a crafted response inject additional shell operators.",
     "Never build a shell command via string concatenation from model output; use a parameterized subprocess call with a fixed, validated argument list."),
    ("High", 7.7, "Model Output From Code-Generation Assistant Passed to eval() Before Review",
     "The code-generation assistant's model output is passed to eval() for a live preview before any human review step, executing unvetted generated code.",
     "Sandbox any live-preview execution of generated code and require human review before it runs against anything beyond a fully isolated sandbox."),
    ("Medium", 6.2, "LLM Output Embedded Unsanitized into Outbound Email Template",
     "The auto-reply feature embeds LLM output unsanitized into the outbound email's HTML template, allowing injected markup to reach recipients.",
     "Sanitize LLM output before embedding it into any outbound content template, the same as any other untrusted content source."),
    ("Medium", 6.6, "Model Output Routed to eval() for Dynamic Report Formatting Logic",
     "The reporting pipeline routes model output to eval() to determine dynamic formatting logic, giving generated text the ability to execute code at render time.",
     "Replace eval()-based formatting logic with a fixed, declarative formatting spec the model can only select from, never author executable code for."),

    # --- excessive-agency (10) ---
    ("Critical", 9.4, "LLM Agent Granted Excessive Agency to Approve Financial Transactions Autonomously",
     "The finance-automation agent was granted excessive agency, able to approve and execute payment transactions with no human checkpoint in the loop.",
     "Require human-in-the-loop confirmation for any consequential financial action, regardless of how confident the agent's own reasoning appears."),
    ("Critical", 9.2, "Autonomous Ops Agent Given Unrestricted Tool Access to Production Shell",
     "The autonomous ops agent was configured with unrestricted tool access to a production shell, letting a single manipulated conversation cascade into real infrastructure changes.",
     "Apply least-privilege scoping to every tool an agent can call, and never grant unrestricted shell access to an autonomous agent operating against production."),
    ("High", 7.9, "Customer Support Agent Can Issue Refunds With No Human Approval Step",
     "The support agent has no human checkpoint before issuing a refund, an excessive agency risk since a manipulated conversation could trigger unauthorized payouts.",
     "Require a human approval step for any refund above a low, pre-approved threshold, and log every agent-initiated refund for audit."),
    ("Critical", 9.0, "Autonomous Agent Deletes Files with Unrestricted Tool Access and No Confirmation",
     "The file-management agent has unrestricted tool access to delete files with no human confirmation step, letting a single erroneous instruction cause irreversible data loss.",
     "Require explicit human confirmation before any destructive file operation, and scope the agent's delete permissions to only what its task genuinely requires."),
    ("High", 8.1, "Agent Orchestrator Chains Tool Calls With No Human Checkpoint Between Steps",
     "The agent orchestrator chains multiple tool calls with no human checkpoint between steps, a form of excessive agency that lets one bad decision cascade unchecked.",
     "Insert a human or policy checkpoint between chained tool calls for any sequence with real-world side effects, rather than allowing an uninterrupted autonomous chain."),
    ("High", 7.6, "Email-Sending Agent Has Unrestricted Tool Access to Company-Wide Distribution Lists",
     "The email agent has unrestricted tool access to company-wide distribution lists with no human review before sending, an excessive agency exposure for mass-communication mistakes.",
     "Require human review before any agent-initiated send to a broad distribution list, and scope the agent's send permissions to smaller, task-specific lists by default."),
    ("Critical", 8.9, "DevOps Agent Can Modify Production Infrastructure With No Human Approval Gate",
     "The DevOps agent can modify production infrastructure directly, an excessive agency configuration since there is no human approval gate before a change is applied.",
     "Require a human approval gate (e.g. a reviewable, generated change plan) before any agent-proposed production infrastructure change is applied."),
    ("Critical", 9.1, "Autonomous Trading Agent Executes Trades With No Human Review of Rationale",
     "The trading agent executes trades autonomously with no human review of its rationale beforehand, an excessive agency risk given the direct financial impact of a wrong decision.",
     "Require human review of the agent's stated rationale before executing any trade above a pre-approved size, and log every autonomous decision for audit."),
    ("High", 8.0, "HR Agent Granted Unrestricted Tool Access to Modify Employee Compensation Records",
     "The HR assistant agent was granted unrestricted tool access to modify compensation records directly, with no human approval required for the change to take effect.",
     "Require a human approval step for any agent-proposed compensation change, and scope the agent's tool access to read-only for sensitive HR records by default."),
    ("Critical", 9.0, "Agent-to-Shell Bridge Allows Arbitrary Command Execution With No Human in the Loop",
     "The agent-to-shell bridge allows arbitrary command execution with no human in the loop, an excessive agency design that turns any single successful manipulation of the agent into direct system access.",
     "Replace the arbitrary-command bridge with a constrained, allowlisted set of specific operations, and require human confirmation for anything outside routine read-only checks."),

    # --- unbounded-consumption (10) ---
    ("Medium", 5.9, "Unbounded Context Window Accepts Arbitrarily Large Uploaded Document",
     "The summarization endpoint accepts an unbounded context input from an uploaded document with no size cap, letting a single request drive excessive inference cost.",
     "Enforce an input-length limit on uploaded documents before they're passed to the model, sized to genuine business need."),
    ("Medium", 6.1, "Token Flood Attack Drives Excessive Inference Cost on Public Chat Endpoint",
     "A scripted token flood attack against the public chat endpoint repeatedly submits maximum-length prompts, driving up inference cost with no per-user rate limit.",
     "Apply per-user rate limiting and cost quotas to the public chat endpoint, independent of any single request's own length limit."),
    ("Medium", 6.3, "Model Denial of Service via Recursive Self-Prompting Agent Loop",
     "An uncontrolled agent loop causes the model to repeatedly re-prompt itself, a model denial of service condition that consumes resources with no forward progress.",
     "Enforce a hard iteration cap on any agent or tool-calling loop, and detect/terminate a loop that isn't making measurable progress toward its goal."),
    ("Medium", 5.7, "Unbounded Consumption from Missing Per-User Rate Limit on Inference API",
     "The inference API has no per-user rate limit, an unbounded consumption exposure that lets a single caller monopolize available capacity.",
     "Add a per-user or per-API-key rate limit to the inference API as a baseline control, regardless of any other cost-management measure."),
    ("Low", 3.7, "Token Flood via Adversarially Crafted Repetitive Prompt Pattern",
     "An adversarially crafted, highly repetitive prompt pattern constitutes a token flood, consuming disproportionate compute relative to its actual informational content.",
     "Detect and rate-limit repetitive/low-information-density prompt patterns as a defense-in-depth cost control."),
    ("Medium", 6.0, "Model DoS Condition from Uncontrolled Retry Loop on Failed Tool Call",
     "A tool-calling agent enters an uncontrolled retry loop on a failed call, a model denial of service condition since retries are unbounded and unthrottled.",
     "Cap retry attempts with backoff and a hard ceiling, and alert rather than retry indefinitely once the cap is reached."),
    ("Low", 3.9, "Unbounded Context Consumption from Unlimited Conversation History Retention",
     "The chat session retains unlimited conversation history and resubmits all of it as context on every turn, an unbounded consumption pattern that scales cost with session length alone.",
     "Cap retained conversation history (e.g. a rolling window or summarized older turns) instead of resubmitting an ever-growing transcript on every request."),
    ("Medium", 6.2, "Token Flood Exploits Lack of Input-Length Validation on Batch Summarization Job",
     "The batch summarization job has no input-length validation, letting a token flood of oversized documents drive excessive cost in a single scheduled run.",
     "Validate and cap input length per document in the batch job, rejecting or splitting oversized documents rather than processing them unbounded."),
    ("Medium", 5.8, "Model Denial of Service via Crafted Prompt Triggering Maximum-Length Generation",
     "A crafted prompt reliably triggers maximum-length generation on every call, a model denial of service pattern that maximizes cost per request with minimal attacker effort.",
     "Set a reasonable output-length cap tuned to genuine use cases, and monitor for prompts that consistently hit the maximum."),
    ("Low", 3.8, "Unbounded Consumption from Missing Iteration Cap on Autonomous Research Agent",
     "The autonomous research agent has no iteration cap on its own tool-calling loop, an unbounded consumption risk that can run indefinitely on an unproductive research path.",
     "Add a hard iteration/time cap to the research agent's loop, mirroring this project's own --max-budget-usd spend-cap pattern applied to a different cost surface."),

    # --- model-theft (10) ---
    ("High", 7.2, "Model Extraction Attack via Systematic Query Sweep Against Public Inference API",
     "A systematic, high-volume query sweep against the public inference API is consistent with a model extraction attack aimed at reconstructing the underlying model's decision boundary.",
     "Rate-limit and monitor API query patterns for extraction-shaped behavior, such as unusually broad, systematic input coverage from one account."),
    ("Medium", 6.5, "Model Theft Risk from Unrestricted Bulk Export of Model Weights",
     "The ML platform allows any authenticated user to bulk-export model weights directly, a model theft risk with no additional access control beyond basic authentication.",
     "Restrict raw model-artifact export to the same access-control standard as any other high-value credential or secret, not just basic authentication."),
    ("Medium", 6.4, "Model Stealing Attempt Detected via High-Volume API Calls from Single Account",
     "An unusually high volume of API calls from a single account, spanning a systematic input sweep, is consistent with a model stealing attempt against the proprietary scoring model.",
     "Alert on and rate-limit accounts whose query volume/pattern is consistent with a model stealing attempt."),
    ("Medium", 6.1, "Model Extraction via Distillation From Repeated Confidence-Score Queries",
     "An attacker issuing repeated queries specifically to harvest confidence scores is performing model extraction via distillation, reconstructing model behavior without access to its weights.",
     "Consider withholding or coarsening raw confidence scores in the public API response where the extra precision isn't needed by legitimate callers."),
    ("Medium", 5.9, "Model Theft Exposure from Unencrypted Model Artifact Storage Bucket",
     "The model artifact storage bucket is unencrypted and broadly readable, a model theft exposure since the raw weights could be copied directly rather than extracted via queries.",
     "Encrypt model artifact storage at rest and restrict read access to only the services that genuinely need it."),
    ("Medium", 6.0, "Model Stealing Risk from Missing Rate Limits on Recommendation Engine's Public API",
     "The recommendation engine's public API has no rate limiting, a model stealing risk since an attacker could systematically probe it to reconstruct its ranking logic.",
     "Add rate limiting to the recommendation engine's public API as a baseline anti-extraction control."),
    ("Low", 4.2, "Model Extraction Attack Pattern Identified in API Access Logs Over 30-Day Window",
     "A 30-day review of API access logs identified a query pattern consistent with a model extraction attack: broad, systematic input coverage from a small number of accounts.",
     "Investigate and rate-limit the identified accounts, and add ongoing monitoring for the same query-pattern signature going forward."),
    ("Medium", 6.3, "Model Theft via Insufficient Access Control on Internal Model-Serving Endpoint",
     "An internal model-serving endpoint intended for one team is reachable more broadly than intended, a model theft exposure since it returns full output the raw model would produce.",
     "Restrict the internal model-serving endpoint's access control to the specific team/service it was intended for."),
    ("Low", 3.9, "Model Stealing Countermeasure Missing: No Watermarking on Generated Outputs",
     "The deployed model has no output watermarking, leaving no way to detect model stealing via a competitor training on scraped outputs.",
     "Evaluate output watermarking where feasible for the model's output type, as a detective (not preventive) control against distillation-based model stealing."),
    ("Medium", 5.7, "Model Extraction Risk from Verbose Error Messages Revealing Internal Model Structure",
     "Verbose error messages returned by the inference API reveal internal model structure details, aiding a model extraction attempt by narrowing the attacker's search space.",
     "Return generic error messages to API callers and log verbose details only server-side."),

    # --- misinformation (10) ---
    ("Medium", 5.5, "Model Hallucinates Fabricated Legal Citation Presented as Fact to End User",
     "The legal-research assistant hallucinates a fabricated case citation and presents it as fact, with no confidence indicator to signal the claim is unverified.",
     "Require citation verification against a real source before presenting any legal reference as fact, and surface confidence/uncertainty in the response."),
    ("Medium", 6.0, "Overreliance on Model Output Without Human Review in Automated Decision Pipeline",
     "The automated decision pipeline exhibits overreliance on model output, acting on generated conclusions with no human review step before a consequential action is taken.",
     "Add a human review step before any consequential automated action, and never let unreviewed model output alone trigger it."),
    ("Low", 3.8, "Model Hallucinates Non-Existent API Endpoint in Generated Integration Code",
     "The coding assistant hallucinates a plausible-sounding but non-existent API endpoint, which a developer could ship without independently verifying it exists.",
     "Verify any AI-suggested API reference against real documentation before shipping generated integration code."),
    ("Medium", 5.9, "Misinformation Risk: Model Presents Uncertain Medical Guidance as Definitive",
     "The health-information model presents an uncertain claim as definitive guidance, a misinformation risk in a model deployed without a clear uncertainty-disclosure mechanism.",
     "Surface confidence/uncertainty explicitly wherever the underlying model exposes it, and never present an uncertain health claim as definitive."),
    ("Medium", 6.1, "Model Hallucinates Financial Figures in Automated Quarterly Summary Draft",
     "The reporting assistant hallucinates a plausible-looking financial figure in its automated summary draft, which was nearly published without cross-checking against the source data.",
     "Cross-check any generated figure against the underlying source data before publication, and keep a human reviewer in the loop for financial reporting content."),
    ("Low", 4.0, "Overreliance on Model-Generated Risk Score Without Independent Verification",
     "The underwriting workflow exhibits overreliance on a model-generated risk score, treating it as authoritative with no independent verification step before a decision is finalized.",
     "Add an independent verification step before finalizing a decision based on a model-generated score, rather than treating it as authoritative on its own."),
    ("Low", 3.6, "Model Hallucinates Source Attribution for a Claim It Cannot Actually Support",
     "The research assistant hallucinates a specific source attribution for a claim, citing a document that does not actually contain the claimed information.",
     "Verify cited sources actually support the attributed claim before surfacing the citation, rather than trusting the model's own attribution."),
    ("Medium", 5.7, "Misinformation Concern: Model Confidently Answers Outside Its Verified Knowledge Scope",
     "The support model answers confidently on topics outside its verified knowledge scope, a misinformation risk since nothing in its response signals the lower reliability.",
     "Constrain the model's confident-answer scope to its verified knowledge domain, and surface an explicit lower-confidence signal outside that scope."),
    ("Medium", 6.0, "Model Hallucinates Plausible but Incorrect Regulatory Requirement in Compliance Assistant",
     "The compliance assistant hallucinates a plausible-sounding but incorrect regulatory requirement, which was surfaced to an analyst as though it were an established rule.",
     "Require verification against the actual regulatory text before presenting any compliance requirement as established, and keep a human reviewer in the loop."),
    ("Medium", 5.8, "Overreliance on Chatbot Guidance Led to Incorrect Customer-Facing Policy Statement",
     "Overreliance on the chatbot's generated guidance, without a human review step, led to an incorrect policy statement being sent directly to a customer.",
     "Add a human review step before any AI-generated policy statement reaches a customer, rather than sending unreviewed guidance directly."),

    # --- insecure-plugin-tool-design (10) ---
    ("Critical", 8.7, "File-System Plugin Accepts Unvalidated Path Input From LLM Agent",
     "The file-system plugin invoked by the LLM agent accepts an unvalidated path argument directly from model output, allowing path traversal outside the intended directory.",
     "Validate and constrain the plugin's path argument at the tool boundary itself, rejecting any path outside an explicit allowlisted directory."),
    ("Critical", 9.0, "Payment Plugin Processes Unvalidated Amount Field Supplied by Agent",
     "The payment-processing plugin accepts an unvalidated amount field passed directly from the agent's tool call, with no server-side bounds checking before executing the charge.",
     "Validate the amount field against server-side bounds and business rules at the plugin boundary, independent of whatever the agent supplies."),
    ("High", 8.2, "Tool-Calling Interface Executes Unvalidated Shell Argument From Model Output",
     "The tool-calling interface passes an unvalidated argument straight from model output into a shell command, extending an attacker's reach from the conversation into the underlying system.",
     "Never build a shell command from unvalidated model output; use a parameterized call with a fixed, validated argument list at the tool boundary."),
    ("High", 7.8, "Internal API Plugin Accepts Unvalidated Request Body Constructed by Agent",
     "The internal API plugin accepts an unvalidated request body constructed entirely by the agent, trusting the model to always produce well-formed, safe arguments.",
     "Validate the plugin's request body against a strict schema at the tool boundary, never trusting the model to only ever pass well-formed arguments."),
    ("High", 7.9, "Database Query Plugin Passes Unvalidated Filter Clause From LLM Agent Tool Call",
     "The database-query plugin passes an unvalidated filter clause directly from the LLM agent's tool call into the query builder, allowing an unintended broad or malicious filter.",
     "Constrain the plugin to a fixed set of parameterized filter options rather than accepting a free-form, unvalidated filter clause from the agent."),
    ("Medium", 6.6, "Tool-Calling Framework Allows Unvalidated Recipient Field in Email-Sending Tool",
     "The tool-calling framework's email tool accepts an unvalidated recipient field from the agent, allowing a manipulated conversation to redirect messages to an unintended address.",
     "Validate the recipient field against an allowlist or existing-contact check at the tool boundary, independent of what the agent supplies."),
    ("High", 7.6, "Webhook-Triggering Plugin Accepts Unvalidated URL From Agent Without Allowlist",
     "The webhook plugin accepts an unvalidated destination URL supplied by the agent with no allowlist, letting a manipulated agent trigger a request to an arbitrary endpoint.",
     "Restrict the webhook plugin to a pre-approved destination allowlist, rejecting any URL supplied by the agent that isn't on it."),
    ("Medium", 6.4, "Calendar-Modifying Plugin Trusts Unvalidated Date Range Supplied by LLM Agent",
     "The calendar plugin trusts an unvalidated date range supplied directly by the LLM agent, with no bounds check before bulk-modifying events in that range.",
     "Bounds-check the date range at the plugin boundary and require confirmation before any bulk-modification action."),
    ("Critical", 8.8, "Code-Execution Plugin Accepts Unvalidated Script Body From Tool-Calling Agent",
     "The code-execution plugin accepts an unvalidated script body passed directly from the tool-calling agent, running it with no sandboxing or review step.",
     "Sandbox any agent-invoked code execution and require human review before running a generated script outside a fully isolated environment."),
    ("Medium", 6.5, "Ticketing-System Plugin Accepts Unvalidated Priority Escalation Field From Agent",
     "The ticketing-system plugin accepts an unvalidated priority-escalation field from the agent's tool call, letting a manipulated conversation force incident escalation.",
     "Validate the escalation field against role-based limits at the plugin boundary, rather than trusting whatever priority the agent's tool call requests."),
]

AI_ML_HOSTS = [
    "LLM-CHATBOT-01", "AI-SUPPORT-AGENT-02", "RAG-KNOWLEDGE-BOT-03", "ML-TRAINING-PIPELINE-04",
    "MODEL-REGISTRY-05", "AI-AGENT-ORCHESTRATOR-06", "LLM-API-GATEWAY-07", "ML-INFERENCE-SVC-08",
    "CONTENT-MOD-MODEL-09", "FRAUD-DETECTION-MODEL-10", "CODE-REVIEW-COPILOT-11", "DOC-SUMMARIZER-AI-12",
    "VOICE-ASSISTANT-BACKEND-13", "AUTONOMOUS-OPS-AGENT-14", "RECOMMENDATION-ENGINE-ML-15",
]


def write_ai_ml_csv():
    """AI/ML security findings have no CVE - each row is a hand-authored finding against
    one of AI_VULNERABILITIES' 10 real, MITRE-ATLAS-cited categories
    (remediation/enrichment/ai_vuln_taxonomy.py), phrased to tag correctly via that
    module's existing keyword heuristic. Unlike write_dast_csv()/write_runtime_csv()'s
    shuffle-and-slice combinatorics, hosts are assigned deterministically (cycled by
    index) since the goal here is reliably 10 findings per category, not just aggregate
    variety across a larger combinatorial pool."""
    BULK_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BULK_DIR / "tenable_bulk_ai_ml.csv"
    ips = ip_stream(118)
    rows = []
    for i, (severity, cvss, title, synopsis, solution) in enumerate(AI_ML_CLASSES):
        host_name = AI_ML_HOSTS[i % len(AI_ML_HOSTS)]
        host = f"AI-ML-{host_name}"
        rows.append([
            _stable_id("ai_ml", title, host_name),
            "",  # no CVE - a hand-authored AI/ML security finding, not a versioned component
            severity,
            cvss,
            host,
            next(ips),
            f"{host_name.lower()}.corp.deloitte.local",
            "AI/ML System (LLM/agent security target)",
            title,
            synopsis,
            solution,
            0,
            "tcp",
            random_recent_date(),
            random_recent_date(days_back_max=3),
        ])
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(TENABLE_HEADER)
        writer.writerows(rows)
    return out_path, len(rows)


def write_armis_json(cves):
    BULK_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BULK_DIR / "armis_bulk_ot.json"
    ips = ip_stream(150)
    devices = []
    for i, c in enumerate(cves, start=1):
        text = (c["description"] or "").lower()
        device_type = DEFAULT_DEVICE_TYPE
        for hint, dtype in DEVICE_TYPES_BY_KEYWORD_HINT:
            if hint in text:
                device_type = dtype
                break
        device_name = f"OT-IOT-{i:04d}"
        devices.append({
            "deviceId": _stable_id("armis", c["cve_id"]),
            "deviceName": device_name,
            "deviceType": device_type,
            "manufacturer": "Various (see finding description)",
            "model": "N/A",
            "ipAddress": next(ips),
            "macAddress": "00:00:00:00:00:00",
            "site": "HQ-Bulk-Demo-Data",
            "riskLevel": c["severity"],
            "alerts": [{
                "alertType": "Known Vulnerability",
                "title": _truncate(c["description"], 120),
                "description": c["description"],
                "cve": c["cve_id"],
                "firstSeen": random_recent_date(),
                "lastSeen": random_recent_date(days_back_max=3),
            }],
        })
    out_path.write_text(json.dumps({"exportedAt": datetime.datetime.now().isoformat(), "devices": devices}, indent=2),
                         encoding="utf-8")
    return out_path, len(devices)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--category", action="append", help="Limit to one or more category keys (repeatable)")
    args = parser.parse_args()

    wanted = set(args.category) if args.category else None
    seen_global = set()
    summary = []

    for key, config in TENABLE_CATEGORIES.items():
        if wanted and key not in wanted:
            continue
        cves = collect_real_cves(config["queries"], config["target"], seen_global)
        path, n = write_tenable_csv(key, cves, config)
        summary.append((key, n, config["target"], str(path)))

    if not wanted or "ot" in wanted:
        cves = collect_real_cves(ARMIS_CATEGORY["queries"], ARMIS_CATEGORY["target"], seen_global)
        path, n = write_armis_json(cves)
        summary.append(("ot", n, ARMIS_CATEGORY["target"], str(path)))

    if not wanted or "dast" in wanted:
        path, n = write_dast_csv()
        summary.append(("dast", n, 300, str(path)))

    if not wanted or "iac" in wanted:
        path, n = write_iac_csv()
        summary.append(("iac", n, 220, str(path)))

    if not wanted or "code_repository_secrets" in wanted:
        path, n = write_code_repository_secrets_csv()
        summary.append(("code_repository_secrets", n, 110, str(path)))

    if not wanted or "runtime" in wanted:
        path, n = write_runtime_csv()
        summary.append(("runtime", n, 220, str(path)))

    if not wanted or "ai_ml" in wanted:
        path, n = write_ai_ml_csv()
        summary.append(("ai_ml", n, 100, str(path)))

    print("\nGenerated (category, real-findings-count, target, path):")
    for row in summary:
        flag = "" if row[1] >= row[2] else "  <-- below target, real-CVE pool exhausted for this query set"
        print(f"  {row[0]:<18} {row[1]:>4} / {row[2]:<4} {row[3]}{flag}")


if __name__ == "__main__":
    main()
