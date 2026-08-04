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


def collect_real_cves(queries, target, seen_global):
    """Runs each keyword query in turn, collecting distinct, well-formed real CVEs
    (must have an English description and a resolvable CVSS score) not already used
    elsewhere in this dataset, until `target` is reached or queries are exhausted."""
    collected = []
    for keyword in queries:
        if len(collected) >= target:
            break
        for entry in fetch_nvd(keyword):
            if len(collected) >= target:
                break
            cve = entry["cve"]
            cve_id = cve["id"]
            if cve_id in seen_global:
                continue
            desc = english_description(cve)
            score, severity = best_cvss(cve)
            if not desc or score is None:
                continue
            seen_global.add(cve_id)
            collected.append({
                "cve_id": cve_id,
                "description": desc,
                "score": score,
                "severity": severity.capitalize(),
                "cwe": cwe_of(cve),
                "published": cve.get("published", "")[:10],
            })
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
                    "Microsoft Exchange Server", "Active Directory"],
        "target": 180,
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
        "queries": ["Linux kernel", "Ubuntu", "Red Hat Enterprise Linux", "OpenSSH", "sudo"],
        "target": 120,
        "os_choices": ["Ubuntu Linux 20.04", "Ubuntu Linux 22.04", "Red Hat Enterprise Linux 8",
                       "Red Hat Enterprise Linux 9", "CentOS Linux 7", "Debian Linux 11"],
        "vendor_hints": [("ubuntu", "Ubuntu Linux 22.04"), ("red hat", "Red Hat Enterprise Linux 9"),
                          ("rhel", "Red Hat Enterprise Linux 9"), ("centos", "CentOS Linux 7"),
                          ("debian", "Debian Linux 11")],
        "host_prefix": "LNX-SRV", "ip_base": 101, "port_choices": [22, 443, 80, 0],
    },
    "network": {
        "queries": ["Cisco IOS", "Cisco IOS XE", "Cisco NX-OS", "Juniper Junos", "Arista EOS"],
        "target": 300,
        "os_choices": ["Cisco IOS XE 17.x", "Cisco IOS 15.x", "Cisco NX-OS 9.x", "Juniper Junos 21.x",
                       "Arista EOS 4.x"],
        "vendor_hints": [("ios xe", "Cisco IOS XE 17.x"), ("nx-os", "Cisco NX-OS 9.x"),
                          ("ios", "Cisco IOS 15.x"), ("junos", "Juniper Junos 21.x"),
                          ("arista", "Arista EOS 4.x")],
        "host_prefix": "NET-RTSW", "ip_base": 102, "port_choices": [443, 22, 23, 0],
    },
    "network_security": {
        "queries": ["Fortinet FortiOS", "Palo Alto Networks PAN-OS", "Check Point", "Juniper SRX",
                    "F5 BIG-IP", "SonicWall", "Citrix NetScaler"],
        "target": 300,
        "os_choices": ["Fortinet FortiOS 7.x", "Palo Alto Networks PAN-OS 10.x", "Check Point GAIA R80.x",
                       "Juniper Junos SRX", "F5 BIG-IP 15.x", "SonicWall SonicOS 7.x",
                       "Citrix ADC/NetScaler 13.x"],
        "vendor_hints": [("fortinet", "Fortinet FortiOS 7.x"), ("fortios", "Fortinet FortiOS 7.x"),
                          ("fortigate", "Fortinet FortiOS 7.x"), ("palo alto", "Palo Alto Networks PAN-OS 10.x"),
                          ("pan-os", "Palo Alto Networks PAN-OS 10.x"), ("check point", "Check Point GAIA R80.x"),
                          ("srx", "Juniper Junos SRX"), ("big-ip", "F5 BIG-IP 15.x"), ("f5", "F5 BIG-IP 15.x"),
                          ("sonicwall", "SonicWall SonicOS 7.x"), ("netscaler", "Citrix ADC/NetScaler 13.x"),
                          ("citrix", "Citrix ADC/NetScaler 13.x")],
        "host_prefix": "FW-EDGE", "ip_base": 103, "port_choices": [443, 4443, 0],
    },
    "cloud": {
        "queries": ["Kubernetes", "Docker", "Amazon Web Services", "Microsoft Azure",
                    "Google Cloud Platform", "Terraform", "container escape"],
        "target": 300,
        "os_choices": ["Kubernetes 1.2x (self-managed cluster node)", "Docker Engine 24.x",
                       "Amazon EKS worker node (Amazon Linux 2)", "Azure Kubernetes Service node",
                       "Google Kubernetes Engine node", "Terraform-provisioned cloud resource"],
        "vendor_hints": [("kubernetes", "Kubernetes 1.2x (self-managed cluster node)"),
                          ("docker", "Docker Engine 24.x"), ("amazon", "Amazon EKS worker node (Amazon Linux 2)"),
                          ("aws", "Amazon EKS worker node (Amazon Linux 2)"),
                          ("azure", "Azure Kubernetes Service node"),
                          ("google cloud", "Google Kubernetes Engine node"),
                          ("terraform", "Terraform-provisioned cloud resource")],
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
}

ARMIS_CATEGORY = {
    "queries": ["SCADA", "industrial control system", "IoT device", "building automation",
                "IP camera", "embedded device", "Siemens SIMATIC", "programmable logic controller"],
    "target": 300,
}

DEVICE_TYPES_BY_KEYWORD_HINT = [
    ("camera", "IP Camera"), ("scada", "SCADA HMI"), ("industrial", "Industrial Sensor Gateway"),
    ("programmable logic", "Programmable Logic Controller"), ("building", "Building Automation Controller"),
    ("siemens", "Industrial PLC (Siemens SIMATIC family)"),
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

_plugin_id_counter = [500000]


def _next_plugin_id():
    _plugin_id_counter[0] += 1
    return _plugin_id_counter[0]


def _truncate(text, max_len=400):
    text = " ".join(text.split())
    return text if len(text) <= max_len else text[:max_len - 1].rsplit(" ", 1)[0] + "…"


def _os_for(config, description):
    """Picks the OS/product label that actually matches the real CVE's own
    description (e.g. a Fortinet CVE gets labeled FortiOS, not a randomly-chosen
    competitor product) - falls back to a random in-category choice only when no
    vendor keyword from this category matched."""
    text = description.lower()
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
            _next_plugin_id(),
            c["cve_id"],
            c["severity"],
            c["score"],
            host,
            next(ips),
            f"{host.lower()}.corp.deloitte.local",
            _os_for(config, c["description"]),
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
            _next_plugin_id(),
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
            "deviceId": 900000 + i,
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

    print("\nGenerated (category, real-findings-count, target, path):")
    for row in summary:
        flag = "" if row[1] >= row[2] else "  <-- below target, real-CVE pool exhausted for this query set"
        print(f"  {row[0]:<18} {row[1]:>4} / {row[2]:<4} {row[3]}{flag}")


if __name__ == "__main__":
    main()
