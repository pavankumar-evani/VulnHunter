"""
One fictional estate, generated deterministically, that every simulated connector renders from.

Why one estate: the same hosts must show up in Tenable, Qualys, OpenVAS (and later Prisma Cloud,
the asset sources and so on) so that Quanta's correlation, ownership and attack-path features have
something real to correlate. Each connector's renderer (remediation/simulation/renderers.py)
turns this one description into that vendor's own response format.

What is invented and what is not:
  * Hosts, addresses, owners (team names only) and applications are fictional. Names end in
    `.corp.test` and addresses are in 10.0.0.0/8, so nothing here can be mistaken for a real
    organisation or reachable machine. No real company or person is named.
  * Every CVE id, title and CVSS v3 base score is a real, public vulnerability (NVD / the vendor
    advisory). No CVE number is made up. Scanner plugin ids, Qualys QIDs and OpenVAS OIDs are
    SYNTHETIC identifiers of the simulation (a scanner's own numbering is not a CVE); they are
    stable so a re-run is idempotent.
  * Dates are derived from REFERENCE_DATE, never from the clock, so two runs on different days
    produce byte-identical data.

build(seed=1, size="small"|"medium") returns an Estate. The same arguments always give the same estate.
"""
import datetime
import random

REFERENCE_DATE = datetime.date(2026, 8, 2)
DOMAIN = "corp.test"
SIZES = ("small", "medium")

# The operating system strings are chosen so remediation/ingest/classify.py classifies them as the intended asset type.
# (role, family, os, count small, count medium, internet facing, listening port)
_HOST_PLAN = [
    ("dc", "windows", "Microsoft Windows Server 2019 Datacenter", 2, 4, False, 445),
    ("fs", "windows", "Microsoft Windows Server 2016 Standard", 2, 5, False, 445),
    ("app-win", "windows", "Microsoft Windows Server 2022 Standard", 1, 4, False, 3389),
    ("web", "linux", "Ubuntu Linux 20.04", 3, 9, True, 443),
    ("db", "linux", "Red Hat Enterprise Linux 8.4", 1, 4, False, 5432),
    ("app", "linux", "Ubuntu Linux 22.04", 1, 6, False, 8080),
    ("sw", "network", "Cisco IOS XE 17.3", 1, 2, False, 443),
    ("fw", "firewall", "PAN-OS 10.2", 1, 2, True, 443),
]
_OWNER_TEAMS = {"windows": "Windows Platform", "linux": "Linux Platform", "network": "Network Operations", "firewall": "Network Security"}

# The vulnerability catalogue: real public CVEs with their well-known titles and CVSS v3 base scores.
# families: which host families can carry it; roles (optional): restricts to certain roles.
VULNERABILITIES = [
    {"key": "printnightmare", "cve": "CVE-2021-34527", "cvss": 8.8, "families": ["windows"], "port": 445, "protocol": "tcp",
     "title": "MS Windows Print Spooler Remote Code Execution (PrintNightmare)",
     "synopsis": "The Windows Print Spooler service allows remote authenticated users to execute arbitrary code with SYSTEM privileges.",
     "solution": "Apply the Microsoft security update for CVE-2021-34527 or disable the Print Spooler service on servers that do not need printing."},
    {"key": "eternalblue", "cve": "CVE-2017-0144", "cvss": 8.1, "families": ["windows"], "roles": ["fs", "dc"], "port": 445, "protocol": "tcp",
     "title": "MS17-010: SMBv1 Remote Code Execution (EternalBlue)",
     "synopsis": "The SMBv1 server on the remote host has remote code execution vulnerabilities.",
     "solution": "Apply the MS17-010 security update and disable SMBv1; use SMBv2 or SMBv3."},
    {"key": "mshtml", "cve": "CVE-2024-30040", "cvss": 8.8, "families": ["windows"], "port": 0, "protocol": "tcp",
     "title": "Windows MSHTML Platform Security Feature Bypass",
     "synopsis": "A security feature bypass exists in the Windows MSHTML platform.",
     "solution": "Install the Windows update that addresses CVE-2024-30040."},
    {"key": "zerologon", "cve": "CVE-2020-1472", "cvss": 10.0, "families": ["windows"], "roles": ["dc"], "port": 445, "protocol": "tcp",
     "title": "Netlogon Elevation of Privilege Vulnerability (Zerologon)",
     "synopsis": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller.",
     "solution": "Install the August 2020 and later Netlogon security updates and enforce secure RPC."},
    {"key": "bluekeep", "cve": "CVE-2019-0708", "cvss": 9.8, "families": ["windows"], "roles": ["app-win", "fs"], "port": 3389, "protocol": "tcp",
     "title": "Remote Desktop Services Remote Code Execution (BlueKeep)",
     "synopsis": "A remote code execution vulnerability exists in Remote Desktop Services when an unauthenticated attacker connects and sends crafted requests.",
     "solution": "Install the Microsoft security update for CVE-2019-0708 and enable Network Level Authentication."},
    {"key": "sudo-baron", "cve": "CVE-2021-3156", "cvss": 7.8, "families": ["linux"], "port": 0, "protocol": "tcp",
     "title": "Sudo Heap-Based Buffer Overflow (Baron Samedit)",
     "synopsis": "A heap-based buffer overflow in sudo before 1.9.5p2 allows local privilege escalation to root.",
     "solution": "Upgrade sudo to 1.9.5p2 or later with the distribution package manager."},
    {"key": "openssl-0778", "cve": "CVE-2022-0778", "cvss": 7.5, "families": ["linux"], "port": 443, "protocol": "tcp",
     "title": "OpenSSL BN_mod_sqrt() Infinite Loop Denial of Service",
     "synopsis": "A crafted certificate can cause the OpenSSL BN_mod_sqrt() function to loop forever, a denial of service.",
     "solution": "Upgrade OpenSSL to 1.1.1n, 3.0.2 or later, or apply the distribution's patched package."},
    {"key": "dirty-pipe", "cve": "CVE-2022-0847", "cvss": 7.8, "families": ["linux"], "port": 0, "protocol": "tcp",
     "title": "Linux Kernel Dirty Pipe Local Privilege Escalation",
     "synopsis": "A flaw in the Linux kernel pipe buffer handling lets an unprivileged local user overwrite data in read-only files.",
     "solution": "Update the kernel to 5.16.11, 5.15.25, 5.10.102 or later and reboot."},
    {"key": "regresshion", "cve": "CVE-2024-6387", "cvss": 8.1, "families": ["linux"], "roles": ["web", "app"], "port": 22, "protocol": "tcp",
     "title": "OpenSSH Signal Handler Race Condition (regreSSHion)",
     "synopsis": "A race condition in the OpenSSH server (sshd) can allow unauthenticated remote code execution on glibc-based Linux systems.",
     "solution": "Upgrade OpenSSH to 9.8p1 or later, or apply the distribution's patched package."},
    {"key": "log4shell", "cve": "CVE-2021-44228", "cvss": 10.0, "families": ["linux"], "roles": ["app"], "port": 8080, "protocol": "tcp",
     "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
     "synopsis": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI endpoints, allowing remote code execution.",
     "solution": "Upgrade Apache Log4j2 to 2.17.1 or later."},
    {"key": "spring4shell", "cve": "CVE-2022-22965", "cvss": 9.8, "families": ["linux"], "roles": ["app"], "port": 8080, "protocol": "tcp",
     "title": "Spring Framework Remote Code Execution (Spring4Shell)",
     "synopsis": "A Spring MVC or WebFlux application running on JDK 9+ may be vulnerable to remote code execution through data binding.",
     "solution": "Upgrade Spring Framework to 5.3.18, 5.2.20 or later."},
    {"key": "apache-41773", "cve": "CVE-2021-41773", "cvss": 7.5, "families": ["linux"], "roles": ["web"], "port": 443, "protocol": "tcp",
     "title": "Apache HTTP Server 2.4.49 Path Traversal",
     "synopsis": "A flaw in path normalisation in Apache HTTP Server 2.4.49 allows an attacker to map URLs to files outside the document root.",
     "solution": "Upgrade Apache HTTP Server to 2.4.51 or later."},
    {"key": "http2-reset", "cve": "CVE-2023-44487", "cvss": 7.5, "families": ["linux"], "roles": ["web"], "port": 443, "protocol": "tcp",
     "title": "HTTP/2 Rapid Reset Denial of Service",
     "synopsis": "The HTTP/2 protocol allows a denial of service through rapid stream resets.",
     "solution": "Apply the vendor update for the web server or proxy, or limit concurrent HTTP/2 streams."},
    {"key": "iosxe-20198", "cve": "CVE-2023-20198", "cvss": 10.0, "families": ["network"], "port": 443, "protocol": "tcp",
     "title": "Cisco IOS XE Web UI Privilege Escalation",
     "synopsis": "A vulnerability in the web UI feature of Cisco IOS XE Software allows a remote unauthenticated attacker to create an account with privilege level 15.",
     "solution": "Upgrade to a fixed Cisco IOS XE release and disable the HTTP server feature if it is not required."},
    {"key": "panos-3400", "cve": "CVE-2024-3400", "cvss": 10.0, "families": ["firewall"], "port": 443, "protocol": "tcp",
     "title": "PAN-OS GlobalProtect Command Injection",
     "synopsis": "A command injection vulnerability in the GlobalProtect feature of PAN-OS allows an unauthenticated attacker to execute code with root privileges on the firewall.",
     "solution": "Upgrade PAN-OS to a fixed hotfix release and apply the vendor's mitigations."},
]


def severity_for(cvss):
    return "Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium" if cvss >= 4.0 else "Low"


def qualys_level(cvss):
    """Qualys's own 1-5 severity scale chosen so the connector's mapping gives the same band as the CVSS score."""
    return 5 if cvss >= 9.0 else 4 if cvss >= 7.0 else 3 if cvss >= 4.0 else 2


def _stamp(date, hour=3):
    return f"{date.isoformat()}T{hour:02d}:00:00Z"


class Estate:
    """The generated estate. Plain dicts and lists throughout, so it is easy to serialise and to read in a test."""

    def __init__(self, seed, size, hosts, applications, vulnerabilities, detections, coverage):
        self.seed = seed
        self.size = size
        self.reference_date = REFERENCE_DATE
        self.hosts = hosts
        self.applications = applications
        self.vulnerabilities = vulnerabilities
        self.detections = detections
        self.coverage = coverage  # source -> list of host ids that source can see
        self._hosts = {h["id"]: h for h in hosts}
        self._vulns = {v["key"]: v for v in vulnerabilities}

    def host(self, host_id):
        return self._hosts[host_id]

    def vulnerability(self, key):
        return self._vulns[key]

    def hosts_for(self, source):
        seen = set(self.coverage.get(source, []))
        return [h for h in self.hosts if h["id"] in seen]

    def detections_for(self, source):
        """The (host, vulnerability, dates) rows the given source would report, in a stable order."""
        seen = set(self.coverage.get(source, []))
        out = []
        for d in self.detections:
            if d["host_id"] in seen:
                out.append({**d, "host": self._hosts[d["host_id"]], "vuln": self._vulns[d["vuln"]]})
        return out

    def host_names(self, source=None):
        hosts = self.hosts if source is None else self.hosts_for(source)
        return sorted(h["fqdn"] for h in hosts)

    def to_dict(self):
        return {"seed": self.seed, "size": self.size, "reference_date": self.reference_date.isoformat(), "hosts": self.hosts,
                "applications": self.applications, "vulnerabilities": self.vulnerabilities, "detections": self.detections,
                "coverage": self.coverage}


def build(seed=1, size="small"):
    if size not in SIZES:
        raise ValueError(f"size must be one of {', '.join(SIZES)}")
    rng = random.Random(f"quanta-estate:{seed}:{size}")
    col = 1 if size == "small" else 2
    hosts = []
    counter = {}
    for role, family, os_name, n_small, n_medium, internet, port in _HOST_PLAN:
        for _ in range(n_small if size == "small" else n_medium):
            counter[role] = counter.get(role, 0) + 1
            n = counter[role]
            name = f"{role}-{n:02d}"
            idx = len(hosts) + 1
            hosts.append({
                "id": f"H{idx:03d}", "name": name, "fqdn": f"{name}.{DOMAIN}", "ip": f"10.{20 + col * 10 + (idx % 4)}.{idx // 4 + 1}.{10 + idx}",
                "mac": "02:00:0a:%02x:%02x:%02x" % (idx // 256, idx % 256, rng.randint(0, 255)),
                "role": role, "family": family, "os": os_name, "internet_facing": internet, "port": port,
                "owner_team": _OWNER_TEAMS[family], "environment": "production" if rng.random() < 0.8 else "staging",
            })
    # applications run on the application and web tiers; the same owner teams, no individuals
    apps = []
    web = [h["id"] for h in hosts if h["role"] == "web"]
    app = [h["id"] for h in hosts if h["role"] == "app"]
    db = [h["id"] for h in hosts if h["role"] == "db"]
    for i, (aname, tier, crit) in enumerate([("Customer Portal", web, "high"), ("Order Service", app, "high"), ("Reporting", app + db, "medium")]):
        if tier:
            apps.append({"id": f"A{i + 1:02d}", "name": aname, "host_ids": tier[: 3 if size == "small" else 6], "business_criticality": crit,
                         "internet_facing": tier is web, "owner_team": "Application Engineering"})
    detections = []
    for h in hosts:
        candidates = [v for v in VULNERABILITIES if h["family"] in v["families"] and (not v.get("roles") or h["role"] in v["roles"])]
        if not candidates:
            continue
        for v in rng.sample(candidates, k=min(len(candidates), rng.randint(2, 4))):
            first = REFERENCE_DATE - datetime.timedelta(days=rng.randint(5, 120))
            last = REFERENCE_DATE - datetime.timedelta(days=rng.randint(0, 1))
            detections.append({"host_id": h["id"], "vuln": v["key"], "port": v["port"], "protocol": v["protocol"],
                               "first_seen": first.isoformat(), "last_seen": last.isoformat()})
    ids = [h["id"] for h in hosts]
    core = ids[:5]  # these five are seen by every scanner, so cross-scanner correlation always has something to join on
    coverage = {
        "tenable": list(ids),
        "qualys": core + [i for i in ids[5:] if rng.random() < 0.8],
        "openvas": core + [i for i in ids[5:] if rng.random() < 0.5],
        "prismacloud": [h["id"] for h in hosts if h["role"] in ("web", "app", "db")],
    }
    vulns = [dict(v, severity=severity_for(v["cvss"]), plugin_id=str(100000 + n), qid=str(370000 + n),
                  oid=f"1.3.6.1.4.1.25623.1.0.{900000 + n}") for n, v in enumerate(VULNERABILITIES, 1)]
    return Estate(seed, size, hosts, apps, vulns, detections, coverage)


def timestamp(date_text, hour=3):
    """ISO date text -> the full timestamp the vendors use (UTC)."""
    return _stamp(datetime.date.fromisoformat(date_text), hour)
