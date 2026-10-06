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


# Devices the vulnerability scanners do NOT see (no agent, no scan credentials): they show up only in the asset sources
# (Infoblox, Axonius, Active Directory), which is exactly what makes those sources worth connecting. Fictional, corp.test.
_UNMANAGED_PLAN = [
    ("ws-01", "workstation", "Windows 11 Enterprise", "Endpoint Operations"),
    ("ws-02", "workstation", "Windows 11 Enterprise", "Endpoint Operations"),
    ("ws-03", "workstation", "Windows 10 Enterprise", "Endpoint Operations"),  # stale: disabled in the directory
    ("cam-01", "iot", "Embedded Linux", "Facilities"),
]

# Cloud posture policies the simulated Prisma Cloud tenant evaluates (generic, AWS-style posture rules). `kind` says what resource they apply to.
POSTURE_POLICIES = [
    {"key": "sg-ssh", "name": "AWS Security Group allows internet traffic to SSH port (22)", "severity": "high", "kind": "instance", "roles": ["web", "app", "db"],
     "description": "A security group attached to the instance allows inbound SSH from 0.0.0.0/0, exposing the administrative port to the internet."},
    {"key": "ebs-unencrypted", "name": "AWS EBS volume is not encrypted", "severity": "medium", "kind": "instance", "roles": ["web", "app", "db"],
     "description": "An EBS volume attached to the instance is not encrypted at rest."},
    {"key": "imds-v1", "name": "AWS EC2 instance is not enforcing IMDSv2", "severity": "medium", "kind": "instance", "roles": ["web", "app"],
     "description": "The instance metadata service accepts IMDSv1 requests, which are exposed to server-side request forgery."},
    {"key": "rds-public", "name": "AWS RDS database instance is publicly accessible", "severity": "critical", "kind": "instance", "roles": ["db"],
     "description": "The database instance is reachable from the internet."},
    {"key": "s3-public", "name": "AWS S3 bucket is publicly readable", "severity": "high", "kind": "bucket", "roles": [],
     "description": "The bucket policy or ACL allows public read access to its objects."},
    {"key": "s3-logging", "name": "AWS S3 bucket has server access logging disabled", "severity": "low", "kind": "bucket", "roles": [],
     "description": "Server access logging is not enabled, so requests to the bucket are not recorded."},
    {"key": "flowlogs", "name": "AWS VPC flow logs are not enabled", "severity": "medium", "kind": "vpc", "roles": [],
     "description": "Flow logs are not enabled on the VPC, so network traffic cannot be investigated after an incident."},
    {"key": "iam-mfa", "name": "AWS IAM user has console access without MFA", "severity": "high", "kind": "iam", "roles": [],
     "description": "An IAM user can sign in to the console with a password only, with no multi-factor authentication."},
]
_CLOUD_ONLY = [("bucket", "reports-archive-corp-test"), ("bucket", "portal-uploads-corp-test"), ("vpc", "vpc-corp-test-prod"), ("iam", "svc-deploy-corp-test")]

# What the simulated Cortex XSIAM tenant raises for exploitation of each catalogued vulnerability: (incident name, severity, MITRE ATT&CK technique).
INCIDENT_PLAN = {
    "printnightmare": ("Suspicious child process of the Print Spooler service", "high", "T1068 - Exploitation for Privilege Escalation"),
    "eternalblue": ("SMBv1 exploit attempt detected", "critical", "T1210 - Exploitation of Remote Services"),
    "zerologon": ("Netlogon secure channel anomaly on a domain controller", "critical", "T1210 - Exploitation of Remote Services"),
    "bluekeep": ("Anomalous inbound RDP connection attempt", "high", "T1210 - Exploitation of Remote Services"),
    "sudo-baron": ("Local privilege escalation attempt through sudo", "high", "T1068 - Exploitation for Privilege Escalation"),
    "dirty-pipe": ("Local privilege escalation attempt through the kernel", "high", "T1068 - Exploitation for Privilege Escalation"),
    "regresshion": ("Repeated sshd connection timeouts", "medium", "T1190 - Exploit Public-Facing Application"),
    "log4shell": ("JNDI lookup string in an inbound HTTP request", "critical", "T1190 - Exploit Public-Facing Application"),
    "spring4shell": ("Possible Spring4Shell exploit attempt", "high", "T1190 - Exploit Public-Facing Application"),
    "apache-41773": ("Path traversal request to a web server", "medium", "T1190 - Exploit Public-Facing Application"),
    "iosxe-20198": ("Unexpected administrative account created on a network device", "high", "T1190 - Exploit Public-Facing Application"),
    "panos-3400": ("Command injection attempt against GlobalProtect", "critical", "T1190 - Exploit Public-Facing Application"),
}

# The AI usage the simulated organisation generates: which models each application's workspace/project calls (real public model ids).
AI_MODELS = {
    "anthropic": {"Customer Portal": ["claude-3-5-haiku-20241022", "claude-sonnet-4-20250514"], "Order Service": ["claude-sonnet-4-20250514"],
                  "Reporting": ["claude-sonnet-4-20250514", "claude-opus-4-1-20250805"]},
    "openai": {"Customer Portal": ["gpt-4o-mini"], "Order Service": ["gpt-4.1", "gpt-4o-mini"], "Reporting": ["gpt-4.1"]},
}


def slug(text):
    return "".join(c if c.isalnum() else "_" for c in text.lower()).strip("_")


def epoch_ms(date_text, hour=3):
    import calendar
    d = datetime.date.fromisoformat(date_text)
    return (calendar.timegm(d.timetuple()) + hour * 3600) * 1000


def severity_for(cvss):
    return "Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium" if cvss >= 4.0 else "Low"


def qualys_level(cvss):
    """Qualys's own 1-5 severity scale chosen so the connector's mapping gives the same band as the CVSS score."""
    return 5 if cvss >= 9.0 else 4 if cvss >= 7.0 else 3 if cvss >= 4.0 else 2


def _stamp(date, hour=3):
    return f"{date.isoformat()}T{hour:02d}:00:00Z"


class Estate:
    """The generated estate. Plain dicts and lists throughout, so it is easy to serialise and to read in a test."""

    def __init__(self, seed, size, hosts, applications, vulnerabilities, detections, coverage, unmanaged=None, cloud_alerts=None, incidents=None):
        self.seed = seed
        self.size = size
        self.reference_date = REFERENCE_DATE
        self.hosts = hosts
        self.applications = applications
        self.vulnerabilities = vulnerabilities
        self.detections = detections
        self.coverage = coverage  # source -> list of host ids that source can see
        self.unmanaged = unmanaged or []  # devices only the asset sources know about
        self.cloud_alerts = cloud_alerts or []  # Prisma Cloud posture alerts (a resource is a host fqdn or a cloud-only resource)
        self.incidents = incidents or []  # Cortex XSIAM incidents referencing host fqdns
        self._hosts = {h["id"]: h for h in hosts}
        self._vulns = {v["key"]: v for v in vulnerabilities}

    def now(self):
        """The fixed 'current time' every simulated clock-dependent call uses (noon UTC on the reference date); never the real clock."""
        return datetime.datetime.combine(self.reference_date, datetime.time(12, 0), tzinfo=datetime.timezone.utc)

    def usage_workspaces(self, provider):
        """[(application name, workspace/project id, key id, [models])] for an AI provider, one per estate application."""
        out = []
        for a in self.applications:
            models = AI_MODELS[provider].get(a["name"]) or []
            if models:
                out.append((a["name"], f"{'wrkspc' if provider == 'anthropic' else 'proj'}_sim_{slug(a['name'])}", f"apikey_sim_{slug(a['name'])}_01", models))
        return out

    def usage_for(self, provider, date, app_name, workspace, model):
        """One day's usage numbers for one application and model: a pure function of (seed, provider, date, workspace, model)."""
        rng = random.Random(f"quanta-usage:{self.seed}:{provider}:{date.isoformat()}:{workspace}:{model}")
        factor = 0.3 if date.weekday() >= 5 else 1.0
        if "opus" in model or "gpt-4.1" == model:
            factor *= 0.4  # the expensive models are used sparingly
        requests_n = max(1, int(rng.randint(400, 3000) * factor))
        return {"requests": requests_n, "uncached_input": int(requests_n * rng.randint(300, 900)), "output": int(requests_n * rng.randint(80, 400)),
                "cache_read": int(requests_n * rng.randint(0, 2500)), "cache_5m": int(requests_n * rng.randint(0, 200)),
                "cache_1h": int(requests_n * rng.randint(0, 40))}

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
                "coverage": self.coverage, "unmanaged": self.unmanaged, "cloud_alerts": self.cloud_alerts, "incidents": self.incidents}


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
    # Everything below uses its own generators so adding a source never changes the hosts and detections above (a re-run stays byte-identical).
    unmanaged = _build_unmanaged(seed, size)
    coverage["infoblox"] = list(ids)
    coverage["axonius"] = list(ids)
    coverage["active-directory"] = [h["id"] for h in hosts if h["family"] == "windows"]
    coverage["cortex-xsiam"] = [h["id"] for h in hosts if h["family"] in ("windows", "linux")]
    return Estate(seed, size, hosts, apps, vulns, detections, coverage, unmanaged=unmanaged,
                  cloud_alerts=_build_cloud_alerts(seed, size, hosts), incidents=_build_incidents(seed, size, hosts, detections, coverage["cortex-xsiam"]))


def _build_unmanaged(seed, size):
    rng = random.Random(f"quanta-estate-unmanaged:{seed}:{size}")
    out = []
    for n, (name, family, os_name, team) in enumerate(_UNMANAGED_PLAN, 1):
        out.append({"id": f"U{n:03d}", "name": name, "fqdn": f"{name}.{DOMAIN}", "ip": f"10.90.{n}.{20 + n}", "mac": "02:00:0a:%02x:%02x:%02x" % (0xf0, n, rng.randint(0, 255)),
                    "family": family, "os": os_name, "owner_team": team, "enabled": name != "ws-03"})
    return out


def _build_cloud_alerts(seed, size, hosts):
    rng = random.Random(f"quanta-estate-cloud:{seed}:{size}")
    account = "111122223333"
    alerts = []

    def add(policy, host, rtype, rid, rname):
        n = len(alerts) + 1
        first = REFERENCE_DATE - datetime.timedelta(days=rng.randint(3, 90))
        last = REFERENCE_DATE - datetime.timedelta(days=rng.randint(0, 1))
        alerts.append({"id": f"P-{10000 + n}", "policy": policy["key"], "host_id": host["id"] if host else None, "status": "resolved" if n % 7 == 0 else "open",
                       "resource": {"id": rid, "name": rname, "cloudType": "aws", "region": "us-east-1", "account": account, "resourceType": rtype},
                       "first_seen": first.isoformat(), "last_seen": last.isoformat()})

    for h in hosts:
        if h["role"] not in ("web", "app", "db"):
            continue
        cands = [p for p in POSTURE_POLICIES if p["kind"] == "instance" and h["role"] in p["roles"]]
        for p in rng.sample(cands, k=min(len(cands), rng.randint(1, 2))):
            add(p, h, "Instance", f"arn:aws:ec2:us-east-1:{account}:instance/i-{rng.getrandbits(68):017x}", h["fqdn"])
    for kind, name in _CLOUD_ONLY:
        cands = [p for p in POSTURE_POLICIES if p["kind"] == kind]
        rid = {"bucket": f"arn:aws:s3:::{name}", "vpc": f"arn:aws:ec2:us-east-1:{account}:vpc/vpc-{rng.getrandbits(32):08x}",
               "iam": f"arn:aws:iam::{account}:user/{name}"}[kind]
        for p in rng.sample(cands, k=min(len(cands), rng.randint(1, 2))):
            add(p, None, {"bucket": "Bucket", "vpc": "VPC", "iam": "IAM User"}[kind], rid, name)
    return alerts


def _build_incidents(seed, size, hosts, detections, covered):
    rng = random.Random(f"quanta-estate-incidents:{seed}:{size}")
    by_id = {h["id"]: h for h in hosts}
    seen = set(covered)
    out = []
    for key, (name, severity, technique) in INCIDENT_PLAN.items():
        hit = [d for d in detections if d["vuln"] == key and d["host_id"] in seen]
        for i in range(0, len(hit), 2):
            if rng.random() < 0.35:
                continue  # not every exposed host is attacked
            group = hit[i:i + 2]
            last = max(datetime.date.fromisoformat(d["last_seen"]) for d in group)
            created = last - datetime.timedelta(days=rng.randint(0, 3))
            n = len(out) + 1
            names = [by_id[d["host_id"]]["fqdn"] for d in group]
            out.append({"incident_id": str(5000 + n), "incident_name": f"{name} on {names[0]}" + (f" and {len(names) - 1} other host" if len(names) > 1 else ""),
                        "description": f"Correlated detection across {len(names)} host(s): {', '.join(names)}.", "severity": severity,
                        "status": rng.choice(["new", "under_investigation", "under_investigation", "resolved_true_positive"]),
                        "hosts": names, "alert_count": rng.randint(1, 6), "mitre": [technique], "vuln": key,
                        "creation_time": created.isoformat(), "modification_time": (created + datetime.timedelta(days=rng.randint(0, 1))).isoformat()})
    return out


def timestamp(date_text, hour=3):
    """ISO date text -> the full timestamp the vendors use (UTC)."""
    return _stamp(datetime.date.fromisoformat(date_text), hour)
