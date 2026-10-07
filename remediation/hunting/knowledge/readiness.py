"""
Data readiness for a hunt: which classes of data a hypothesis needs, and what Quanta can tell about whether each is collected.

Quanta is not a SIEM and holds no log text, so it can only infer. A class is
  connected   a connection on the Connections page proves the feed (for example a Cortex XSIAM connection for endpoint telemetry);
  data-held   Quanta itself holds that data (Access Governance entitlements for the directory, the attack-surface inventory for external exposure);
  alerts-seen alerts have arrived from a product that normally produces that data, so it probably exists in the tool that raised them (evidence, not proof);
  cannot-tell nothing Quanta holds says either way. This is the honest default: your logs may live in a system Quanta is not connected to.
It never says "missing" or "not connected". The overall status is `ready` (every needed class is connected or held), `partial` (some have evidence) or `cannot-tell`.
Uploaded log summaries are not retained by Quanta, so they cannot count as evidence.
"""
CLASS_LABEL = {
    "endpoint": "Endpoint telemetry (process, file, registry, module load)", "host-auth": "Host authentication logs (Windows Security, auditd, sudo)",
    "identity-provider": "Identity provider sign-in and audit logs", "email": "Email gateway and mailbox audit logs", "proxy": "Web proxy / secure web gateway logs", "dns": "DNS query logs",
    "network-flow": "Network flow, firewall and IDS logs", "cloud-audit": "Cloud control-plane audit logs", "cloud-billing": "Cloud billing and cost data", "saas-audit": "SaaS audit logs (M365, Workspace)",
    "file-activity": "File access and DLP / CASB activity", "vcs-ci": "Source-control and CI/CD audit logs", "ai-gateway": "LLM gateway, agent and MCP logs",
    "external-exposure": "Internet-facing asset inventory", "directory": "Directory, entitlement and HR roster data", "ot-network": "Passive OT network monitoring",
    "mobile-mdm": "Mobile device management events", "web-server": "Web server and WAF logs"}
WHAT_TO_CHECK = {
    "endpoint": "Confirm process creation with command lines (Sysmon or your EDR) is collected for the in-scope hosts and searchable for the look-back period.",
    "host-auth": "Confirm Windows Security events 4624/4625/4768/4769/4662 (or auditd/sudo on Linux) are forwarded from servers and domain controllers.",
    "identity-provider": "Confirm sign-in and audit logs from your identity provider are exported with source address, user agent, device and MFA result.",
    "email": "Confirm message trace, URL-click and mailbox audit logs are retained and searchable.",
    "proxy": "Confirm web proxy logs include URL, user, bytes out and referrer.", "dns": "Confirm DNS query logs from your resolvers record the client address and the full query name.",
    "network-flow": "Confirm firewall or flow logs (and any NDR or IDS) cover the segments in scope, with bytes and destination.",
    "cloud-audit": "Confirm control-plane logging is on in every account and region, including data events where a lead needs them (for example S3 object-level).",
    "cloud-billing": "Confirm daily cost and usage exports are delivered to a place you can search.", "saas-audit": "Confirm the unified audit log is enabled and retained.",
    "file-activity": "Confirm file access or DLP / CASB activity is collected for the repositories in scope.", "vcs-ci": "Confirm source-control and pipeline audit logs are exported.",
    "ai-gateway": "Confirm model gateway, agent trace and MCP tool-call logs are recorded with user, tool and arguments (never keep secrets in them).",
    "external-exposure": "Add the internet-facing assets to the attack-surface inventory.", "directory": "Load entitlements and the HR roster on the Access Governance page.",
    "ot-network": "Passive OT monitoring (a span port or sensor) must be in place; never probe controllers.", "mobile-mdm": "Confirm MDM events are exported.",
    "web-server": "Confirm web server access and WAF logs are collected."}
CONNECTION_PROVIDES = {"cortex-xsiam": ("endpoint",), "prismacloud": ("cloud-audit",), "active-directory": ("directory",), "github": ("vcs-ci",), "gitlab": ("vcs-ci",),
                       "anthropic-usage": ("ai-gateway",), "openai-usage": ("ai-gateway",)}
SIEM_TYPES = ("splunk-search", "splunk")
ALERT_SOURCE_WORDS = {
    "endpoint": ("crowdstrike", "falcon", "defender", "sentinelone", "edr", "xdr", "sysmon", "carbon black", "cortex", "cybereason", "tanium"),
    "identity-provider": ("okta", "entra", "azure ad", "azuread", "ping", "auth0", "duo", "identity"), "email": ("proofpoint", "mimecast", "exchange", "o365", "m365", "email", "abnormal"),
    "proxy": ("zscaler", "proxy", "netskope", "bluecoat", "secure web"), "dns": ("dns", "umbrella"),
    "network-flow": ("firewall", "palo alto", "fortinet", "zeek", "suricata", "ids", "ndr", "darktrace", "vectra", "netflow"),
    "cloud-audit": ("cloudtrail", "guardduty", "azure activity", "defender for cloud", "gcp", "security command", "wiz"), "saas-audit": ("casb", "google workspace", "salesforce", "slack"),
    "host-auth": ("windows security", "domain controller", "kerberos"), "ot-network": ("claroty", "nozomi", "dragos"), "mobile-mdm": ("intune", "jamf", "mdm"),
    "vcs-ci": ("github", "gitlab", "jenkins", "bitbucket"), "ai-gateway": ("llm", "openai", "anthropic", "bedrock"), "file-activity": ("dlp", "purview", "varonis"),
    "web-server": ("waf", "web server", "apache", "nginx")}
STRENGTH = {"connected": 3, "data-held": 3, "alerts-seen": 1, "cannot-tell": 0}


def signals(connections=None, alerts=None, entitlements=None, asm_assets=None):
    """What Quanta can see, as {class: {status, evidence: [..]}} plus siem flags. Each argument may be None (not held)."""
    out = {c: {"status": "cannot-tell", "evidence": []} for c in CLASS_LABEL}
    on = {c["type"] for c in connections or [] if c.get("enabled")}

    def raise_to(cls, status, why):
        if STRENGTH[status] > STRENGTH[out[cls]["status"]]:
            out[cls]["status"] = status
        out[cls]["evidence"].append(why)

    for t, classes in CONNECTION_PROVIDES.items():
        if t in on:
            for cls in classes:
                raise_to(cls, "connected", f"A {t} connection is enabled.")
    counts = {}
    for a in alerts or []:
        src = str(a.get("source") or "").lower()
        for cls, words in ALERT_SOURCE_WORDS.items():
            if any(w in src for w in words):
                counts.setdefault(cls, {})
                counts[cls][a.get("source")] = counts[cls].get(a.get("source"), 0) + 1
    for cls, srcs in counts.items():
        top = sorted(srcs.items(), key=lambda kv: -kv[1])[:2]
        raise_to(cls, "alerts-seen", "Alerts have arrived from " + ", ".join(f"{s} ({n})" for s, n in top) + ".")
    if entitlements:
        raise_to("directory", "data-held", f"{len(entitlements)} entitlement records are loaded in Access Governance.")
    if asm_assets:
        raise_to("external-exposure", "data-held", f"{asm_assets} internet-facing assets are in the attack-surface inventory.")
    return {"classes": out, "siem_connected": bool(on & set(SIEM_TYPES)), "can_run_in_quanta": "splunk-search" in on}


def assess(needed, sig):
    """-> {status, siem_connected, can_run_in_quanta, needs: [{class, label, status, evidence, what_to_check}], note}. `needed` is a list of data classes."""
    needed = [n for n in dict.fromkeys(needed or []) if n in CLASS_LABEL]
    rows = []
    for cls in needed:
        s = (sig or {}).get("classes", {}).get(cls) or {"status": "cannot-tell", "evidence": []}
        ev = list(s["evidence"]) or (["A SIEM connection exists, but Quanta cannot see which log sources it indexes."] if (sig or {}).get("siem_connected") else
                                     ["Nothing Quanta holds says whether this is collected. It may exist in a system Quanta is not connected to."])
        rows.append({"class": cls, "label": CLASS_LABEL[cls], "status": s["status"], "evidence": ev[:3], "what_to_check": WHAT_TO_CHECK.get(cls, "")})
    if not rows:
        status = "none-required"
    elif all(r["status"] in ("connected", "data-held") for r in rows):
        status = "ready"
    elif any(STRENGTH[r["status"]] > 0 for r in rows):
        status = "partial"
    else:
        status = "cannot-tell"
    return {"status": status, "siem_connected": bool((sig or {}).get("siem_connected")), "can_run_in_quanta": bool((sig or {}).get("can_run_in_quanta")), "needs": rows,
            "note": "Quanta infers readiness from connections, alerts and data it holds; it never says a source is missing. It can run a lead for you only through a Splunk search "
                    "connection, after you confirm; otherwise run the query in your own tool and record the result."}


def to_engine_shape(a):
    """The hunt engine's own `data_sources` rows and `data_readiness` summary, so a knowledge hypothesis reads like every other one."""
    rows = [{"name": r["label"], "class": r["class"], "label": r["label"], "status": "connected" if r["status"] in ("connected", "data-held") else "cannot-tell",
             "detail": " ".join(r["evidence"][:2]) + (f" ({r['status']})" if r["status"] == "alerts-seen" else "")} for r in a["needs"]]
    st = {"ready": "connected", "partial": "partial", "cannot-tell": "cannot-tell", "none-required": "none-required"}[a["status"]]
    return {"sources": rows, "summary": {"status": st, "siem_connected": a["siem_connected"], "can_run_in_quanta": a["can_run_in_quanta"], "note": a["note"]}}
