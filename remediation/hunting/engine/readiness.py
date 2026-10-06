"""
Which data sources a hunt needs, and whether Quanta knows one is connected.

Quanta only knows what is on the Connections page. A Cortex XSIAM pull connection means endpoint/XDR telemetry is flowing into a system Quanta can see; a Prisma
Cloud one means cloud posture and audit data. A Splunk search connection means Quanta can run a read-only search (after a person confirms) but says nothing about
WHICH log sources that Splunk holds. Everything else is "cannot tell": the absence of a connection is not evidence the data is missing, because your logs may be in
a system Quanta is not connected to. The engine never says "not connected" for that reason.
"""
CLASS_WORDS = (
    ("edr", ("process creation", "edr", "sysmon", "command-line", "command line", "auditd", "token and privilege", "sudo", "uac")),
    ("auth", ("authentication", "sign-in", "4624", "4625", "vpn", "identity provider", "logon")),
    ("web", ("web server", "waf", "application error", "access logs")),
    ("dns", ("dns",)),
    ("proxy", ("proxy",)),
    ("cloud", ("cloud", "cloudtrail", "audit log")),
    ("network", ("firewall", "flow", "netflow", "network", "smb", "rdp")),
)
CLASS_LABEL = {"edr": "EDR / endpoint telemetry", "auth": "Authentication logs", "web": "Web / WAF logs", "dns": "DNS logs", "proxy": "Web proxy logs",
               "cloud": "Cloud audit logs", "network": "Network / firewall / flow logs", "other": "Other logs"}
CONNECTED_BY = {"edr": ("cortex-xsiam",), "cloud": ("prismacloud",)}
SIEM_TYPES = ("splunk-search", "splunk")


def classify(source_text):
    low = source_text.lower()
    for cls, words in CLASS_WORDS:
        if any(w in low for w in words):
            return cls
    return "other"


def assess(source_names, connections):
    """-> {"sources": [...], "summary": {...}}. `connections` are the public connection dicts (type, enabled)."""
    on = {c["type"] for c in connections or [] if c.get("enabled")}
    siem = bool(on & set(SIEM_TYPES))
    run_here = "splunk-search" in on
    rows = []
    for name in source_names:
        cls = classify(name)
        have = [t for t in CONNECTED_BY.get(cls, ()) if t in on]
        if have:
            status, detail = "connected", f"A {have[0]} connection is enabled."
        elif siem:
            status, detail = "cannot-tell", "A SIEM connection exists, but Quanta cannot see which log sources it indexes."
        else:
            status, detail = "cannot-tell", "No connection tells Quanta whether this log source is collected. It may exist in a system Quanta is not connected to."
        rows.append({"name": name, "class": cls, "label": CLASS_LABEL[cls], "status": status, "detail": detail})
    if not rows:
        overall = "none-required"
    elif all(r["status"] == "connected" for r in rows):
        overall = "connected"
    elif any(r["status"] == "connected" for r in rows):
        overall = "partial"
    else:
        overall = "cannot-tell"
    return {"sources": rows, "summary": {"status": overall, "siem_connected": siem, "can_run_in_quanta": run_here,
                                         "note": "Quanta can run a lead for you only through a Splunk search connection, only after you confirm; otherwise run the query in your own tool and record the result."}}
