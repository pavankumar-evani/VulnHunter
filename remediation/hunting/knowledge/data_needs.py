"""What data a technique's detection needs, read from the catalog's own data components (never typed in per technique)."""
_COMPONENT_WORDS = (("dns", "dns"), ("email", "email"), ("message", "email"), ("internet scan", "external-exposure"), ("application log", "web-server"), ("web credential", "identity-provider"),
                    ("logon", "host-auth"), ("authentication", "host-auth"), ("user account", "host-auth"), ("active directory", "host-auth"), ("cloud", "cloud-audit"), ("instance", "cloud-audit"),
                    ("snapshot", "cloud-audit"), ("volume", "cloud-audit"), ("storage", "cloud-audit"), ("network", "network-flow"), ("firewall", "network-flow"), ("process", "endpoint"),
                    ("command", "endpoint"), ("module", "endpoint"), ("driver", "endpoint"), ("file", "endpoint"), ("registry", "endpoint"), ("script", "endpoint"), ("service", "endpoint"),
                    ("scheduled", "endpoint"), ("wmi", "endpoint"), ("pipe", "endpoint"), ("os api", "endpoint"), ("kernel", "endpoint"), ("firmware", "endpoint"), ("container", "endpoint"),
                    ("image", "endpoint"), ("group", "directory"), ("sensor", "ot-network"), ("asset", "ot-network"), ("user interface", "endpoint"))
_CLOUD_PLATFORMS = ("iaas", "saas", "office suite", "identity provider", "azure ad", "entra id", "google workspace", "office 365", "containers")


def classes_for_technique(c, tid, cap=4):
    """Data classes a technique's detection needs. ATLAS -> LLM/agent logs, ICS -> OT monitoring, Mobile -> MDM; Enterprise from its data components and platform."""
    t = c.technique(tid, detail=False)
    if not t:
        return []
    fw = t["framework"]
    if fw == "atlas":
        return ["ai-gateway"]
    if fw == "ics":
        return ["ot-network"]
    if fw == "mobile":
        return ["mobile-mdm"]
    cloudy = any(p.lower() in _CLOUD_PLATFORMS for p in t.get("platforms") or [])
    out = []
    for comp in t.get("data_sources") or []:
        low = comp.lower()
        for word, cls in _COMPONENT_WORDS:
            if word in low:
                if cloudy and cls == "host-auth" and ("authentication" in low or "user account" in low or "logon" in low):
                    cls = "identity-provider"
                if cls not in out:
                    out.append(cls)
                break
    return out[:cap]
