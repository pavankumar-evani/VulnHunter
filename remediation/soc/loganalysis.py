"""
Log investigation: paste or load log lines on a case and get structure, anomalies and technique suggestions back. Everything is classical statistics on the text
given; nothing is sent anywhere and no model is called.

Parsing. Each line is read as JSON, or as key=value pairs, or as plain text; a leading timestamp (ISO 8601 or 'YYYY-MM-DD HH:MM:SS') is taken when present. At most
MAX_LINES lines are read.

Findings (each says how it was found, so an analyst can judge it):
  top values      most common users, hosts, source and destination addresses, processes
  rare values     values seen once in a field where other values repeat (a lone process name among many)
  bursts          events per minute with a z-score above 3 and at least 10 events (mean and standard deviation of the per-minute counts)
  beaconing       a source/destination pair with 6 or more events at near-regular intervals: coefficient of variation (std/mean) of the gaps below 0.2 and mean gap of 5 s or more
  auth pattern    5 or more failed sign-ins for an account or address followed by a success (the usual shape of a guessed or sprayed password)
  indicators      addresses, domains, hashes and CVEs found in the text (the same extractor the alert intake uses), private addresses excluded
  techniques      ATT&CK techniques suggested by the TTP classifier from the lines that look most like attacker activity, with the evidence words

Limits: a regular interval can be a legitimate health check; a burst can be a deployment; a rare value is rare, not malicious. The output is a list of things to look at.
"""
import datetime
import json
import math
import re
import statistics

from remediation.hunting import ocsf, ttp

MAX_LINES = 20000
TS = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
KV = re.compile(r'([A-Za-z_][\w.\-]*)=("[^"]*"|\S+)')
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAIL = re.compile(r"\b(failed|failure|invalid password|4625|denied|bad password|authentication failure)\b", re.I)
OK = re.compile(r"\b(accepted|4624|logon success|logged on|login success|authenticated|successful)\b", re.I)
SRC_KEYS = ("src", "src_ip", "source", "source_ip", "srcip", "client_ip", "ip")
DST_KEYS = ("dst", "dst_ip", "dest", "dest_ip", "destination", "destination_ip", "dstip", "host")
USER_KEYS = ("user", "username", "account", "user_name", "targetusername")
PROC_KEYS = ("process", "process_name", "image", "exe", "command", "cmd", "commandline", "command_line")
SUSPICIOUS = re.compile(r"(powershell|cmd\.exe|wmic|certutil|bitsadmin|mshta|rundll32|regsvr32|vssadmin|mimikatz|procdump|psexec|schtasks|net user|whoami|nltest|curl|wget|base64|-enc)", re.I)


def _ts(line):
    m = TS.search(line)
    if not m:
        return None
    return datetime.datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")


def parse(text):
    rows = []
    for i, raw in enumerate((text or "").splitlines()[:MAX_LINES]):
        line = raw.strip()
        if not line:
            continue
        fields = {}
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                fields = {str(k).lower(): str(v) for k, v in obj.items() if not isinstance(v, (dict, list))}
            except ValueError:
                pass
        if not fields:
            fields = {k.lower(): v.strip('"') for k, v in KV.findall(line)}
        ts = _ts(fields.get("timestamp") or fields.get("time") or fields.get("@timestamp") or "") or _ts(line)
        rows.append({"n": i + 1, "raw": line[:500], "fields": fields, "ts": ts})
    return rows


def _first(fields, keys):
    for k in keys:
        if fields.get(k):
            return fields[k]
    return None


def _ends(r):
    src, dst = _first(r["fields"], SRC_KEYS), _first(r["fields"], DST_KEYS)
    if not (src and dst):
        ips = IP.findall(r["raw"])
        if len(ips) >= 2:
            src, dst = src or ips[0], dst or ips[1]
    return src, dst


def _top(counter, n=5):
    return [{"value": k, "count": v} for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def analyse(text, examples=()):
    rows = parse(text)
    if not rows:
        return {"lines": 0, "note": "No log lines to analyse"}
    counters = {"users": {}, "sources": {}, "destinations": {}, "processes": {}}
    for r in rows:
        f = r["fields"]
        for name, keys in (("users", USER_KEYS), ("processes", PROC_KEYS)):
            v = _first(f, keys)
            if v:
                counters[name][v[:120]] = counters[name].get(v[:120], 0) + 1
        s, d = _ends(r)
        if s:
            counters["sources"][s] = counters["sources"].get(s, 0) + 1
        if d:
            counters["destinations"][d] = counters["destinations"].get(d, 0) + 1
    out = {"lines": len(rows), "with_timestamp": sum(1 for r in rows if r["ts"]), "top": {k: _top(v) for k, v in counters.items()}}

    rare = []
    for name, c in counters.items():
        if len(c) >= 4 and max(c.values()) >= 3:
            rare += [{"field": name, "value": k} for k, v in c.items() if v == 1][:5]
    out["rare"] = rare[:15]

    # bursts
    per_min = {}
    for r in rows:
        if r["ts"]:
            k = r["ts"].replace(second=0)
            per_min[k] = per_min.get(k, 0) + 1
    bursts = []
    if len(per_min) >= 5:
        counts = list(per_min.values())
        mu, sd = statistics.mean(counts), statistics.pstdev(counts)
        if sd > 0:
            for k, v in sorted(per_min.items()):
                z = (v - mu) / sd
                if z > 3 and v >= 10:
                    bursts.append({"minute": k.strftime("%Y-%m-%dT%H:%MZ"), "events": v, "z_score": round(z, 1), "baseline_mean": round(mu, 1)})
    out["bursts"] = bursts

    # beaconing
    pairs = {}
    for r in rows:
        s, d = _ends(r)
        if s and d and r["ts"]:
            pairs.setdefault((s, d), []).append(r["ts"])
    beacons = []
    for (s, d), stamps in pairs.items():
        if len(stamps) < 6:
            continue
        stamps.sort()
        gaps = [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])]
        mean = statistics.mean(gaps)
        if mean < 5:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv < 0.2:
            beacons.append({"source": s, "destination": d, "events": len(stamps), "mean_interval_seconds": round(mean, 1), "regularity_cv": round(cv, 3)})
    out["beaconing"] = sorted(beacons, key=lambda b: b["regularity_cv"])[:5]

    # fail-then-success
    state, auth = {}, []
    for r in rows:
        who = _first(r["fields"], USER_KEYS) or _first(r["fields"], SRC_KEYS)
        if not who:
            ips = IP.findall(r["raw"])
            who = ips[0] if ips else None
        if not who:
            continue
        st = state.setdefault(who, {"fails": 0, "reported": False})
        if FAIL.search(r["raw"]):
            st["fails"] += 1
        elif OK.search(r["raw"]):
            if st["fails"] >= 5 and not st["reported"]:
                auth.append({"who": who, "failures_before_success": st["fails"], "success_line": r["n"]})
                st["reported"] = True
            st["fails"] = 0
    out["auth_pattern"] = auth

    # indicators and techniques
    ents = ocsf.scan_text("\n".join(r["raw"] for r in rows[:2000]))
    out["indicators"] = {k: v for k, v in ents.items() if v and k in ("ips", "domains", "hashes", "cves", "urls")}
    cand = [r for r in rows if SUSPICIOUS.search(r["raw"])] or rows
    text_for_ttp = " ".join(r["raw"] for r in cand[:60])
    res = ttp.classify(text_for_ttp, examples)
    out["techniques"] = [t for t in res["techniques"] if t["probability"] >= 0.2][:3]
    out["techniques_confident"] = res["confident"]
    out["suspicious_lines"] = [{"n": r["n"], "line": r["raw"][:240]} for r in rows if SUSPICIOUS.search(r["raw"])][:10]
    out["caveat"] = "Statistics on the lines given. A regular interval may be a health check, a burst a deployment, a rare value merely rare: these are leads to check."
    return out
