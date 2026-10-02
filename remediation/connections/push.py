"""
Push connections: send the findings that matter to a ticketing or logging system, and read the
ticket state back.

A stored push connection (ServiceNow, Jira, Splunk) carries a *rule* that decides which
findings are sent, so "create an incident for every new Critical or KEV finding" is a setting,
not a script:

    rule = {min_severity: "High", kev_only: false, min_epss: null, max_per_run: 50}

Each run:
  1. picks findings that match the rule and have not been pushed through this connection yet,
     most urgent first (KEV, then EPSS, then severity), at most `max_per_run`;
  2. creates the ticket (ServiceNow and Jira are idempotent: they look for an existing one
     keyed on the finding id first, so a re-run never duplicates) or sends the event (Splunk
     is an append-only stream, so each finding is sent once);
  3. records a link (finding <-> ticket reference) so the finding shows its ticket;
  4. for ServiceNow and Jira, refreshes the state of the still-open linked tickets and mirrors
     it onto the finding's assignment (see links.py).

One failing finding never aborts the batch; its error is stored on its link and the finding is
retried on the next run.
"""
from remediation.connections import links
from remediation.ingest import merge

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
DEFAULT_RULE = {"min_severity": "High", "kev_only": False, "min_epss": None, "max_per_run": 50}


def normalise_rule(rule):
    rule = {**DEFAULT_RULE, **(rule or {})}
    if rule["min_severity"] not in SEVERITY_RANK:
        raise ValueError("min_severity must be Critical, High, Medium or Low")
    try:
        rule["max_per_run"] = int(rule["max_per_run"])
    except (TypeError, ValueError):
        raise ValueError("max_per_run must be a whole number") from None
    if not 1 <= rule["max_per_run"] <= 500:
        raise ValueError("max_per_run must be between 1 and 500")
    if rule["min_epss"] not in (None, ""):
        try:
            rule["min_epss"] = float(rule["min_epss"])
        except (TypeError, ValueError):
            raise ValueError("min_epss must be a number between 0 and 1") from None
        if not 0 <= rule["min_epss"] <= 1:
            raise ValueError("min_epss must be between 0 and 1")
    else:
        rule["min_epss"] = None
    rule["kev_only"] = bool(rule["kev_only"])
    return rule


def matches(finding, rule):
    if SEVERITY_RANK.get(finding.get("severity"), 0) < SEVERITY_RANK[rule["min_severity"]]:
        return False
    kev = (finding.get("kev") or {}).get("listed")
    if rule["kev_only"] and not kev:
        return False
    if rule["min_epss"] is not None and ((finding.get("epss") or {}).get("score") or 0) < rule["min_epss"]:
        return False
    return True


def urgency(finding):
    return (1 if (finding.get("kev") or {}).get("listed") else 0, (finding.get("epss") or {}).get("score") or 0,
            SEVERITY_RANK.get(finding.get("severity"), 0), finding.get("cvss") or 0)


def select_findings(findings, rule, already_pushed):
    chosen = [f for f in findings if f.get("id") not in already_pushed and matches(f, rule)]
    chosen.sort(key=urgency, reverse=True)
    return chosen[:rule["max_per_run"]]


def _record_for(system, result):
    """(external_ref, external_id, state) from a connector result record."""
    if system == "servicenow":
        return result.get("number"), result.get("sys_id"), links.map_state("servicenow", result.get("state")) or "open"
    if system == "jira":
        status = ((result.get("fields") or {}).get("status") or {})
        cat = (status.get("statusCategory") or {}).get("key") or status.get("name")
        return result.get("key"), result.get("id"), links.map_state("jira", cat) or "open"
    return "sent", None, "open"


def push(system, connector, connection_id, rule, findings_path=merge.DEFAULT_PATH, engine=None, actor="scheduler"):
    """Runs one push. Returns {sent, errors, refreshed, matched}."""
    rule = normalise_rule(rule)
    findings = merge.load(findings_path)
    chosen = select_findings(findings, rule, links.pushed_ids(connection_id, engine))
    sent, errors = 0, 0
    for f in chosen:
        try:
            if system == "servicenow":
                result = connector.create_incident(f)
            elif system == "jira":
                result = connector.create_issue(f)
            else:
                connector.send_event(f)
                result = {}
            ref, ext_id, state = _record_for(system, result)
            links.upsert(f["id"], system, ref, state, connection_id=connection_id, external_id=ext_id, engine=engine)
            sent += 1
        except Exception as exc:  # noqa: BLE001 - one finding must not abort the batch
            links.upsert(f["id"], system, None, None, connection_id=connection_id, error=str(exc)[:300], engine=engine)
            errors += 1
    refreshed = refresh_states(system, connector, connection_id, engine, actor) if system in ("servicenow", "jira") else 0
    return {"matched": len(chosen), "sent": sent, "errors": errors, "refreshed": refreshed}


def refresh_states(system, connector, connection_id, engine=None, actor="scheduler"):
    """Reads the current state of still-open linked tickets and mirrors changes. Returns how many
    changed. A ticket that cannot be read this time is left alone."""
    changed = 0
    for link in links.open_links(connection_id, engine):
        try:
            if system == "servicenow":
                rec = connector.find_existing_incident(link["finding_id"])
                new = links.map_state("servicenow", (rec or {}).get("state")) if rec else None
            else:
                rec = connector.find_existing_issue(link["finding_id"])
                status = ((rec or {}).get("fields") or {}).get("status") or {}
                new = links.map_state("jira", (status.get("statusCategory") or {}).get("key") or status.get("name")) if rec else None
        except Exception:  # noqa: BLE001
            continue
        if new and new != link["state"]:
            links.report_state(link["finding_id"], system, new, actor, external_ref=link["external_ref"], engine=engine)
            changed += 1
    return changed
