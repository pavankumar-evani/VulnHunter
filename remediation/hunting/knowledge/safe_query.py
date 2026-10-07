"""
The read-only gate for a query Quanta did not write itself (a model-drafted one, or one a person pastes into a draft).

Splunk SPL goes through the SAME validator the SIEM search path uses (`siem_search_connector.check_query`: only a `search ...` query, no macros, none of the write, script,
lookup-output or REST commands). For the other languages there is no execution path in Quanta at all; these checks only refuse text that would be dangerous if a person pasted
it into their own tool: KQL management commands and plugins that call out, EQL that is not a plain event query, Sigma that is not a rule. Passing is NOT a statement that the
query is correct or efficient, only that it is a read-only search in that language.
"""
import re

import yaml

from remediation.connectors import siem_search_connector as siem

LANGUAGES = ("splunk-spl", "kql", "eql", "sigma")
MAX_LEN = 6000
_KQL_FORBIDDEN = re.compile(r"(?i)(^|\s|\|)(\.(set|append|set-or-append|set-or-replace|drop|create|alter|delete|ingest|execute|purge|move|rename|replace)\b|externaldata\b|evaluate\b|invoke\b|"
                            r"http_request(_post)?\b|plugin\b|cluster\s*\(|database\s*\(|sql_request\b|mysql_request\b|cosmosdb_sql_request\b|ingestion_time\s*\(\s*\)\s*=)")
_EQL_START = re.compile(r"(?i)^\s*(any|process|file|network|registry|dns|library|image_load|driver|event|authentication|intrusion_detection|sequence|sample)\b")
_EQL_PIPES = {"head", "tail", "unique", "count", "sort", "filter", "unique_count"}


def check(language, text):
    """-> {ok, errors, language}. Never raises."""
    errs = []
    t = (text or "").strip()
    if language not in LANGUAGES:
        return {"ok": False, "language": language, "errors": [f"language must be one of {', '.join(LANGUAGES)}"]}
    if not t:
        return {"ok": False, "language": language, "errors": ["The query is empty"]}
    if len(t) > MAX_LEN:
        errs.append("The query is too long")
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", t):
        errs.append("The query contains control characters")
    if errs:
        return {"ok": False, "language": language, "errors": errs}
    if language == "splunk-spl":
        try:
            siem.check_query(t)
        except ValueError as exc:   # SearchRefused is a ValueError
            errs.append(str(exc))
    elif language == "kql":
        if t.startswith("."):
            errs.append("A KQL management command (starts with a dot) is not a search")
        elif _KQL_FORBIDDEN.search(t):
            errs.append("The query uses a management command, a plugin or a cross-cluster or external call that is not a plain read-only search")
    elif language == "eql":
        if not _EQL_START.match(t):
            errs.append("An EQL query must start with an event category (for example 'process where ...' or 'any where ...') or 'sequence'")
        for seg in t.split("|")[1:]:
            cmd = re.match(r"\s*([A-Za-z_]+)", seg)
            if cmd and cmd.group(1).lower() not in _EQL_PIPES:
                errs.append(f"The pipe command '{cmd.group(1)}' is not allowed")
    else:
        try:
            doc = yaml.safe_load(t)
        except yaml.YAMLError as exc:
            return {"ok": False, "language": language, "errors": [f"Not valid YAML: {str(exc)[:100]}"]}
        if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict) or "condition" not in doc["detection"]:
            errs.append("A Sigma rule needs a detection section with a condition")
        elif not doc.get("title") or not isinstance(doc.get("logsource"), dict):
            errs.append("A Sigma rule needs a title and a logsource")
    return {"ok": not errs, "language": language, "errors": errs}
