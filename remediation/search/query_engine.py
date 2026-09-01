"""
A real, deterministic "ask your data" search engine - answers a free-text question by
querying this app's own real data (the live remediation queue, code-scan findings,
asset inventory) and, when no structured query pattern matches, by real keyword-overlap
scoring against the real FAQ documentation (docs/FAQ.md).

Deliberately NOT an LLM and not natural-language understanding: this is pattern/keyword
matching over a fixed, disclosed set of real query shapes (a finding ID, a CVE, a
severity/KEV/SLA/team/owner/asset filter, a count question) - same "transparent,
explainable, not a model" honesty this repo's other pattern-matching module
(remediation/inventory/pattern_recognition.py) already commits to. The payoff of that
honesty: this can never hallucinate an answer. Every fact returned is a real lookup into
real data; a query with no confident match says so plainly instead of guessing - see
`answer_query()`'s "no_match" branch.

It IS genuinely "agentic" in a narrow, real sense: `answer_query()` chains real lookups
(resolve a team/owner/asset name mentioned in the query, THEN filter findings by it,
combined with any severity/KEV/SLA words in the same query) rather than doing only a
single flat substring match - see dashboard/static/js/search.js for that simpler,
complementary type-ahead tool this is not trying to replace.

No external API call, no signup, no API key, no cost, no data ever leaves this machine -
this is the "free, open" search the product ask called for. A real hosted or local LLM
(e.g. via Ollama) could be layered on top of this later as an optional upgrade for more
flexible phrasing, without changing anything below - see the module docstring in
dashboard/app.py's /api/search/ask route for that extension point.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FAQ_PATH = REPO_ROOT / "docs" / "FAQ.md"

FINDING_ID_RE = re.compile(r"\bFIND-\d+\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

_SEVERITY_WORDS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
_KEV_WORDS = ("kev", "known exploited", "actively exploited", "exploited")
# Order matters - "overdue"/"breached" are checked before the plain-substring "at risk"/
# "on track" phrases so a query mentioning several doesn't silently pick the wrong one.
_SLA_PHRASES = (
    ("breached", "breached"), ("overdue", "breached"),
    ("at risk", "at_risk"), ("on track", "on_track"),
)
_COUNT_TRIGGERS = ("how many", "count", "number of", "total")
_TEAM_OWNER_RE = re.compile(r"(?:team|owned by|owner)\s+([a-z0-9 &-]+)", re.IGNORECASE)

_SLA_LABELS = {"breached": "SLA-breached", "at_risk": "SLA at-risk", "on_track": "SLA on-track"}


def _sla_status_of(finding):
    """Mirrors dashboard_data.sla_summary()'s own per-finding classification exactly,
    and dashboard/static/js/pages/queue.js's slaStatusOf() (the client-side mirror of
    the same real logic) - kept as one small duplicated check rather than a new shared
    abstraction, matching the convention those two already established."""
    sla = finding.get("sla") or {}
    if sla.get("breached"):
        return "breached"
    if sla.get("days_remaining") is not None and sla["days_remaining"] <= 3:
        return "at_risk"
    return "on_track"


def _extract_filters(query, assets):
    """Real, disclosed keyword/entity extraction - not NLP. Returns a dict with any of
    severity/kev/sla_status/team/owner/asset present, only for what the query text
    actually names. `assets` grounds team/owner/asset-name resolution in real values
    that actually exist in the data, rather than guessing at a name."""
    q = query.lower()
    filters = {}

    for word, value in _SEVERITY_WORDS.items():
        if word in q:
            filters["severity"] = value
            break
    if any(w in q for w in _KEV_WORDS):
        filters["kev"] = True
    for phrase, value in _SLA_PHRASES:
        if phrase in q:
            filters["sla_status"] = value
            break

    team_owner_match = _TEAM_OWNER_RE.search(query)
    if team_owner_match:
        candidate = team_owner_match.group(1).strip().rstrip(".?!").lower()
        known_teams = {a.get("team") for a in assets if a.get("team")}
        known_owners = {a.get("owner") for a in assets if a.get("owner")}
        matched_team = next((t for t in known_teams if candidate in t.lower() or t.lower() in candidate), None)
        if matched_team:
            filters["team"] = matched_team
        else:
            matched_owner = next((o for o in known_owners if candidate in o.lower() or o.lower() in candidate), None)
            if matched_owner:
                filters["owner"] = matched_owner

    # Longest real asset name that appears in the query wins, so a more specific name
    # is never shadowed by a shorter one that happens to also be a substring match.
    known_asset_names = sorted({a.get("name") for a in assets if a.get("name")}, key=len, reverse=True)
    matched_asset = next((name for name in known_asset_names if name.lower() in q), None)
    if matched_asset:
        filters["asset"] = matched_asset

    return filters


def _apply_filters(findings, filters):
    def keep(f):
        if filters.get("severity") and f.get("severity") != filters["severity"]:
            return False
        if filters.get("kev") and not (f.get("kev") and f["kev"].get("listed")):
            return False
        if filters.get("sla_status") and _sla_status_of(f) != filters["sla_status"]:
            return False
        if filters.get("team") and f.get("team") != filters["team"]:
            return False
        if filters.get("owner") and f.get("owner") != filters["owner"]:
            return False
        if filters.get("asset"):
            asset = f.get("asset") or {}
            if not (isinstance(asset, dict) and asset.get("name") == filters["asset"]):
                return False
        return True
    return [f for f in findings if keep(f)]


def _filter_summary_text(filters):
    parts = []
    if filters.get("severity"):
        parts.append(f"{filters['severity']} severity")
    if filters.get("kev"):
        parts.append("CISA KEV-listed")
    if filters.get("sla_status"):
        parts.append(_SLA_LABELS[filters["sla_status"]])
    if filters.get("team"):
        parts.append(f"owned by team {filters['team']}")
    if filters.get("owner"):
        parts.append(f"owned by {filters['owner']}")
    if filters.get("asset"):
        parts.append(f"on {filters['asset']}")
    return ", ".join(parts) if parts else "all findings in the live queue"


def _queue_link(filters):
    """Only ever emits URL params dashboard/static/js/pages/queue.js actually reads
    (kevOnly, slaStatus, asset) - severity/team/owner have no real deep-link param
    there today, so those filters affect the real COUNT below but the link honestly
    falls back to an unfiltered /queue rather than a param that would silently do
    nothing."""
    params = []
    if filters.get("kev"):
        params.append("kevOnly=true")
    if filters.get("sla_status"):
        params.append(f"slaStatus={filters['sla_status']}")
    if filters.get("asset"):
        params.append(f"asset={filters['asset']}")
    return "/queue" + ("?" + "&".join(params) if params else "")


_FAQ_HEADER_RE = re.compile(r"^### (.+)$", re.MULTILINE)
_WORD_RE = re.compile(r"[a-z0-9]+")
_FAQ_STOPWORDS = {
    "the", "a", "an", "is", "are", "does", "do", "this", "to", "of", "in", "on", "for",
    "and", "or", "it", "what", "how", "can", "i", "with", "at", "be", "not", "any",
}


def _tokenize(text):
    return set(_WORD_RE.findall(text.lower()))


def _load_faq_entries(path=None):
    path = Path(path) if path is not None else FAQ_PATH
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    headers = list(_FAQ_HEADER_RE.finditer(text))
    entries = []
    for i, m in enumerate(headers):
        start = m.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        entries.append({"question": m.group(1).strip(), "body": text[start:end].strip()})
    return entries


def search_faq(query, min_score=2, path=None):
    """Real keyword-overlap scoring (meaningful query words actually present in a real
    FAQ entry's question+body) - no embeddings, no model, fully inspectable. Returns
    None (never a low-confidence guess) when nothing clears `min_score`, so callers can
    honestly say "no match" instead of surfacing an unrelated FAQ entry."""
    entries = _load_faq_entries(path)
    query_tokens = _tokenize(query) - _FAQ_STOPWORDS
    if not query_tokens:
        return None
    scored = []
    for e in entries:
        entry_tokens = _tokenize(e["question"]) | _tokenize(e["body"])
        score = len(query_tokens & entry_tokens)
        if score > 0:
            scored.append((score, e))
    if not scored:
        return None
    scored.sort(key=lambda pair: -pair[0])
    best_score, best = scored[0]
    if best_score < min_score:
        return None
    excerpt = _strip_markdown_emphasis(best["body"].split("\n\n")[0].strip())
    return {"question": best["question"], "excerpt": excerpt[:500], "score": best_score}


_MARKDOWN_EMPHASIS_RE = re.compile(r"\*\*(.+?)\*\*|`(.+?)`", re.DOTALL)


def _strip_markdown_emphasis(text):
    """Renders FAQ.md's own bold/code markdown as plain text for a UI that shows the
    excerpt as-is rather than rendering markdown - cosmetic only, never changes which
    words are there."""
    return _MARKDOWN_EMPHASIS_RE.sub(lambda m: m.group(1) or m.group(2), text)


def answer_query(query, *, queue_findings, vulnhunt_findings=None, assets=None):
    """The main entry point. `queue_findings` is the live remediation queue
    (dashboard_data.load_live_queue()'s output); `vulnhunt_findings` is the code-scan
    result list (optional - only used for a direct FIND-id lookup that isn't in the
    infra queue); `assets` is /api/assets' row list (optional - only used to ground
    team/owner/asset-name resolution in real values).

    Returns {query, intent, answer, results, link, matched_faq} - `intent` is one of
    "finding_lookup"/"cve_lookup"/"count"/"list"/"asset_lookup"/"faq"/"no_match"/
    "empty". `answer` is always built only from real numbers/facts already computed
    here - never a fabricated sentence."""
    vulnhunt_findings = vulnhunt_findings or []
    assets = assets or []
    query = (query or "").strip()
    if not query:
        return {
            "query": query, "intent": "empty",
            "answer": "Ask about a finding ID (FIND-123), a CVE, an asset name, or a "
                       "real count (e.g. \"how many critical KEV findings are breached\").",
            "results": [], "link": None, "matched_faq": None,
        }

    id_match = FINDING_ID_RE.search(query)
    if id_match:
        fid = id_match.group(0).upper()
        finding = next((f for f in queue_findings if str(f.get("id", "")).upper() == fid), None)
        if not finding:
            finding = next((f for f in vulnhunt_findings if str(f.get("ID", "")).upper() == fid), None)
        if finding:
            title = finding.get("title") or finding.get("Title")
            severity = finding.get("severity") or finding.get("Severity")
            asset = finding.get("asset")
            asset_name = asset.get("name") if isinstance(asset, dict) else None
            suffix = f" on {asset_name}" if asset_name else ""
            return {
                "query": query, "intent": "finding_lookup",
                "answer": f"{fid}: {title} ({severity or 'unknown severity'}){suffix}.",
                "results": [finding], "link": f"/queue?highlight={fid}", "matched_faq": None,
            }
        return {
            "query": query, "intent": "finding_lookup",
            "answer": f"No finding with ID {fid} in the live queue or code-scan results.",
            "results": [], "link": None, "matched_faq": None,
        }

    cve_match = CVE_RE.search(query)
    if cve_match:
        cve = cve_match.group(0).upper()
        matching = [f for f in queue_findings if str(f.get("cve") or "").upper() == cve]
        if matching:
            assets_hit = sorted({
                f["asset"]["name"] for f in matching
                if isinstance(f.get("asset"), dict) and f["asset"].get("name")
            })
            shown = ", ".join(assets_hit[:5])
            more = f" (+{len(assets_hit) - 5} more)" if len(assets_hit) > 5 else ""
            return {
                "query": query, "intent": "cve_lookup",
                "answer": f"{cve} affects {len(matching)} real finding(s) across {len(assets_hit)} asset(s): {shown}{more}.",
                "results": matching[:10], "link": f"/queue?cve={cve}", "matched_faq": None,
            }
        return {
            "query": query, "intent": "cve_lookup",
            "answer": f"No findings in the live queue reference {cve}.",
            "results": [], "link": None, "matched_faq": None,
        }

    filters = _extract_filters(query, assets)
    non_asset_filters = {k: v for k, v in filters.items() if k != "asset"}
    is_count = any(t in query.lower() for t in _COUNT_TRIGGERS)

    if is_count or non_asset_filters:
        matching = _apply_filters(queue_findings, filters)
        summary = _filter_summary_text(filters)
        link = _queue_link(filters)
        if is_count or not matching:
            answer = f"{len(matching)} finding(s) match: {summary}."
        else:
            top = matching[:5]
            listed = "; ".join(f"{f.get('id')} - {f.get('title')}" for f in top)
            more = f" (+{len(matching) - len(top)} more)" if len(matching) > len(top) else ""
            answer = f"{len(matching)} finding(s) match ({summary}). Top results: {listed}{more}."
        return {
            "query": query, "intent": "count" if is_count else "list", "answer": answer,
            "results": matching[:10], "link": link, "matched_faq": None,
        }

    if filters.get("asset"):
        asset_name = filters["asset"]
        asset = next((a for a in assets if a.get("name") == asset_name), None)
        if asset:
            return {
                "query": query, "intent": "asset_lookup",
                "answer": (
                    f"{asset_name}: {asset.get('finding_count', 0)} finding(s), "
                    f"highest severity {asset.get('highest_severity') or 'none'}, "
                    f"risk score {asset.get('risk_score', 'unscored')}, "
                    f"owned by {asset.get('owner') or 'nobody yet'}."
                ),
                "results": [asset], "link": f"/assets?highlight={asset_name}", "matched_faq": None,
            }

    faq_match = search_faq(query)
    if faq_match:
        return {
            "query": query, "intent": "faq", "answer": faq_match["excerpt"],
            "results": [], "link": "/faq", "matched_faq": faq_match,
        }

    return {
        "query": query, "intent": "no_match",
        "answer": "No confident match in real data or documentation for that - try a "
                   "finding ID (FIND-123), a CVE, an asset name, or a count question "
                   "(e.g. \"how many critical findings are breached\").",
        "results": [], "link": None, "matched_faq": None,
    }
