"""
Real, unsupervised machine learning: asset anomaly detection, finding risk-archetype
clustering, and near-duplicate/similar-finding text search - built with scikit-learn,
genuinely fit at request time against this app's own real finding/asset data.

READ THIS FIRST if you're wondering how this reconciles with
remediation/inventory/pattern_recognition.py's honest "this is deliberately NOT real
machine learning" disclaimer, or docs/FAQ.md's "no, and calling it that would be
dishonest" answer about owner suggestions. Both of those are still correct, and this
module doesn't change them - it answers a genuinely different question with genuinely
different data:

- Owner/team/type suggestion needs LABELED examples (an asset with a known-correct
  owner) to learn from. This app's real label pool - remediation/inventory/
  asset_ownership.json - has exactly 5 entries. Supervised learning on 5 examples is
  overfitting theater, not a real capability - pattern_recognition.py's own docstring
  already reached this conclusion, and nothing here changes that math. That heuristic
  stays exactly as it was.
- Anomaly detection, clustering, and text similarity are UNSUPERVISED - they need no
  labels at all, only a real feature population large enough to describe a genuine
  distribution. remediation/output/normalized-findings.json has 9,415 real findings
  (8,463 with a real CVE, 8,308 with a numeric CVSS score, 134 real CISA KEV-listed,
  8,462 with a real FIRST.org EPSS score) across 8,571 distinct assets and 17 asset
  types - genuinely large enough to fit and validate real scikit-learn models on,
  independently verified (WebSearch, not memory) as: scikit-learn 1.9.0, current
  stable, supports Python 3.11-3.14.

What this deliberately does NOT do, and why - read before extending this module:
- No supervised learning and no remediation-outcome prediction ("will this get fixed
  on time"). There is no field anywhere in this app's schema or data representing a
  real remediation outcome (no resolved/fixed_at/time_to_remediate) to learn from -
  fabricating one would be exactly the dishonesty this repo's documentation style
  exists to avoid.
- This never feeds back into, or replaces, remediation_policy_engine.py's domain
  resolution or priority_engine.py's scoring. Those are deterministic, auditable rule
  systems a security team can read and reason about line-by-line; making either of
  them a harder-to-audit statistical model would be a real regression, not an
  improvement, especially with no real outcome data to validate it against. Everything
  in this module is an advisory INSIGHTS layer that sits alongside those engines, never
  inside their decision path.

Every function here returns NEW data (never mutates its inputs), same convention as
every other enrichment module in this package.
"""
import numpy as np
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from remediation.config import priority_engine

# Numeric features used for per-asset anomaly detection, in matrix-column order - kept
# as a module constant so detect_asset_anomalies()'s "reasons" explanation can name
# exactly which real feature drove a flagged asset's score.
ASSET_FEATURE_NAMES = ("finding_count", "critical_count", "kev_count", "severity_score", "max_cvss", "max_epss")

# Minimum real examples required before fitting anything - matches the same "don't
# train on too little data" rule pattern_recognition.py's own docstring already
# applies, just enforced here in code rather than only in prose. Chosen so a handful of
# demo assets can never be dressed up as a real trained population; 9,415 real findings
# and 8,571 real assets (verified counts, not assumed) sit two to three orders of
# magnitude above this floor.
_MIN_ASSETS_FOR_ANOMALY_DETECTION = 10
_MIN_FINDINGS_FOR_CLUSTERING = 20


def _findings_by_asset(findings):
    by_asset = {}
    for f in findings:
        name = (f.get("asset") or {}).get("name")
        if not name:
            continue
        by_asset.setdefault(name, []).append(f)
    return by_asset


def build_asset_feature_matrix(asset_rows, findings, severity_weights=None):
    """Returns a (n_assets, 6) real-valued numpy array - one row per `asset_rows`
    entry, columns per ASSET_FEATURE_NAMES. `finding_count`/`critical_count`/
    `kev_count`/`highest_severity` come straight from asset_inventory.
    build_asset_inventory()'s own output; `max_cvss`/`max_epss` are computed here from
    that asset's own real findings (same reuse-not-recompute convention risk_scoring.py
    already established for asset_criticality_score())."""
    severity_weights = severity_weights or priority_engine.load_rules()["severity_weights"]
    by_asset = _findings_by_asset(findings)

    rows = []
    for a in asset_rows:
        asset_findings = by_asset.get(a.get("name"), [])
        cvss_values = [f.get("cvss") for f in asset_findings if isinstance(f.get("cvss"), (int, float))]
        epss_values = [
            f["epss"]["score"] for f in asset_findings
            if f.get("epss") and isinstance(f["epss"].get("score"), (int, float))
        ]
        rows.append([
            a.get("finding_count", 0) or 0,
            a.get("critical_count", 0) or 0,
            a.get("kev_count", 0) or 0,
            severity_weights.get(a.get("highest_severity"), 0),
            max(cvss_values) if cvss_values else 0.0,
            max(epss_values) if epss_values else 0.0,
        ])
    return np.array(rows, dtype=float)


def detect_asset_anomalies(asset_rows, findings, contamination=0.05, random_state=42):
    """Real unsupervised anomaly detection via sklearn.ensemble.IsolationForest, fit
    SEPARATELY per asset type - "anomalous" is judged against peers of the same type
    (a certificate asset with 1 finding is never compared against a cloud-infrastructure
    asset's very different baseline), matching how a real analyst would actually read
    "is this unusual." A type group with fewer than _MIN_ASSETS_FOR_ANOMALY_DETECTION
    real assets is honestly skipped (every real asset type in this app's own data has
    well over 100 - see the module docstring - so this floor exists for correctness at
    the boundary, not because it's expected to bite in practice).

    Returns a NEW list (same rows as `asset_rows`, never mutated) with `anomaly_score`
    (float, lower = more anomalous; None if the type group was too small to fit),
    `is_anomaly` (bool), and `reasons` (list of plain-English strings naming which real
    feature(s) deviate most from same-type peers, only populated when is_anomaly)."""
    by_type = {}
    for i, a in enumerate(asset_rows):
        by_type.setdefault(a.get("type"), []).append(i)

    results = [None] * len(asset_rows)
    for asset_type, indices in by_type.items():
        group_rows = [asset_rows[i] for i in indices]
        if len(group_rows) < _MIN_ASSETS_FOR_ANOMALY_DETECTION:
            for i in indices:
                results[i] = {**asset_rows[i], "anomaly_score": None, "is_anomaly": False, "reasons": []}
            continue

        X = build_asset_feature_matrix(group_rows, findings)
        model = IsolationForest(random_state=random_state, contamination=contamination)
        model.fit(X)
        scores = model.decision_function(X)  # lower = more anomalous
        preds = model.predict(X)  # -1 = anomaly, 1 = normal

        means = X.mean(axis=0)
        stds = X.std(axis=0)
        stds_safe = np.where(stds == 0, 1, stds)  # a constant feature within this type can't drive a "reason"

        for row_idx, asset_idx in enumerate(indices):
            is_anomaly = bool(preds[row_idx] == -1)
            reasons = []
            if is_anomaly:
                z = (X[row_idx] - means) / stds_safe
                top = np.argsort(-np.abs(z))[:2]
                for rank, feat_idx in enumerate(top):
                    # The single most-deviating feature is always reported - it's the
                    # real reason IsolationForest flagged this row even if, on rare
                    # borderline cases, no single feature clears a full 1.0 std dev (the
                    # model can flag a genuine joint/multivariate pattern that isn't
                    # extreme on any one axis). The second slot stays threshold-gated so
                    # a flagged asset isn't padded with a second, weak reason.
                    if rank > 0 and abs(z[feat_idx]) < 1.0:
                        continue
                    direction = "higher" if z[feat_idx] > 0 else "lower"
                    label = ASSET_FEATURE_NAMES[feat_idx].replace("_", " ")
                    reasons.append(f"{label} is unusually {direction} than other {asset_type} assets ({z[feat_idx]:+.1f} std dev)")
            results[asset_idx] = {
                **asset_rows[asset_idx],
                "anomaly_score": round(float(scores[row_idx]), 4),
                "is_anomaly": is_anomaly,
                "reasons": reasons,
            }
    return results


# One-hot-able asset types, fixed order - keeps cluster_findings()'s feature matrix
# columns stable across calls regardless of which types happen to appear in a given
# findings slice.
_ASSET_TYPES = (
    "windows-server", "unix-server", "windows-endpoint", "mobile-device",
    "network-routing-switching", "network-security-device", "iot-ot-device",
    "virtualization-host", "cloud-infrastructure", "client-application", "printer",
    "application", "certificate", "code-repository", "iac-resource",
    "container-runtime", "ai-ml-system",
)


def build_finding_feature_matrix(findings, severity_weights=None):
    """Returns a (n_findings, 4 + len(_ASSET_TYPES)) real-valued numpy array: severity
    weight, CVSS (0 if absent), a KEV-listed 0/1 flag, EPSS score (0 if absent), plus a
    one-hot column per known asset type - lets KMeans discover archetypes like
    "KEV-listed critical server findings" as a natural cluster rather than needing that
    grouping predefined."""
    severity_weights = severity_weights or priority_engine.load_rules()["severity_weights"]
    rows = []
    for f in findings:
        sev = severity_weights.get(f.get("severity"), 0)
        cvss = f.get("cvss") if isinstance(f.get("cvss"), (int, float)) else 0.0
        kev = 1.0 if (f.get("kev") or {}).get("listed") else 0.0
        epss = (f.get("epss") or {}).get("score") or 0.0
        asset_type = (f.get("asset") or {}).get("type")
        one_hot = [1.0 if asset_type == t else 0.0 for t in _ASSET_TYPES]
        rows.append([sev, cvss, kev, epss, *one_hot])
    return np.array(rows, dtype=float)


def cluster_findings(findings, n_clusters=8, random_state=42):
    """Real unsupervised clustering via sklearn.cluster.KMeans over
    build_finding_feature_matrix()'s real feature vectors. Returns (tagged_findings,
    cluster_summaries):
    - tagged_findings: a NEW list (never mutates `findings`) with a `risk_cluster` int
      added to every finding.
    - cluster_summaries: one dict per discovered cluster - {"cluster_id", "size",
      "dominant_severity", "dominant_asset_type", "avg_cvss", "avg_epss",
      "kev_count"} - computed from the ACTUAL members of that cluster, not a
      predefined label, so the summary describes whatever KMeans genuinely found.

    Returns ([], []) if there are fewer than _MIN_FINDINGS_FOR_CLUSTERING real findings
    - too few to describe real clusters (never expected to bite given this app's real
    ~9,400-finding scale, but a small custom-uploaded dataset should get an honest
    empty result rather than degenerate 1-member "clusters")."""
    if len(findings) < _MIN_FINDINGS_FOR_CLUSTERING:
        return [], []

    n_clusters = min(n_clusters, len(findings))
    X = build_finding_feature_matrix(findings)
    model = KMeans(n_clusters=n_clusters, random_state=random_state, n_init="auto")
    labels = model.fit_predict(X)

    tagged = [{**f, "risk_cluster": int(label)} for f, label in zip(findings, labels)]

    summaries = []
    for cluster_id in range(n_clusters):
        members = [f for f, label in zip(findings, labels) if label == cluster_id]
        if not members:
            continue
        severities = [m.get("severity") for m in members if m.get("severity")]
        asset_types = [(m.get("asset") or {}).get("type") for m in members if (m.get("asset") or {}).get("type")]
        cvss_values = [m.get("cvss") for m in members if isinstance(m.get("cvss"), (int, float))]
        epss_values = [
            m["epss"]["score"] for m in members
            if m.get("epss") and isinstance(m["epss"].get("score"), (int, float))
        ]
        summaries.append({
            "cluster_id": cluster_id,
            "size": len(members),
            "dominant_severity": max(set(severities), key=severities.count) if severities else None,
            "dominant_asset_type": max(set(asset_types), key=asset_types.count) if asset_types else None,
            "avg_cvss": round(sum(cvss_values) / len(cvss_values), 2) if cvss_values else None,
            "avg_epss": round(sum(epss_values) / len(epss_values), 4) if epss_values else None,
            "kev_count": sum(1 for m in members if (m.get("kev") or {}).get("listed")),
        })
    summaries.sort(key=lambda s: -s["size"])
    return tagged, summaries


def find_similar_findings(findings, finding_id, top_n=5):
    """Real text-similarity search: sklearn.feature_extraction.text.TfidfVectorizer
    over each finding's `title + description`, ranked by cosine similarity against the
    finding named `finding_id`. Returns a list of up to `top_n` OTHER findings (the
    query finding itself is excluded), each with a `similarity` float (0-1) added -
    highest first. Returns [] if `finding_id` isn't found, or if there are too few
    other findings with text to compare against."""
    by_id = {f["id"]: i for i, f in enumerate(findings)}
    if finding_id not in by_id or len(findings) < 2:
        return []

    texts = [f"{f.get('title', '')} {f.get('description', '')}".strip() for f in findings]
    vectorizer = TfidfVectorizer(max_features=5000, stop_words="english")
    tfidf = vectorizer.fit_transform(texts)

    query_idx = by_id[finding_id]
    sims = cosine_similarity(tfidf[query_idx:query_idx + 1], tfidf).flatten()
    ranked = np.argsort(-sims)

    results = []
    for idx in ranked:
        if idx == query_idx:
            continue
        if sims[idx] <= 0:
            break  # argsort is descending - once similarity hits 0, nothing further is a real match
        results.append({**findings[idx], "similarity": round(float(sims[idx]), 4)})
        if len(results) >= top_n:
            break
    return results
