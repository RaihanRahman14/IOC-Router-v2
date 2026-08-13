"""Numeric confidence scoring for IOC threat intel results.

Computes a 0.0–100.0 confidence score per IOC by:
1. Normalizing each provider's signal to 0.0–1.0
2. Weighting active providers (re-normalized when some return no data)
3. Applying an infra-classification modifier (BP floor / FP discount / HIGH_RISK boost)

This module measures **evidence strength, not guilt**. The verdict of record is
the rule cascade in `ioc.verdict.summarize_results`; nothing here overrides it,
and `verdict_from_score` / `session_label` must never be rendered as a verdict
alongside it. They exist so the score can be described in words — see
`ioc.verdict` for the full rationale.
"""
from __future__ import annotations

from typing import Optional


BASE_WEIGHTS: dict[str, float] = {
    "virustotal":      0.25,
    "abuseipdb":       0.20,
    "threatfox":       0.20,
    "shodan":          0.10,
    "hybrid_analysis": 0.15,
    "malwarebazaar":   0.10,
    # urlscan, ransomware_live: context-only, not part of the score formula.
}

# When any single provider returns a score ≥ this threshold, the final
# weighted sum is floored at `signal * STRONG_SIGNAL_FLOOR_FACTOR`. Keeps a
# confident hit (e.g. confirmed malware in MalwareBazaar/Hybrid Analysis)
# from being averaged down by a low VirusTotal detection ratio.
STRONG_SIGNAL_THRESHOLD: float = 0.70
STRONG_SIGNAL_FLOOR_FACTOR: float = 0.70

THREATFOX_CONF_MAP: dict[str, float] = {"High": 0.9, "Medium": 0.6, "Low": 0.3}


# ---------------------------------------------------------------------------
# Per-provider scoring (return None when no data → exclude from weighted sum)
# ---------------------------------------------------------------------------

def _score_virustotal(vt: dict) -> Optional[float]:
    """Score a VirusTotal result on 0.0–1.0.

    Args:
        vt: VirusTotal result dict for a single IOC (stats / attributes / votes).

    Returns:
        Float in [0.0, 1.0], or None if VT returned no engine data.
    """
    if not vt or not isinstance(vt, dict):
        return None

    stats = vt.get("stats", {}) or {}
    try:
        mal = int(stats.get("malicious", 0))
        sus = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) if stats else 0
    except (TypeError, ValueError):
        return None

    if total == 0:
        return None

    engine_score = (mal + sus * 0.5) / total

    attrs = vt.get("attributes", {}) or {}
    rep = attrs.get("reputation")
    if rep is not None:
        try:
            rep_int = int(rep)
            rep_score = max(0.0, min(1.0, (-rep_int) / 100.0)) if rep_int < 0 else 0.0
        except (TypeError, ValueError):
            rep_score = 0.0
    else:
        rep_score = 0.0

    votes = vt.get("votes") or []
    mal_v = sum(
        1 for v in votes
        if isinstance(v, dict)
        and v.get("attributes", {}).get("verdict") == "malicious"
    )
    har_v = sum(
        1 for v in votes
        if isinstance(v, dict)
        and v.get("attributes", {}).get("verdict") == "harmless"
    )
    vote_total = mal_v + har_v
    vote_score = mal_v / vote_total if vote_total > 0 else 0.0

    return engine_score * 0.6 + rep_score * 0.2 + vote_score * 0.2


def _score_abuseipdb(ab: dict) -> Optional[float]:
    """Score an AbuseIPDB result on 0.0–1.0.

    Args:
        ab: AbuseIPDB result dict (abuseConfidenceScore + reports).

    Returns:
        Float in [0.0, 1.0], or None if no data / error response.
    """
    if not ab or not isinstance(ab, dict):
        return None
    if ab.get("error"):
        return None

    try:
        base = int(ab.get("abuseConfidenceScore", 0)) / 100.0
    except (TypeError, ValueError):
        return None

    reports = ab.get("reports") or []
    distinct_reporters = len({
        r.get("reporter") for r in reports
        if isinstance(r, dict) and r.get("reporter")
    })
    diversity = min(1.0, distinct_reporters / 10.0)

    return base * (0.8 + 0.2 * diversity)


def _score_threatfox(tf: dict) -> Optional[float]:
    """Score a ThreatFox result on 0.0–1.0.

    Args:
        tf: ThreatFox result dict (query_status + data list).

    Returns:
        Float in [0.0, 1.0], or None if query_status != "ok".
    """
    if not tf or not isinstance(tf, dict):
        return None
    if tf.get("query_status") != "ok":
        return None

    data = tf.get("data") or []
    first = data[0] if data else {}
    if not isinstance(first, dict):
        return None

    conf_label = first.get("confidence_level", "")
    base = THREATFOX_CONF_MAP.get(conf_label, 0.3)

    type_boost = 0.10 if first.get("ioc_type") in ("ip:port", "domain") else 0.0
    malware_boost = 0.05 if first.get("malware") else 0.0

    return min(1.0, base + type_boost + malware_boost)


def _score_shodan(sh: dict) -> Optional[float]:
    """Score a Shodan result on 0.0–1.0.

    Reuses the provider's pre-computed `risk_summary.confidence` rather than
    re-deriving from raw banners.

    Args:
        sh: Shodan result dict with a risk_summary block.

    Returns:
        Float in [0.0, 1.0], or None if risk_level is UNKNOWN / no data / error.
    """
    if not sh or not isinstance(sh, dict):
        return None
    if sh.get("error"):
        return None

    risk = sh.get("risk_summary", {}) or {}
    if risk.get("risk_level") == "UNKNOWN":
        return None

    try:
        confidence = int(risk.get("confidence", 20))
    except (TypeError, ValueError):
        return None
    return confidence / 100.0


def _score_hybrid_analysis(ha: dict) -> Optional[float]:
    """Score a Hybrid Analysis result on 0.0–1.0.

    Args:
        ha: Hybrid Analysis result dict (threat_score + verdict).

    Returns:
        Float in [0.0, 1.0], or None if threat_score is absent.
    """
    if not ha or not isinstance(ha, dict):
        return None

    threat_score = ha.get("threat_score")
    if threat_score is None:
        return None

    try:
        base = int(threat_score) / 100.0
    except (TypeError, ValueError):
        return None

    verdict = (ha.get("verdict") or "").lower()
    if verdict == "no specific threat":
        return base * 0.3
    if verdict == "suspicious":
        return base * 0.8
    if verdict == "malicious":
        return base * 1.0
    return base * 0.5


def _score_malwarebazaar(mb: dict) -> Optional[float]:
    """Score a MalwareBazaar result on 0.0–1.0.

    A confirmed MB hit (query_status == "ok" AND non-empty data list) means
    the hash is a known malware sample, so the base is already very high; the
    signature field nudges it a touch higher. Any other state — error,
    hash_not_found, no_result, or empty data — means MB has nothing to say
    about this hash and must NOT contribute to the score.

    Args:
        mb: MalwareBazaar result dict.

    Returns:
        Float in [0.0, 1.0], or None if no hit.
    """
    if not mb or not isinstance(mb, dict):
        return None
    if mb.get("error"):
        return None
    if mb.get("query_status") != "ok":
        return None

    rows = mb.get("data") or []
    if not isinstance(rows, list) or not rows:
        return None

    primary = rows[0] if isinstance(rows[0], dict) else {}
    sig_boost = 0.05 if primary.get("signature") else 0.0
    return min(1.0, 0.95 + sig_boost)


# ---------------------------------------------------------------------------
# Infra-classification modifier
# ---------------------------------------------------------------------------

def _get_infra(vt: dict, sh: dict) -> Optional[dict]:
    """Pick the infra_classification block to apply (VT preferred over Shodan).

    Args:
        vt: VirusTotal result dict.
        sh: Shodan result dict.

    Returns:
        The infra_classification dict, or None if neither provider has one.
    """
    vt_infra = (vt or {}).get("infra_classification")
    sh_infra = (sh or {}).get("infra_classification")
    return vt_infra or sh_infra


def _apply_infra_modifier(
    score: float,
    infra: Optional[dict],
) -> tuple[float, Optional[str]]:
    """Adjust a weighted score based on infra category.

    Args:
        score: Weighted score in [0.0, 1.0] before infra modifier.
        infra: infra_classification dict, or None.

    Returns:
        Tuple of (modified_score_in_0_to_1_or_0_to_100_for_BP, note).
        Note: BP returns 5.0 already on the 0–100 scale because it's a hard
        floor that overrides everything else.
    """
    if not infra or not isinstance(infra, dict):
        return score, None

    category = infra.get("category", "")
    provider_name = infra.get("provider", "")

    if category == "BP":
        # Hard floor: known-benign infra (CDN, public DNS, etc.).
        # Return 0.05 on the 0–1 scale so the downstream *100 yields 5.0.
        return 0.05, f"Benign infrastructure: {provider_name}"

    if category == "FP":
        return score * 0.6, (
            f"Shared hosting ({provider_name}) — low attribution confidence"
        )

    if category == "HIGH_RISK":
        return min(1.0, score * 1.3), f"High-risk infrastructure: {provider_name}"

    return score, None


# ---------------------------------------------------------------------------
# Main aggregation
# ---------------------------------------------------------------------------

def compute_confidence_score(
    ioc_value: str,
    vt_results: dict,
    abuse_results: dict,
    threatfox_results: dict,
    shodan_results: dict,
    hybrid_results: Optional[dict] = None,
    malwarebazaar_results: Optional[dict] = None,
) -> dict:
    """Compute the per-IOC confidence score on a 0.0–100.0 scale.

    Args:
        ioc_value: The IOC string used to key into each provider's result dict.
        vt_results: Mapping of ioc_value → VirusTotal result.
        abuse_results: Mapping of ioc_value → AbuseIPDB result.
        threatfox_results: Mapping of ioc_value → ThreatFox result.
        shodan_results: Mapping of ioc_value → Shodan result.
        hybrid_results: Mapping of ioc_value → Hybrid Analysis result (optional).
        malwarebazaar_results: Mapping of ioc_value → MalwareBazaar result (optional).

    Returns:
        Dict with keys: score, label, provider_scores, active_providers,
        infra_note, verdict_from_score, ioc_value.
    """
    vt = (vt_results or {}).get(ioc_value) or {}
    ab = (abuse_results or {}).get(ioc_value) or {}
    tf = (threatfox_results or {}).get(ioc_value) or {}
    sh = (shodan_results or {}).get(ioc_value) or {}
    ha = (hybrid_results or {}).get(ioc_value) or {} if hybrid_results else {}
    mb = (malwarebazaar_results or {}).get(ioc_value) or {} if malwarebazaar_results else {}

    raw_scores: dict[str, Optional[float]] = {
        "virustotal":      _score_virustotal(vt),
        "abuseipdb":       _score_abuseipdb(ab),
        "threatfox":       _score_threatfox(tf),
        "shodan":          _score_shodan(sh),
        "hybrid_analysis": _score_hybrid_analysis(ha),
        "malwarebazaar":   _score_malwarebazaar(mb),
    }

    active: dict[str, float] = {p: s for p, s in raw_scores.items() if s is not None}

    if not active:
        return {
            "ioc_value": ioc_value,
            "score": 0.0,
            "label": "Unknown",
            "provider_scores": {},
            "active_providers": [],
            "infra_note": None,
            "verdict_from_score": "Unknown",
        }

    active_weights = {p: BASE_WEIGHTS.get(p, 0.05) for p in active}
    total_w = sum(active_weights.values())
    norm_weights = {p: w / total_w for p, w in active_weights.items()}

    weighted_sum = sum(active[p] * norm_weights[p] for p in active)

    strong_signal = max(active.values())
    if strong_signal >= STRONG_SIGNAL_THRESHOLD:
        weighted_sum = max(weighted_sum, strong_signal * STRONG_SIGNAL_FLOOR_FACTOR)

    infra = _get_infra(vt, sh)
    final_score, infra_note = _apply_infra_modifier(weighted_sum, infra)

    score_100 = round(final_score * 100, 1)

    # `verdict` here is the score's own band name, kept for this module's
    # bookkeeping and for the session distribution. It is NOT the IOC's verdict
    # — `ioc.verdict` owns that — and no UI surface may present it as one.
    if score_100 >= 70:
        label = "High"
        verdict = "Malicious"
    elif score_100 >= 40:
        label = "Medium"
        verdict = "Suspicious"
    elif score_100 >= 10:
        label = "Low"
        verdict = "Unknown"
    else:
        label = "Low"
        verdict = "Benign"

    return {
        "ioc_value": ioc_value,
        "score": score_100,
        "label": label,
        "provider_scores": {p: round(s * 100, 1) for p, s in active.items()},
        "active_providers": list(active.keys()),
        "infra_note": infra_note,
        "verdict_from_score": verdict,
    }


# ---------------------------------------------------------------------------
# Session-level aggregation
# ---------------------------------------------------------------------------

def compute_session_summary(per_ioc_scores: list[dict]) -> dict:
    """Aggregate per-IOC score dicts into a single session-level summary.

    The session label is driven by the *highest* IOC score in the batch
    (not the average), since a single malicious IOC is the operative signal
    for an L1 analyst.

    Args:
        per_ioc_scores: List of dicts returned by compute_confidence_score.

    Returns:
        Dict with keys: highest_score, highest_ioc, verdict_distribution,
        session_label. ``session_label`` names the *evidence strength* band
        (Strong / Moderate / Weak / Minimal), not a threat verdict — the
        verdict counts in ``summary`` come from the cascade in `ioc.verdict`.
    """
    if not per_ioc_scores:
        return {
            "highest_score": 0.0,
            "highest_ioc": None,
            "verdict_distribution": {},
            "session_label": "Minimal",
        }

    best = max(per_ioc_scores, key=lambda x: x.get("score", 0))

    distribution: dict[str, int] = {}
    for entry in per_ioc_scores:
        v = entry.get("verdict_from_score", "Unknown")
        distribution[v] = distribution.get(v, 0) + 1

    # Named for evidence strength rather than threat level ("Strong", not "High
    # Threat"): this sits next to the authoritative verdict counts in the hero,
    # and a threat-shaped word there reads as a second, competing verdict.
    highest = best.get("score", 0.0)
    if highest >= 70:
        session_label = "Strong"
    elif highest >= 40:
        session_label = "Moderate"
    elif highest >= 10:
        session_label = "Weak"
    else:
        session_label = "Minimal"

    return {
        "highest_score": highest,
        "highest_ioc": best.get("ioc_value"),
        "verdict_distribution": distribution,
        "session_label": session_label,
    }
