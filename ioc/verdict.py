"""Verdict aggregation helpers.

**One authoritative verdict.** ``Verdict`` and ``Confidence`` — produced by the
rule cascade in :func:`summarize_results` — are the verdict of record. They are
what the results table, the ticket notes, and the AI prompt all report, and the
only fields any new consumer should read as "is this IOC bad".

The ``ConfidenceScore`` family that rides alongside them (from
``ioc.confidence_scorer``) is a *supporting signal*: it ranks how much
corroborating evidence the providers supplied. It deliberately does not decide
the verdict, because the two disagree often — a lone VirusTotal hit scores near
zero while the cascade calls it Malicious, and a confirmed MalwareBazaar sample
scores 100 while the cascade only reaches Suspicious. Rendering both as verdicts
put two different answers on one screen; the score is now presented as evidence
strength only. ``VerdictFromScore`` is kept in the row for that module's own
bookkeeping and must not be displayed as a verdict.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ioc.parser import IOC
from ioc.confidence_scorer import compute_confidence_score, compute_session_summary


def summarize_results(
    items: List[IOC],
    vt_results: Dict[str, dict],
    urlscan_results: Dict[str, dict],
    abuse_results: Dict[str, dict],
    threatfox_results: Dict[str, dict],
    malwarebazaar_results: Dict[str, dict],
    shodan_results: Optional[Dict[str, dict]] = None,
    hybrid_results: Optional[Dict[str, dict]] = None,
) -> Tuple[dict, List[dict]]:
    """Aggregate provider results into a verdict summary and per-IOC rows.

    Args:
        items: Parsed IOC objects in the batch.
        vt_results: VirusTotal results keyed by IOC value.
        urlscan_results: urlscan.io results keyed by IOC value.
        abuse_results: AbuseIPDB results keyed by IOC value.
        threatfox_results: ThreatFox results keyed by IOC value.
        malwarebazaar_results: MalwareBazaar results keyed by IOC value.
        shodan_results: Shodan results keyed by IOC value (optional).
        hybrid_results: Hybrid Analysis results keyed by IOC value (optional).

    Returns:
        Tuple of (summary, rows). `summary` carries the authoritative verdict
        counts plus a `session_summary` key holding the numeric score
        aggregation. `rows` contains the authoritative `Verdict` / `Confidence`
        pair plus the supporting `ConfidenceScore` family produced by
        `ioc.confidence_scorer` — see this module's docstring for which of the
        two decides.
    """
    summary = {
        "total": len(items),
        "malicious": 0,
        "suspicious": 0,
        "unknown": 0,
        "benign": 0,
    }
    rows: List[dict] = []
    per_ioc_scores: List[dict] = []

    for ioc in items:
        vt = vt_results.get(ioc.value) or {}
        us = urlscan_results.get(ioc.value) or {}
        ab = abuse_results.get(ioc.value) or {}
        tf = threatfox_results.get(ioc.value) or {}
        mb = malwarebazaar_results.get(ioc.value) or {}
        stats = vt.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        abuse_score = ab.get("abuseConfidenceScore", 0) if ab else 0
        urlscan_verdicts = us.get("verdicts", {}) if us else {}
        urlscan_mal = urlscan_verdicts.get("malicious", False)
        urlscan_phish = urlscan_verdicts.get("phishing", False)

        strong_sources = 0
        weak_sources = 0
        if malicious >= 3:
            strong_sources += 1
        elif malicious > 0:
            weak_sources += 1
        if suspicious > 0:
            weak_sources += 1
        if abuse_score >= 80:
            strong_sources += 1
        elif abuse_score >= 50:
            weak_sources += 1
        if urlscan_mal or urlscan_phish:
            weak_sources += 1
        if mb:
            weak_sources += 1
        if tf:
            weak_sources += 1

        if malicious > 0:
            verdict = "Malicious"
            summary["malicious"] += 1
            confidence = "High" if strong_sources >= 1 and (strong_sources + weak_sources) >= 2 else "Med"
            reason = f"VT: {malicious} engines flagged"
        elif suspicious > 0:
            verdict = "Suspicious"
            summary["suspicious"] += 1
            confidence = "Med"
            reason = f"VT: {suspicious} engines suspicious"
        elif abuse_score >= 80:
            verdict = "Malicious"
            summary["malicious"] += 1
            confidence = "High" if strong_sources >= 2 or (strong_sources >= 1 and weak_sources >= 1) else "Med"
            reason = f"AbuseIPDB score {abuse_score}"
        elif abuse_score >= 50 or urlscan_mal or urlscan_phish:
            verdict = "Suspicious"
            summary["suspicious"] += 1
            confidence = "Med" if (strong_sources + weak_sources) >= 2 else "Low"
            if abuse_score >= 50:
                reason = f"AbuseIPDB score {abuse_score}"
            else:
                reason = "urlscan verdict suspicious"
        elif mb:
            verdict = "Suspicious"
            summary["suspicious"] += 1
            confidence = "Med" if (strong_sources + weak_sources) >= 2 else "Low"
            reason = "MalwareBazaar hit"
        elif tf:
            verdict = "Suspicious"
            summary["suspicious"] += 1
            confidence = "Med" if (strong_sources + weak_sources) >= 2 else "Low"
            reason = "ThreatFox hit"
        elif harmless > 0 or undetected > 0:
            verdict = "Unknown"
            summary["unknown"] += 1
            confidence = "Low"
            reason = "VT: no detections"
        else:
            verdict = "Unknown"
            summary["unknown"] += 1
            confidence = "Low"
            reason = "No data"

        sources = []
        if vt:
            sources.append("VT")
        if us:
            sources.append("urlscan")
        if ab:
            sources.append("AbuseIPDB")
        if tf:
            sources.append("ThreatFox")
        if mb:
            sources.append("MalwareBazaar")

        conf_result = compute_confidence_score(
            ioc_value=ioc.value,
            vt_results=vt_results,
            abuse_results=abuse_results,
            threatfox_results=threatfox_results,
            shodan_results=shodan_results or {},
            hybrid_results=hybrid_results,
            malwarebazaar_results=malwarebazaar_results,
        )
        per_ioc_scores.append(conf_result)

        rows.append(
            {
                "Artifact": ioc.value,
                "Type": ioc.type,
                "Verdict": verdict,
                "Confidence": confidence,
                "Primary Evidence": reason,
                "Next Action": "Review",
                "Sources": ", ".join(sources) if sources else "",
                "ConfidenceScore":   conf_result["score"],
                "ConfidenceLabel":   conf_result["label"],
                "ProviderScores":    conf_result["provider_scores"],
                "ActiveProviders":   conf_result["active_providers"],
                "InfraNote":         conf_result["infra_note"],
                "VerdictFromScore":  conf_result["verdict_from_score"],
            }
        )

    # The cascade above has no Benign branch — its weakest outcome is Unknown
    # ("VT: no detections" / "No data"), so this count is structurally always
    # zero rather than incidentally so. The hero still renders the card to keep
    # the five verdict buckets visible; giving the cascade a real Benign branch
    # is a scoring change, deliberately out of scope here.
    summary["benign"] = 0
    summary["session_summary"] = compute_session_summary(per_ioc_scores)
    return summary, rows
