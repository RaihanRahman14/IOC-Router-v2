"""Threat state/level decision helpers for SOC L1 triage.

Threat State names follow the Unified Kill Chain phases. ``Exposure`` is the one
state outside it: it describes the asset's posture, not attacker activity. See
docs/threat_state_level_verdict.md.
"""
from __future__ import annotations

from typing import Dict, List


PREVENTION_ACTIONS = {"blocked", "isolated", "prevented", "quarantined", "denied", "terminated", "file cleaned"}

VERDICT_TRUE_POSITIVE_STATES = {"Execution", "Privilege Escalation", "Lateral Movement", "Persistence", "Impact"}

# States where an attack reached the target but did not progress past it.
ATTEMPT_STATES = {"Delivery", "Exploitation"}
VERDICT_TRUE_POSITIVE_LEVELS = {"High", "Very High"}

VERDICT_COLORS = {
    "False Positive": "#2ecc71",
    "Benign Positive": "#e67e22",
    "True Positive": "#e74c3c",
}


def determineThreatState(analysis_summary: dict) -> str:
    """Map evidence onto a single Unified Kill Chain stage.

    The two lowest rungs each hold a pair of alternatives at the same level:
    Reconnaissance replaces Exposure when recon was observed, and Exploitation
    replaces Delivery when a WAF saw an exploit payload aimed at the application.

    Args:
        analysis_summary: Dict carrying ``evidence`` and ``device_action``.

    Returns:
        The Threat State name.
    """
    evidence = analysis_summary.get("evidence", {}) if isinstance(analysis_summary, dict) else {}
    if not isinstance(evidence, dict):
        evidence = {}

    device_action = str(analysis_summary.get("device_action", "") or "").strip().lower()
    is_prevented = device_action in PREVENTION_ACTIONS

    # Override: impact signals always win (unless prevented — prevention caps at Delivery).
    if not is_prevented:
        if evidence.get("data_exfiltration") or evidence.get("service_disruption_or_encryption"):
            return "Impact"
        if evidence.get("persistence_mechanism"):
            return "Persistence"
        if evidence.get("lateral_movement"):
            return "Lateral Movement"
        if evidence.get("privilege_escalation"):
            return "Privilege Escalation"
        if evidence.get("malware_executed") or evidence.get("c2_connection"):
            return "Execution"

    # Blocked or not: a payload that reached a WAF says it was sent, not that it
    # worked. Success is only claimed through server-side evidence above.
    if evidence.get("web_exploit_payload"):
        return "Exploitation"

    if evidence.get("phishing_or_social_eng") or evidence.get("exploit_attempt") or (
        is_prevented and any([
            evidence.get("data_exfiltration"),
            evidence.get("service_disruption_or_encryption"),
            evidence.get("persistence_mechanism"),
            evidence.get("lateral_movement"),
            evidence.get("privilege_escalation"),
            evidence.get("malware_executed"),
            evidence.get("c2_connection"),
        ])
    ):
        return "Delivery"
    if evidence.get("scanning_or_recon"):
        return "Reconnaissance"
    return "Exposure"


def determineThreatLevel(threat_state: str, asset_criticality: str, evidence: dict) -> str:
    """Translate a Threat State into a severity band.

    Args:
        threat_state: Output of :func:`determineThreatState`.
        asset_criticality: ``"critical"`` raises the level; anything else does not.
        evidence: The evidence dict, for the hard overrides and floor rules.

    Returns:
        Low, Medium, High or Very High.
    """
    base = {
        "Exposure": "Low",
        "Reconnaissance": "Low",
        "Delivery": "Low",
        # Medium whether or not the WAF blocked it: an exploit payload aimed at
        # this application warrants a look even when it was stopped.
        "Exploitation": "Medium",
        "Execution": "Medium",
        "Privilege Escalation": "High",
        "Lateral Movement": "High",
        "Persistence": "High",
        "Impact": "Very High",
    }.get(threat_state, "Low")

    # Hard overrides.
    if evidence.get("data_exfiltration") or evidence.get("service_disruption_or_encryption"):
        return "Very High"

    level = base
    is_critical = str(asset_criticality or "").lower() == "critical"
    if is_critical:
        if threat_state == "Execution":
            level = "High"
        elif threat_state in ("Privilege Escalation", "Lateral Movement", "Persistence"):
            level = "Very High"
        elif threat_state == "Impact":
            level = "Very High"

    # Minimum floor rules.
    if evidence.get("persistence_mechanism") or evidence.get("lateral_movement") or evidence.get("privilege_escalation"):
        if level in ("Low", "Medium"):
            level = "High"

    return level


def buildReasons(threat_state: str, threat_level: str, analysis_summary: dict) -> List[str]:
    evidence = analysis_summary.get("evidence", {}) if isinstance(analysis_summary, dict) else {}
    if not isinstance(evidence, dict):
        evidence = {}
    notes = analysis_summary.get("risk_notes", []) if isinstance(analysis_summary, dict) else []
    if not isinstance(notes, list):
        notes = []

    reasons: List[str] = []
    if evidence.get("data_exfiltration"):
        reasons.append("Data exfiltration indicator observed")
    if evidence.get("service_disruption_or_encryption"):
        reasons.append("Service disruption/encryption behavior detected")
    if evidence.get("persistence_mechanism"):
        reasons.append("Persistence mechanism found")
    if evidence.get("lateral_movement"):
        reasons.append("Lateral movement activity detected")
    if evidence.get("privilege_escalation"):
        reasons.append("Privilege escalation indicator present")
    if evidence.get("malware_executed"):
        reasons.append("Malware execution evidence present")
    if evidence.get("c2_connection"):
        reasons.append("C2 communication observed")
    if evidence.get("scanning_or_recon"):
        reasons.append("Recon/scanning activity detected")
    if evidence.get("phishing_or_social_eng"):
        reasons.append("Phishing/social engineering indicator present")
    if evidence.get("web_exploit_payload"):
        reasons.append("Exploit payload observed in a WAF-flagged request")
    elif evidence.get("exploit_attempt"):
        reasons.append("Exploit attempt indicator present")
    if evidence.get("attack_prevented") and threat_state in ATTEMPT_STATES:
        reasons.append("Attempt appears blocked by controls")

    device_action = str(analysis_summary.get("device_action", "") or "").strip()
    if device_action.lower() in PREVENTION_ACTIONS:
        reasons.insert(0, f"Device action '{device_action}' — threat state capped at Exploitation or below")

    for note in notes:
        text = str(note).strip()
        if text:
            reasons.append(text)
        if len(reasons) >= 3:
            break

    if not reasons:
        reasons.append(f"{threat_state} observed with {threat_level} severity")
    return reasons[:3]


def determineVerdict(threat_state: str, threat_level: str, evidence: dict) -> str:
    """Return False Positive / Benign Positive / True Positive based on threat signals."""
    if threat_state in VERDICT_TRUE_POSITIVE_STATES or threat_level in VERDICT_TRUE_POSITIVE_LEVELS:
        return "True Positive"

    has_weak_signal = any([
        evidence.get("scanning_or_recon"),
        evidence.get("phishing_or_social_eng"),
        evidence.get("exploit_attempt"),
        evidence.get("web_exploit_payload"),
        evidence.get("attack_prevented"),
    ])
    if threat_state in ATTEMPT_STATES or threat_state == "Reconnaissance" or has_weak_signal:
        return "Benign Positive"

    return "False Positive"


def analyzeThreat(analysis_summary: Dict) -> Dict:
    evidence = analysis_summary.get("evidence", {}) if isinstance(analysis_summary, dict) else {}
    if not isinstance(evidence, dict):
        evidence = {}
    asset_criticality = analysis_summary.get("asset_criticality", "standard") if isinstance(analysis_summary, dict) else "standard"
    mitre = analysis_summary.get("mitre_tactics", []) if isinstance(analysis_summary, dict) else []
    if not isinstance(mitre, list):
        mitre = []

    threat_state = determineThreatState(analysis_summary)
    threat_level = determineThreatLevel(threat_state, str(asset_criticality), evidence)
    reasons = buildReasons(threat_state, threat_level, analysis_summary)
    verdict = determineVerdict(threat_state, threat_level, evidence)

    supporting = []
    if evidence.get("scanning_or_recon"):
        supporting.append("TA0043")
    if evidence.get("phishing_or_social_eng") or evidence.get("exploit_attempt"):
        supporting.append("TA0001")
    if evidence.get("malware_executed"):
        supporting.append("TA0002")
    if evidence.get("c2_connection"):
        supporting.append("TA0011")
    if evidence.get("privilege_escalation"):
        supporting.append("TA0004")
    if evidence.get("lateral_movement"):
        supporting.extend(["TA0008", "TA0007"])
    if evidence.get("persistence_mechanism"):
        supporting.extend(["TA0003", "TA0005"])
    if evidence.get("data_exfiltration"):
        supporting.append("TA0010")
    if evidence.get("service_disruption_or_encryption"):
        supporting.append("TA0040")

    for t in mitre:
        if isinstance(t, str):
            supporting.append(t)
    mitre_alignment = list(dict.fromkeys([t for t in supporting if t]))[:8]

    return {
        "threat_state": threat_state,
        "threat_level": threat_level,
        "verdict": verdict,
        "verdict_color": VERDICT_COLORS[verdict],
        "mitre_alignment": mitre_alignment,
        "reasons": reasons,
    }
