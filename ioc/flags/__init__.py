"""
Threat flag extraction from all provider results.

Each flag represents one observable indicator derived from provider data.
Framework references:
  - MITRE ATT&CK Enterprise (tactics TA00xx, techniques Txxxx)
  - CIS Controls v8 for severity framing
  - Custom SOC-L1 indicators where no standard applies

Flag severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
"""
from __future__ import annotations

from .virustotal import _flags_virustotal
from .urlscan import _flags_urlscan
from .abuseipdb import _flags_abuseipdb
from .shodan import _flags_shodan
from .threatfox import _flags_threatfox
from .malwarebazaar import _flags_malwarebazaar
from .hybrid_analysis import _flags_hybrid_analysis
from .dnsdumpster import _flags_dnsdumpster
from .multisource import _flags_multisource
from .mxtoolbox import _flags_mxtoolbox
from .ransomware_live import _flags_ransomware_live


def extract_ioc_flags(
    ioc_value: str,
    ioc_type: str,
    vt: dict,
    us: dict,
    ab: dict,
    tf: dict,
    mb: dict,
    sh: dict,
    dnsd: dict,
    ha: dict,
    mx: dict | None = None,
    rl: dict | None = None,
) -> list[dict]:
    """
    Extract all threat flags for a single IOC from all provider results.

    Returns a list of flag dicts sorted by severity (CRITICAL first).
    """
    flags: list[dict] = []

    flags.extend(_flags_virustotal(vt))
    flags.extend(_flags_urlscan(us))
    flags.extend(_flags_abuseipdb(ab))
    flags.extend(_flags_shodan(sh))
    flags.extend(_flags_threatfox(tf))
    flags.extend(_flags_malwarebazaar(mb))
    flags.extend(_flags_hybrid_analysis(ha))
    flags.extend(_flags_dnsdumpster(dnsd))
    flags.extend(_flags_multisource(vt, us, ab, tf, mb, ha))
    flags.extend(_flags_mxtoolbox(mx or {}))
    flags.extend(_flags_ransomware_live(rl or {}))

    # Deduplicate by id
    seen_ids: set[str] = set()
    unique: list[dict] = []
    for f in flags:
        if f["id"] not in seen_ids:
            seen_ids.add(f["id"])
            unique.append(f)

    # Sort: CRITICAL > HIGH > MEDIUM > LOW > INFO
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unique.sort(key=lambda f: order.get(f["severity"], 5))

    return unique


def flags_to_ai_context(flags: list[dict]) -> str:
    """
    Serialize flags into a compact string for injection into AI prompts.
    Groups by severity for readability.
    """
    if not flags:
        return "No threat flags detected."

    lines: list[str] = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = [f for f in flags if f["severity"] == sev]
        if not group:
            continue
        lines.append(f"[{sev}]")
        for f in group:
            mitre_str = ", ".join(f["mitre"]) if f["mitre"] else "—"
            lines.append(
                f"  • {f['label']} | Type: {f['threat_type']} | MITRE: {mitre_str}"
                + (f" | {f['detail']}" if f.get("detail") else "")
            )
    return "\n".join(lines)


def flags_summary_for_evidence(flags: list[dict]) -> dict:
    """
    Map flags back into the evidence dict structure used by _build_analysis_summary.
    """
    ev: dict[str, bool] = {
        "attack_prevented": False,
        "scanning_or_recon": False,
        "phishing_or_social_eng": False,
        "exploit_attempt": False,
        "malware_executed": False,
        "c2_connection": False,
        "privilege_escalation": False,
        "lateral_movement": False,
        "persistence_mechanism": False,
        "data_exfiltration": False,
        "service_disruption_or_encryption": False,
    }
    tactics: set[str] = set()
    notes: list[str] = []

    for f in flags:
        fid = f["id"]
        sev = f["severity"]
        for t in f.get("mitre", []):
            tactics.add(t)

        if sev in ("CRITICAL", "HIGH") and len(notes) < 8:
            notes.append(f['label'])

        # Map flag IDs to evidence keys
        if any(k in fid for k in ("MALWARE", "YARA", "SIGMA", "SANDBOX_PROCESS", "SANDBOX_FILE", "MB_KNOWN", "MB_SIGNATURE", "HA_MALICIOUS", "HA_KNOWN_FAMILY", "VT_HIGH_MALICIOUS", "VT_MALICIOUS_DETECTION")):
            ev["malware_executed"] = True
        if any(k in fid for k in ("C2", "NETWORK_COMMS", "TF_C2", "HA_NETWORK")):
            ev["c2_connection"] = True
        if any(k in fid for k in ("PHISHING", "BRAND_IMP", "CREDENTIAL_HARVEST", "TF_PHISH", "MX_SPF_FAIL", "MX_DMARC_FAIL", "MX_SPF_WARN", "MX_DMARC_WARN", "MX_BLACKLIST_HIT", "MX_BLACKLIST_CRITICAL")):
            ev["phishing_or_social_eng"] = True
        if any(k in fid for k in ("EXPLOIT", "SQLI", "WEBATTACK", "CVE")):
            ev["exploit_attempt"] = True
        if any(k in fid for k in ("PORTSCAN", "RECON", "SCANNING", "WIDE_ATTACK", "MX_DNS_FAIL")):
            ev["scanning_or_recon"] = True
        if any(k in fid for k in ("PERSISTENCE", "REGISTRY_MOD", "MUTEX")):
            ev["persistence_mechanism"] = True
        if any(k in fid for k in ("LATERAL", "SMB", "RDP")):
            ev["lateral_movement"] = True
        if any(k in fid for k in ("PRIVESC", "PROCESS_INJECTION")):
            ev["privilege_escalation"] = True
        if any(k in fid for k in ("MALWARE_DOWNLOAD", "DOWNLOAD_SERVED")):
            ev["malware_executed"] = True
        if any(k in fid for k in ("RANSOMWARE", "RL_VICTIM", "RL_RECENT")):
            ev["service_disruption_or_encryption"] = True

        # Process-analysis flags (core.process_analyzer). Without these the
        # module's findings would reach the Threat Analysis narrative with an
        # empty evidence dict and silently score as "Exposure".
        #
        # All three map to `malware_executed` ("Compromise"), not
        # `persistence_mechanism` ("Persistence"): impersonating a system binary
        # or spawning a shell from Office says something ran that should not
        # have, but says nothing about a persistence mechanism being installed.
        # A prevented Device Action still caps the state at Intrusion Attempt.
        if any(k in fid for k in (
            "MASQUERADING", "PARENT_CHAIN_CONTAMINATION", "SUSPICIOUS_PARENT_CHILD_PAIR",
        )):
            ev["malware_executed"] = True

    return {
        "evidence": ev,
        "mitre_tactics": sorted(tactics),
        "notes": notes,
    }
