"""Threat flag extraction from VirusTotal results."""
from __future__ import annotations

from .base import _flag, _days_since, _safe_int, _flag_from_infra


def _flags_virustotal(vt: dict) -> list[dict]:
    flags: list[dict] = []
    if not isinstance(vt, dict) or not vt:
        return flags

    attrs = vt.get("attributes", {}) or {}
    stats = vt.get("stats", {}) or {}
    analysis = vt.get("analysis_results", {}) or {}

    mal = _safe_int(stats.get("malicious"))
    sus = _safe_int(stats.get("suspicious"))
    total = sum(_safe_int(v) for v in stats.values()) if stats else 0

    infra = vt.get("infra_classification")
    infra_flag = _flag_from_infra(infra, "VirusTotal")
    if infra_flag:
        flags.append(infra_flag)

    # --- Detection counts ---
    if mal >= 10:
        flags.append(_flag(
            "VT_HIGH_MALICIOUS_DETECTION",
            f"{mal} AV engines flagged as malicious",
            "Malware / Known bad indicator",
            "CRITICAL",
            ["TA0002", "T1204"],
            f"{mal}/{total} engines: malicious",
            "VirusTotal",
        ))
    elif mal >= 3:
        flags.append(_flag(
            "VT_MALICIOUS_DETECTION",
            f"{mal} AV engines flagged as malicious",
            "Malware / Phishing delivery",
            "HIGH",
            ["TA0002", "T1566"],
            f"{mal}/{total} engines: malicious",
            "VirusTotal",
        ))
    elif mal == 1 or mal == 2:
        flags.append(_flag(
            "VT_LOW_MALICIOUS_DETECTION",
            f"{mal} AV engine flagged as malicious",
            "Potentially malicious",
            "MEDIUM",
            ["TA0002"],
            f"{mal}/{total} engines: malicious",
            "VirusTotal",
        ))

    if sus >= 5:
        flags.append(_flag(
            "VT_SUSPICIOUS_DETECTION",
            f"{sus} AV engines flagged as suspicious",
            "Potentially unwanted / Gray area",
            "MEDIUM",
            ["TA0002"],
            f"{sus}/{total} engines: suspicious",
            "VirusTotal",
        ))

    # --- Specific engine labels ---
    flagged_labels = set()
    for res in analysis.values():
        if isinstance(res, dict) and res.get("category") in ("malicious", "suspicious"):
            r = str(res.get("result") or "").lower()
            for kw, threat, mitre_list in [
                ("phish", "Phishing", ["TA0001", "T1566.002"]),
                ("trojan", "Trojan", ["TA0002", "T1204"]),
                ("ransomware", "Ransomware", ["TA0040", "T1486"]),
                ("spyware", "Spyware / Infostealer", ["TA0009", "T1056"]),
                ("backdoor", "Backdoor", ["TA0003", "T1543"]),
                ("downloader", "Downloader / Dropper", ["TA0002", "T1105"]),
                ("exploit", "Exploit", ["TA0001", "T1190"]),
                ("c2", "C2 infrastructure", ["TA0011", "T1071"]),
                ("miner", "Cryptominer", ["TA0040", "T1496"]),
                ("rat", "Remote Access Trojan (RAT)", ["TA0011", "T1219"]),
                ("worm", "Worm", ["TA0008", "T1080"]),
                ("spam", "Spam / Unsolicited traffic", ["TA0001"]),
            ]:
                if kw in r and threat not in flagged_labels:
                    flagged_labels.add(threat)
                    flags.append(_flag(
                        f"VT_ENGINE_LABEL_{kw.upper()}",
                        f"Engine detected: {threat}",
                        threat,
                        "HIGH" if kw not in ("spam",) else "MEDIUM",
                        mitre_list,
                        f"Label: {r[:80]}",
                        "VirusTotal",
                    ))
                    break

    # --- Categories from vendor classification ---
    cats = attrs.get("categories", {}) or {}
    if isinstance(cats, dict):
        cat_vals = " ".join(cats.values()).lower()
        for kw, threat, mitre_list, sev in [
            ("phishing", "Phishing site categorized by vendor", ["TA0001", "T1566.002"], "HIGH"),
            ("malware", "Malware hosting site", ["TA0002"], "HIGH"),
            ("command and control", "C2 server categorized", ["TA0011", "T1071"], "CRITICAL"),
            ("botnet", "Botnet node", ["TA0011", "T1583.005"], "HIGH"),
            ("ransomware", "Ransomware-related domain", ["TA0040", "T1486"], "CRITICAL"),
            ("spam", "Spam distribution", ["TA0001"], "LOW"),
            ("cryptomining", "Cryptominer hosting", ["TA0040", "T1496"], "MEDIUM"),
            ("hacking", "Hacking tools / content", ["TA0042"], "MEDIUM"),
        ]:
            if kw in cat_vals:
                flags.append(_flag(
                    f"VT_CATEGORY_{kw.upper().replace(' ', '_')}",
                    threat,
                    threat,
                    sev,
                    mitre_list,
                    f"Vendor categories: {', '.join(set(cats.values()))[:120]}",
                    "VirusTotal",
                ))

    # --- Reputation ---
    rep = attrs.get("reputation")
    if rep is not None:
        rep = _safe_int(rep)
        if rep <= -20:
            flags.append(_flag(
                "VT_VERY_NEGATIVE_REPUTATION",
                f"Very low community reputation ({rep})",
                "Known bad actor",
                "HIGH",
                [],
                f"Reputation score: {rep}",
                "VirusTotal",
            ))
        elif rep <= -5:
            flags.append(_flag(
                "VT_NEGATIVE_REPUTATION",
                f"Negative community reputation ({rep})",
                "Community-flagged as suspicious",
                "MEDIUM",
                [],
                f"Reputation score: {rep}",
                "VirusTotal",
            ))

    # --- Domain age ---
    creation_date = attrs.get("creation_date")
    if creation_date:
        age = _days_since(creation_date)
        if age is not None and age <= 14:
            flags.append(_flag(
                "VT_DOMAIN_VERY_NEW",
                f"Domain registered {age} days ago",
                "Newly registered domain — common in phishing/malware campaigns",
                "HIGH",
                ["T1583.001"],
                f"Age: {age} days",
                "VirusTotal",
            ))
        elif age is not None and age <= 30:
            flags.append(_flag(
                "VT_DOMAIN_RECENTLY_CREATED",
                f"Domain registered {age} days ago",
                "Recently registered domain",
                "MEDIUM",
                ["T1583.001"],
                f"Age: {age} days",
                "VirusTotal",
            ))

    # --- Crowdsourced YARA ---
    yara = attrs.get("crowdsourced_yara_results") or []
    if isinstance(yara, list) and yara:
        names = [y.get("rule_name", "") for y in yara[:3] if isinstance(y, dict)]
        flags.append(_flag(
            "VT_YARA_MATCH",
            f"{len(yara)} YARA rule(s) matched",
            "Known malware pattern match",
            "HIGH",
            ["TA0002", "T1204"],
            "Rules: " + ", ".join(n for n in names if n),
            "VirusTotal",
        ))

    # --- SIGMA rules ---
    sigma = attrs.get("sigma_analysis_results") or []
    if isinstance(sigma, list) and sigma:
        sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
        top_sev = "MEDIUM"
        for s in sigma:
            if isinstance(s, dict):
                lvl = str(s.get("rule_level") or "").lower()
                if sev_map.get(lvl, "LOW") == "CRITICAL":
                    top_sev = "CRITICAL"
                    break
                elif sev_map.get(lvl, "LOW") == "HIGH":
                    top_sev = "HIGH"
        flags.append(_flag(
            "VT_SIGMA_MATCH",
            f"{len(sigma)} SIGMA rule(s) matched",
            "Behavioral threat detection",
            top_sev,
            ["TA0002"],
            f"{len(sigma)} rules fired",
            "VirusTotal",
        ))

    # --- IDS rules ---
    ids = attrs.get("crowdsourced_ids_results") or []
    if isinstance(ids, list) and ids:
        flags.append(_flag(
            "VT_IDS_MATCH",
            f"{len(ids)} IDS/IPS rule(s) matched",
            "Known network attack pattern",
            "HIGH",
            ["TA0011", "T1071"],
            f"{len(ids)} rules fired",
            "VirusTotal",
        ))

    # --- Redirect chain (URL) ---
    rchain = attrs.get("redirection_chain") or []
    if isinstance(rchain, list) and len(rchain) >= 3:
        flags.append(_flag(
            "VT_LONG_REDIRECT_CHAIN",
            f"URL redirect chain: {len(rchain)} hops",
            "Redirect chain evasion",
            "MEDIUM",
            ["T1027", "T1036"],
            f"{len(rchain)} hops observed",
            "VirusTotal",
        ))

    # --- Trackers (URL) ---
    trackers = attrs.get("trackers") or {}
    if isinstance(trackers, dict) and len(trackers) >= 5:
        flags.append(_flag(
            "VT_MANY_TRACKERS",
            f"{len(trackers)} tracking scripts detected",
            "Aggressive data collection / privacy risk",
            "LOW",
            ["T1056"],
            f"Trackers: {', '.join(list(trackers.keys())[:5])}",
            "VirusTotal",
        ))

    # --- Sandbox behavior ---
    beh = vt.get("behavior") or {}
    if isinstance(beh, dict) and beh:
        procs = beh.get("processes_created") or []
        files = beh.get("files_dropped") or beh.get("files_written") or []
        net = beh.get("network_communications") or {}
        reg = beh.get("registry_keys_set") or []
        mutex = beh.get("mutexes_created") or []

        if procs:
            flags.append(_flag(
                "VT_SANDBOX_PROCESS_CREATION",
                f"Sandbox: {len(procs)} process(es) created",
                "Execution behavior observed in sandbox",
                "HIGH",
                ["TA0002", "T1059"],
                f"Processes: {', '.join(str(p) for p in procs[:3])}",
                "VirusTotal (Sandbox)",
            ))
        if files:
            flags.append(_flag(
                "VT_SANDBOX_FILE_DROP",
                f"Sandbox: {len(files)} file(s) dropped/written",
                "Payload dropper behavior",
                "HIGH",
                ["TA0002", "T1105"],
                f"Files: {', '.join((f.get('path') or str(f)) if isinstance(f, dict) else str(f) for f in files[:3])}",
                "VirusTotal (Sandbox)",
            ))
        if isinstance(net, dict):
            dns_hits = net.get("dns_lookups") or []
            http_hits = net.get("http_conversations") or []
            if dns_hits or http_hits:
                flags.append(_flag(
                    "VT_SANDBOX_NETWORK_COMMS",
                    f"Sandbox: network communication observed ({len(dns_hits)} DNS, {len(http_hits)} HTTP)",
                    "C2 or exfiltration network behavior",
                    "HIGH",
                    ["TA0011", "T1071"],
                    "Network activity in sandbox",
                    "VirusTotal (Sandbox)",
                ))
        if reg:
            flags.append(_flag(
                "VT_SANDBOX_REGISTRY_MOD",
                f"Sandbox: {len(reg)} registry key(s) modified",
                "Persistence or configuration tampering",
                "HIGH",
                ["TA0003", "T1547"],
                f"Keys: {', '.join((r.get('key') or str(r)) if isinstance(r, dict) else str(r) for r in reg[:3])}",
                "VirusTotal (Sandbox)",
            ))
        if mutex:
            flags.append(_flag(
                "VT_SANDBOX_MUTEX",
                f"Sandbox: {len(mutex)} mutex(es) created",
                "Mutex creation — anti-reinfection or coordination signal",
                "MEDIUM",
                ["TA0002"],
                f"Mutexes: {', '.join(str(m) for m in mutex[:3])}",
                "VirusTotal (Sandbox)",
            ))

    return flags
