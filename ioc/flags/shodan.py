"""Threat flag extraction from Shodan results."""
from __future__ import annotations

from .base import _flag, _safe_int, _flag_from_infra


def _flags_shodan(sh: dict) -> list[dict]:
    flags: list[dict] = []
    if not isinstance(sh, dict) or not sh:
        return flags

    summary = sh.get("summary", {}) if isinstance(sh.get("summary"), dict) else {}
    rollup = (summary.get("shodan", {}) or {}).get("rollup", {}) if summary else {}
    ports = rollup.get("unique_ports") or sh.get("ports") or []
    cves = rollup.get("cves") or sh.get("vulns") or []
    tags = rollup.get("tags") or sh.get("tags") or []
    hostnames = sh.get("hostnames") or []

    n_ports = len(ports) if isinstance(ports, list) else 0
    n_cves = len(cves) if isinstance(cves, list) else 0

    if n_ports >= 20:
        flags.append(_flag(
            "SHODAN_VERY_WIDE_ATTACK_SURFACE",
            f"{n_ports} open ports exposed",
            "Extremely wide attack surface",
            "HIGH",
            ["TA0043", "T1046"],
            f"Ports: {list(ports)[:10]}",
            "Shodan",
        ))
    elif n_ports >= 10:
        flags.append(_flag(
            "SHODAN_WIDE_ATTACK_SURFACE",
            f"{n_ports} open ports exposed",
            "Wide attack surface / recon target",
            "MEDIUM",
            ["TA0043", "T1046"],
            f"Ports: {list(ports)[:10]}",
            "Shodan",
        ))

    if n_cves >= 5:
        flags.append(_flag(
            "SHODAN_MANY_CVES",
            f"{n_cves} CVEs detected on host",
            "Multiple unpatched vulnerabilities",
            "CRITICAL",
            ["T1190", "T1203"],
            f"CVEs: {list(cves)[:5]}",
            "Shodan",
        ))
    elif n_cves >= 1:
        flags.append(_flag(
            "SHODAN_CVE_PRESENT",
            f"{n_cves} CVE(s) detected on host",
            "Unpatched vulnerability present",
            "HIGH",
            ["T1190", "T1203"],
            f"CVEs: {list(cves)[:5]}",
            "Shodan",
        ))

    # High-risk service exposure
    risky_port_map = {
        23:   ("SHODAN_TELNET_OPEN",  "Telnet exposed (plaintext protocol)",  "Plaintext remote access risk", ["T1021"], "HIGH"),
        3389: ("SHODAN_RDP_OPEN",     "RDP exposed to internet",              "Remote Desktop — brute-force / exploitation risk", ["T1021.001", "T1190"], "HIGH"),
        445:  ("SHODAN_SMB_OPEN",     "SMB port 445 exposed",                 "SMB — lateral movement / ransomware risk", ["T1021.002", "T1486"], "HIGH"),
        5900: ("SHODAN_VNC_OPEN",     "VNC exposed to internet",              "Remote desktop takeover risk", ["T1021.005"], "HIGH"),
        1433: ("SHODAN_MSSQL_OPEN",   "MSSQL exposed to internet",            "Database exposed publicly", ["T1190"], "MEDIUM"),
        3306: ("SHODAN_MYSQL_OPEN",   "MySQL exposed to internet",            "Database exposed publicly", ["T1190"], "MEDIUM"),
        6379: ("SHODAN_REDIS_OPEN",   "Redis exposed without auth",           "Unauthenticated data store", ["T1190"], "HIGH"),
        27017:("SHODAN_MONGO_OPEN",   "MongoDB exposed to internet",          "Unauthenticated database", ["T1190"], "HIGH"),
    }
    for p in (ports if isinstance(ports, list) else []):
        p_int = _safe_int(p)
        if p_int in risky_port_map:
            fid, label, threat, mitre_list, sev = risky_port_map[p_int]
            flags.append(_flag(fid, label, threat, sev, mitre_list,
                               f"Port {p_int} open", "Shodan"))

    # Tags
    tag_list = [str(t).lower() for t in (tags if isinstance(tags, list) else [])]
    if "tor" in tag_list:
        flags.append(_flag(
            "SHODAN_TOR_NODE",
            "Host tagged as Tor node",
            "Anonymization / evasion infrastructure",
            "HIGH",
            ["T1090.003"],
            "Tag: tor",
            "Shodan",
        ))
    if "vpn" in tag_list:
        flags.append(_flag(
            "SHODAN_VPN_NODE",
            "Host tagged as VPN node",
            "Anonymization infrastructure",
            "MEDIUM",
            ["T1090"],
            "Tag: vpn",
            "Shodan",
        ))
    infra = sh.get("infra_classification")
    infra_flag = _flag_from_infra(infra, "Shodan")
    if infra_flag:
        flags.append(infra_flag)

    if "honeypot" in tag_list:
        flags.append(_flag(
            "SHODAN_HONEYPOT",
            "Host tagged as honeypot",
            "Possible deception / research node",
            "INFO",
            [],
            "Tag: honeypot",
            "Shodan",
        ))

    return flags
