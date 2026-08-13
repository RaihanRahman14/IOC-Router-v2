"""Shodan client."""
from __future__ import annotations

import ipaddress
import socket
import time
from urllib.parse import urlparse

import requests

from config import Settings
from core.http import get_session
from core.infra_classifier import classify as classify_infra, lookup_asn
from ioc.parser import IOC


INTERNETDB_BASE = "https://internetdb.shodan.io"
HIGH_RISK_PORTS = {22, 23, 3389, 445, 5900, 3306, 5432, 27017, 6379, 9200}
COMMON_WEB_PORTS = {80, 443}
STRONG_RISK_TAGS = {"malware", "compromised"}


def _host_from_url(value: str) -> str:
    try:
        parsed = urlparse(value)
    except ValueError:
        return ""
    return (parsed.hostname or "").strip().lower()


def _resolve_ips(host: str) -> list[str]:
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    found: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    for info in infos:
        addr = info[4][0]
        if addr not in found:
            found.append(addr)
    return found


def _targets(ioc: IOC) -> list[str]:
    if ioc.type == "ip":
        return [ioc.value]
    if ioc.type == "domain":
        return _resolve_ips(ioc.value)
    if ioc.type == "url":
        return _resolve_ips(_host_from_url(ioc.value))
    return []


def scoreRisk(item: dict) -> dict:
    ports = [int(p) for p in (item.get("ports") or []) if isinstance(p, int) or str(p).isdigit()]
    vulns = [v for v in (item.get("vulns") or []) if isinstance(v, str) and v.strip()]
    tags = [t.lower() for t in (item.get("tags") or []) if isinstance(t, str)]

    risky_port_present = any(p in HIGH_RISK_PORTS for p in ports)
    strong_tag_present = any(t in STRONG_RISK_TAGS for t in tags)
    many_open_ports = len(set(ports)) >= 10

    reasons: list[str] = []
    if (len(vulns) >= 1 and risky_port_present) or strong_tag_present:
        risk_level = "HIGH"
        confidence = 90
        if len(vulns) >= 1 and risky_port_present:
            reasons.append("CVE ditemukan pada service berisiko")
        if strong_tag_present:
            reasons.append("Tag kompromi/malware terdeteksi")
    elif (risky_port_present and len(vulns) == 0) or many_open_ports:
        risk_level = "MEDIUM"
        confidence = 70
        if risky_port_present and len(vulns) == 0:
            reasons.append("Port berisiko terbuka tanpa data CVE")
        if many_open_ports:
            reasons.append("Banyak port terbuka")
    elif ports and set(ports).issubset(COMMON_WEB_PORTS) and len(vulns) == 0:
        risk_level = "LOW"
        confidence = 35
        reasons.append("Hanya port web umum tanpa CVE")
    elif not ports and not vulns and not (item.get("cpes") or []) and not (item.get("hostnames") or []) and not (item.get("tags") or []):
        risk_level = "UNKNOWN"
        confidence = 20
        reasons.append("Data InternetDB tidak tersedia")
    else:
        risk_level = "LOW"
        confidence = 30
        reasons.append("Tidak ada indikator risiko kuat")

    return {
        "risk_level": risk_level,
        "reasons": reasons[:3],
        "confidence": confidence,
    }


def _internetdb_get(ip: str, timeout: int = 10) -> tuple[dict | None, str | None]:
    url = f"{INTERNETDB_BASE}/{ip}"
    attempts = 0
    timeout_retry_done = False
    rate_retry_done = False
    while attempts < 3:
        attempts += 1
        try:
            response = get_session().get(url, timeout=timeout)
        except requests.Timeout:
            if not timeout_retry_done:
                timeout_retry_done = True
                continue
            return None, "timeout"
        except requests.RequestException:
            return None, "request_error"

        if response.status_code == 200:
            try:
                return response.json(), None
            except ValueError:
                return None, "invalid_json"
        if response.status_code == 404:
            return None, "not_found"
        if response.status_code == 429:
            if not rate_retry_done:
                rate_retry_done = True
                time.sleep(1.0)
                continue
            return None, "rate_limited"
        if 500 <= response.status_code <= 599 and attempts < 2:
            continue
        return None, f"http_{response.status_code}"
    return None, "unknown_error"


def enrichWithInternetDB(resolvedIps: list[str]) -> list[dict]:
    results: list[dict] = []
    seen = set()
    for raw_ip in resolvedIps or []:
        ip = (raw_ip or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)

        payload, error = _internetdb_get(ip)
        if payload is None:
            item = {
                "ip": ip,
                "ports": [],
                "hostnames": [],
                "cpes": [],
                "vulns": [],
                "tags": [],
            }
            risk = {
                "risk_level": "UNKNOWN",
                "reasons": [f"InternetDB error: {error or 'unknown'}"][:3],
                "confidence": 20,
            }
            item["risk_summary"] = risk
            results.append(item)
            continue

        item = {
            "ip": ip,
            "ports": payload.get("ports") if isinstance(payload.get("ports"), list) else [],
            "hostnames": payload.get("hostnames") if isinstance(payload.get("hostnames"), list) else [],
            "cpes": payload.get("cpes") if isinstance(payload.get("cpes"), list) else [],
            "vulns": payload.get("vulns") if isinstance(payload.get("vulns"), list) else [],
            "tags": payload.get("tags") if isinstance(payload.get("tags"), list) else [],
        }
        item["risk_summary"] = scoreRisk(item)
        item["infra_classification"] = _classify_ip_infra(ip)
        results.append(item)
    return results


def _classify_ip_infra(ip: str) -> dict | None:
    """Look up ASN for ``ip`` and classify it as BP / FP / HIGH_RISK.

    Args:
        ip: IPv4 / IPv6 address string.

    Returns:
        Classification dict from ``core.infra_classifier.classify`` or
        ``None`` when ASN lookup fails or the infra is unrecognized.
    """
    asn, org = lookup_asn(ip)
    if asn is None and not org:
        return None
    return classify_infra(asn=asn, org=org, ip=ip)


def buildRollup(results: list[dict]) -> dict:
    def _uniq_sorted(values: list) -> list:
        uniq = {v for v in values if isinstance(v, str) and v.strip()}
        return sorted(uniq)

    ports = set()
    vulns: list[str] = []
    cpes: list[str] = []
    hostnames: list[str] = []
    tags: list[str] = []

    for row in results or []:
        for p in (row.get("ports") or []):
            if isinstance(p, int) or str(p).isdigit():
                ports.add(int(p))
        vulns.extend(row.get("vulns") or [])
        cpes.extend(row.get("cpes") or [])
        hostnames.extend(row.get("hostnames") or [])
        tags.extend(row.get("tags") or [])

    return {
        "unique_ports": sorted(ports),
        "unique_vulns": _uniq_sorted(vulns),
        "unique_cpes": _uniq_sorted(cpes),
        "unique_hostnames": _uniq_sorted(hostnames),
        "unique_tags": _uniq_sorted(tags),
    }


def summarize_shodan_internetdb(target: dict, now_utc=None) -> dict:
    input_type = target.get("input_type") or "ip"
    value = target.get("value") or ""
    resolved_ips = target.get("resolved_ips") or []
    if input_type == "ip" and not resolved_ips and value:
        resolved_ips = [value]

    results = enrichWithInternetDB(resolved_ips)
    rollup = buildRollup(results)

    levels = [r.get("risk_summary", {}).get("risk_level") for r in results]
    if "HIGH" in levels:
        recommended_action = "Korelasi dengan SIEM/EDR, cek apakah aset milik internal/third-party, pertimbangkan block/contain jika sesuai policy, eskalasi L2"
    elif "MEDIUM" in levels:
        recommended_action = "Korelasi cepat (DNS, ASN/Org, log koneksi), monitor, eskalasi jika ada indikator tambahan"
    elif "LOW" in levels:
        recommended_action = "Dokumentasi, monitor pasif"
    else:
        recommended_action = "Ulangi enrichment atau gunakan sumber lain (AbuseIPDB/VT/urlscan) jika tersedia"

    return {
        "input": {
            "type": input_type,
            "value": value,
            "resolved_ips": resolved_ips,
        },
        "shodan": {
            "source": "internetdb",
            "results": results,
            "rollup": rollup,
        },
        "recommended_action": recommended_action,
    }


def shodan_lookup_batch(items: list[IOC], settings: Settings) -> dict[str, dict]:
    # Membership-less mode: use InternetDB only (no /shodan/host/{ip} call).
    out: dict[str, dict] = {}
    for ioc in items:
        targets = _targets(ioc)
        if not targets:
            out[ioc.value] = {"error": f"No resolvable IP for IOC type '{ioc.type}'"}
            continue
        summary = summarize_shodan_internetdb(
            {
                "input_type": ioc.type,
                "value": ioc.value,
                "resolved_ips": targets,
            }
        )
        results = summary.get("shodan", {}).get("results", [])
        selected = results[0] if results else None
        out[ioc.value] = {
            "summary": summary,
            "ports": (selected or {}).get("ports", []),
            "org": None,
            "isp": None,
            "tags": (selected or {}).get("tags", []),
            "hostnames": (selected or {}).get("hostnames", []),
            "vulns": (selected or {}).get("vulns", []),
            "cpes": (selected or {}).get("cpes", []),
            "queriedIp": (selected or {}).get("ip"),
            "queriedIps": targets,
            "risk_summary": (selected or {}).get("risk_summary", {"risk_level": "UNKNOWN", "reasons": ["No InternetDB result"], "confidence": 20}),
            "infra_classification": (selected or {}).get("infra_classification"),
        }
    return out
