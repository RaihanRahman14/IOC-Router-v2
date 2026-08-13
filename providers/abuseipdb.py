"""AbuseIPDB client."""
from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

from config import Settings
from core.http import get_session
from ioc.parser import IOC


ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
ABUSE_CATEGORY_MAP = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _parse_iso_utc(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_category(value) -> str | None:
    if isinstance(value, int):
        return ABUSE_CATEGORY_MAP.get(value, str(value))
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        if stripped.isdigit():
            as_int = _safe_int(stripped, -1)
            return ABUSE_CATEGORY_MAP.get(as_int, stripped)
        return stripped
    return None


def _extract_unique_categories(data: dict) -> list[str]:
    unique: list[str] = []
    seen = set()

    reports = data.get("reports") or []
    if isinstance(reports, list):
        for rep in reports:
            if not isinstance(rep, dict):
                continue
            categories = rep.get("categories") or []
            if not isinstance(categories, list):
                continue
            for cat in categories:
                normalized = _normalize_category(cat)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    unique.append(normalized)

    data_categories = data.get("categories")
    if isinstance(data_categories, list):
        for cat in data_categories:
            normalized = _normalize_category(cat)
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
    elif isinstance(data_categories, dict):
        for key in data_categories.keys():
            normalized = _normalize_category(key)
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)

    return unique


def classify_abuseipdb_check(
    abuseipdb_response: dict,
    ip: str | None = None,
    now_utc: datetime | None = None,
) -> dict:
    """Classify AbuseIPDB /check response into SOC L1-oriented risk summary."""
    data = abuseipdb_response.get("data", {}) if isinstance(abuseipdb_response, dict) else {}
    if not isinstance(data, dict):
        data = {}

    score = _safe_int(data.get("abuseConfidenceScore"), 0)
    total_reports = _safe_int(data.get("totalReports"), 0)
    last_reported_at = data.get("lastReportedAt") if isinstance(data.get("lastReportedAt"), str) else None
    categories = _extract_unique_categories(data)

    if score > 75:
        risk_level = "HIGH"
        interpretation = "High risk, likely malicious"
    elif score >= 50:
        risk_level = "MEDIUM"
        interpretation = "Medium risk, investigate"
    else:
        risk_level = "LOW"
        interpretation = "Low risk, likely benign or scanner"

    if total_reports > 10:
        report_weight = "HIGH"
        report_interpretation = "Investigate thoroughly"
    elif total_reports >= 1:
        report_weight = "MEDIUM"
        report_interpretation = "Low-moderate concern"
    else:
        report_weight = "LOW"
        report_interpretation = "No prior reports"

    category_flag = len(categories) > 1
    if category_flag:
        category_interpretation = "More concerning"
    else:
        category_interpretation = "Single/no category"

    now_value = now_utc.astimezone(timezone.utc) if now_utc else datetime.now(timezone.utc)
    last_dt = _parse_iso_utc(last_reported_at)
    recency_flag = False
    if last_dt is not None:
        age = now_value - last_dt
        recency_flag = timedelta(0) <= age <= timedelta(days=7)
    recency_interpretation = "Active threat" if recency_flag else "Not recent/unknown"

    if risk_level == "HIGH":
        final_verdict = "MALICIOUS"
    elif risk_level == "MEDIUM":
        if recency_flag or category_flag or report_weight == "HIGH":
            final_verdict = "SUSPICIOUS"
        else:
            final_verdict = "LIKELY_BENIGN"
    else:
        if recency_flag and total_reports > 0:
            final_verdict = "SUSPICIOUS"
        else:
            final_verdict = "LIKELY_BENIGN"

    if final_verdict == "MALICIOUS":
        recommended_action = "Block/contain jika sesuai policy, kumpulkan bukti log, eskalasi ke L2/IR"
    elif final_verdict == "SUSPICIOUS":
        recommended_action = "Korelasi dengan DNS/SIEM/EDR, cek proses & user, pertimbangkan block sementara, eskalasi jika ada indikasi kuat"
    else:
        recommended_action = "Dokumentasi, monitor, tidak perlu tindakan agresif"

    ip_value = ip or data.get("ipAddress")

    return {
        "ip": ip_value,
        "abuse_confidence_score": score,
        "risk_level": risk_level,
        "interpretation": interpretation,
        "total_reports": total_reports,
        "report_weight": report_weight,
        "report_interpretation": report_interpretation,
        "categories": categories,
        "category_flag": category_flag,
        "category_interpretation": category_interpretation,
        "last_reported_at": last_reported_at,
        "recency_flag": recency_flag,
        "recency_interpretation": recency_interpretation,
        "final_verdict": final_verdict,
        "recommended_action": recommended_action,
    }


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


def abuseipdb_lookup_batch(items: list[IOC], settings: Settings) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not settings.abuse_key:
        for ioc in items:
            out[ioc.value] = {"error": "ABUSEIPDB_KEY is missing"}
        return out
    for ioc in items:
        targets = _targets(ioc)
        if not targets:
            out[ioc.value] = {"error": f"No resolvable IP for IOC type '{ioc.type}'"}
            continue
        best: dict | None = None
        last_error = ""
        for target in targets:
            try:
                r = get_session().get(
                    f"{ABUSE_BASE}/check",
                    headers={"Key": settings.abuse_key, "Accept": "application/json"},
                    params={"ipAddress": target, "maxAgeInDays": 90, "verbose": True},
                    timeout=15,
                )
            except requests.RequestException as exc:
                last_error = str(exc)
                continue
            if r.status_code != 200:
                body = (r.text or "").strip().replace("\n", " ")
                last_error = f"HTTP {r.status_code}: {body[:180]}"
                continue

            data = r.json().get("data", {})
            reports = data.get("reports", []) or []
            category_counts: dict[int, int] = {}
            parsed_reports: list[dict] = []
            for rep in reports:
                cats = rep.get("categories") or []
                cat_codes: list[int] = []
                for c in cats:
                    try:
                        c_int = int(c)
                    except Exception:
                        continue
                    cat_codes.append(c_int)
                    category_counts[c_int] = category_counts.get(c_int, 0) + 1
                reporter = (
                    rep.get("reporterCountryName")
                    or rep.get("reporterCountryCode")
                    or rep.get("reporterId")
                )
                parsed_reports.append(
                    {
                        "reporter": reporter,
                        "ioaTimestamp": rep.get("reportedAt"),
                        "comment": rep.get("comment"),
                        "categories": cat_codes,
                    }
                )

            current = {
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "lastReportedAt": data.get("lastReportedAt"),
                "reportCategories": category_counts,
                "reports": parsed_reports[:20],
                "queriedIp": target,
                "queriedIps": targets,
                "countryCode": data.get("countryCode"),
                "usageType": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
            }
            if best is None or int(current.get("abuseConfidenceScore", 0)) > int(best.get("abuseConfidenceScore", 0)):
                best = current

        if best is not None:
            out[ioc.value] = best
        elif last_error:
            out[ioc.value] = {"error": last_error, "queriedIps": targets}
    return out
