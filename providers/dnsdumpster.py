"""DNSDumpster client.

Real API response shape (as of 2026):
  {
    "a": [ { "host": str, "ips": [ { "ip", "asn", "asn_name", "asn_range",
              "banners": {"http": {"server","title","apps",...},
                          "https": {"server","title","cn","o","alt_n",...}},
              "country", "country_code", "ptr" } ] } ],
    "cname": [ { "host": str, "target": str } ],
    "mx":    [ { "host": str, "priority": int, "ips": [...] } ],
    "ns":    [ { "host": str, "ips": [...] } ],
    "txt":   [ { "host": str, "entries": [str, ...] } ],
    "total_a_recs": int
  }
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import requests

from config import Settings
from core.http import get_session
from ioc.parser import IOC


DNSD_BASE = "https://api.dnsdumpster.com"

SENSITIVE_HOST_HINTS = ("vpn", "mail", "remote", "admin", "staging", "stage", "dev", "test", "old")
THIRD_PARTY_CNAME_HINTS = (
    "cloudfront.net", "azurewebsites.net", "herokudns.com", "github.io",
    "s3.amazonaws.com", "netlify.app", "pages.dev", "fastly.net",
)
RESIDENTIAL_OWNER_HINTS = (
    "telecom", "communications", "broadband", "wireless", "isp",
    "residential", "home", "comcast", "verizon", "att", "vodafone",
)


def _domain_target(ioc: IOC) -> str:
    """Extract a bare domain string from an IOC (domain or URL type)."""
    if ioc.type == "domain":
        return ioc.value.strip().lower()
    if ioc.type == "url":
        try:
            parsed = urlparse(ioc.value)
        except ValueError:
            return ""
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return ""
        try:
            ipaddress.ip_address(host)
            return ""
        except ValueError:
            return host
    return ""


def _as_list(value) -> list:
    """Coerce a value to a list, flattening single-level dict-of-lists."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        out: list = []
        for v in value.values():
            if isinstance(v, list):
                out.extend(v)
        return out
    return []


def _asn_fmt(raw: str) -> str:
    """Normalise ASN to 'AS12345' format."""
    s = str(raw or "").strip()
    if not s:
        return ""
    return s if s.upper().startswith("AS") else f"AS{s}"


def _banner_str(banners: dict) -> str:
    """Build a short human-readable banner string from the nested banners dict."""
    if not isinstance(banners, dict):
        return ""
    parts: list[str] = []
    http = banners.get("http") or {}
    https = banners.get("https") or {}
    if http.get("server"):
        title = f" ({http['title']})" if http.get("title") else ""
        parts.append(f"HTTP:{http['server']}{title}")
    if https.get("server") and https.get("server") != http.get("server"):
        title = f" ({https['title']})" if https.get("title") else ""
        parts.append(f"HTTPS:{https['server']}{title}")
    elif https.get("title") and https.get("title") != http.get("title"):
        parts.append(f"({https['title']})")
    return " | ".join(parts)


def _build_soc_summary(domain: str, data: dict) -> dict:
    """Build a structured SOC-friendly summary from the raw DNSDumpster API response.

    Args:
        domain: The queried domain string.
        data: Raw JSON dict exactly as returned by the DNSDumpster API.

    Returns:
        Dict with a_records, cname_map, mail_dns_infra, open_services,
        network_enrichment, and red_flags.
    """
    if not isinstance(data, dict):
        data = {}

    a_record_rows: list[dict] = []
    open_services: list[dict] = []
    cname_map: dict[str, str] = {}
    mx_values: set[str] = set()
    mx_details: list[dict] = []
    unique_ns: set[str] = set()
    unique_txt: set[str] = set()

    # ── A records ──────────────────────────────────────────────────────────────
    for a_entry in _as_list(data.get("a")):
        if not isinstance(a_entry, dict):
            continue
        host = str(a_entry.get("host") or "").strip().lower()
        for ip_obj in _as_list(a_entry.get("ips")):
            if not isinstance(ip_obj, dict):
                continue
            ip = str(ip_obj.get("ip") or "").strip()
            asn = _asn_fmt(ip_obj.get("asn") or "")
            owner = str(ip_obj.get("asn_name") or "").strip()
            netblock = str(ip_obj.get("asn_range") or "").strip()
            country = str(ip_obj.get("country") or "").strip()
            country_code = str(ip_obj.get("country_code") or "").strip()
            ptr = str(ip_obj.get("ptr") or "").strip()
            banner = _banner_str(ip_obj.get("banners") or {})

            a_record_rows.append({
                "host": host,
                "ip": ip,
                "asn": asn,
                "owner": owner,
                "netblock": netblock,
                "country": country,
                "country_code": country_code,
                "ptr": ptr,
                "banner": banner,
                "type": "A",
            })
            if banner:
                open_services.append({"host": host, "ip": ip, "banner": banner})

    # ── CNAME records ──────────────────────────────────────────────────────────
    for cname_entry in _as_list(data.get("cname")):
        if not isinstance(cname_entry, dict):
            continue
        host = str(cname_entry.get("host") or "").strip().lower()
        target = str(cname_entry.get("target") or cname_entry.get("value") or "").strip()
        if host and target:
            cname_map[host] = target

    # ── MX records ─────────────────────────────────────────────────────────────
    for mx_entry in _as_list(data.get("mx")):
        if not isinstance(mx_entry, dict):
            continue
        mx_host = str(mx_entry.get("host") or "").strip()
        mx_priority = mx_entry.get("priority") or ""
        if mx_host:
            mx_values.add(mx_host)
        mx_ip = mx_asn = mx_owner = mx_country = ""
        for ip_obj in _as_list(mx_entry.get("ips")):
            if isinstance(ip_obj, dict):
                mx_ip = str(ip_obj.get("ip") or "").strip()
                mx_asn = _asn_fmt(ip_obj.get("asn") or "")
                mx_owner = str(ip_obj.get("asn_name") or "").strip()
                mx_country = str(ip_obj.get("country") or "").strip()
                break
        mx_details.append({
            "host": mx_host, "priority": mx_priority,
            "ip": mx_ip, "asn": mx_asn, "owner": mx_owner, "country": mx_country,
        })

    # ── NS records ─────────────────────────────────────────────────────────────
    for ns_entry in _as_list(data.get("ns")):
        if isinstance(ns_entry, dict):
            ns_host = str(ns_entry.get("host") or ns_entry.get("value") or "").strip()
            if ns_host:
                unique_ns.add(ns_host)
        elif isinstance(ns_entry, str) and ns_entry.strip():
            unique_ns.add(ns_entry.strip())

    # ── TXT records ────────────────────────────────────────────────────────────
    for txt_entry in _as_list(data.get("txt")):
        if isinstance(txt_entry, dict):
            entries = txt_entry.get("entries") or []
            if isinstance(entries, list):
                unique_txt.update(str(e) for e in entries if e)
            val = txt_entry.get("value") or txt_entry.get("data") or ""
            if val:
                unique_txt.add(str(val))
        elif isinstance(txt_entry, str) and txt_entry.strip():
            unique_txt.add(txt_entry.strip())

    # ── Red flags ──────────────────────────────────────────────────────────────
    red_flags: list[str] = []
    seen_hosts: set[str] = set()
    for row in a_record_rows:
        host = row["host"]
        label = host.split(".")[0] if host else ""
        if host not in seen_hosts:
            seen_hosts.add(host)
            if any(h in label for h in SENSITIVE_HOST_HINTS):
                red_flags.append(f"Sensitive host pattern: {host}")
            owner_lower = (row["owner"] or "").lower()
            if owner_lower and any(h in owner_lower for h in RESIDENTIAL_OWNER_HINTS):
                red_flags.append(f"Residential/ISP owner: {host} ({row['owner']})")
            sub = label if "." not in host else label
            if sub and len(sub) >= 16 and re.search(r"\d", sub):
                red_flags.append(f"Potential random/generated hostname: {host}")

    for host, target in cname_map.items():
        target_lower = target.lower()
        if any(h in target_lower for h in THIRD_PARTY_CNAME_HINTS):
            red_flags.append(f"CNAME takeover risk: {host} → {target}")

    uniq_red: list[str] = []
    seen_r: set[str] = set()
    for r in red_flags:
        if r not in seen_r:
            seen_r.add(r)
            uniq_red.append(r)

    # ── Network enrichment (deduplicated) ─────────────────────────────────────
    seen_net: set[tuple] = set()
    network_enrichment: list[dict] = []
    for row in a_record_rows:
        k = (row["host"], row["ip"], row["asn"])
        if k not in seen_net:
            seen_net.add(k)
            network_enrichment.append({
                "host": row["host"],
                "ip": row["ip"],
                "asn": row["asn"],
                "network_owner": row["owner"],
                "netblock": row["netblock"],
                "ptr": row["ptr"],
                "country": row["country"],
                "country_code": row["country_code"],
            })

    return {
        "domain": domain,
        "total_a_recs": data.get("total_a_recs") or len(a_record_rows),
        "a_records": a_record_rows,
        "cname_map": cname_map,
        "mail_dns_infra": {
            "mx": sorted(mx_values),
            "mx_details": mx_details,
            "ns": sorted(unique_ns),
            "txt_highlights": sorted(unique_txt)[:15],
        },
        "open_services": open_services[:30],
        "network_enrichment": network_enrichment,
        "red_flags": uniq_red[:30],
    }


def dnsdumpster_lookup_batch(items: list[IOC], settings: Settings) -> dict[str, dict]:
    """Fetch DNSDumpster data for a batch of IOCs.

    Args:
        items: List of IOC objects to query (domain/url types only).
        settings: App settings containing the API key.

    Returns:
        Dict mapping each IOC value to its result dict.
    """
    out: dict[str, dict] = {}
    if not settings.dnsdumpster_key:
        for ioc in items:
            out[ioc.value] = {"error": "DNSDUMPSTER_KEY is missing"}
        return out

    for ioc in items:
        target = _domain_target(ioc)
        if not target:
            out[ioc.value] = {"error": f"No domain target for IOC type '{ioc.type}'"}
            continue
        try:
            r = get_session().get(
                f"{DNSD_BASE}/domain/{target}",
                headers={"X-API-Key": settings.dnsdumpster_key},
                timeout=15,
            )
        except requests.RequestException as exc:
            out[ioc.value] = {"error": str(exc), "queriedDomain": target}
            continue
        if r.status_code != 200:
            body = (r.text or "").strip().replace("\n", " ")
            out[ioc.value] = {"error": f"HTTP {r.status_code}: {body[:180]}", "queriedDomain": target}
            continue
        try:
            data = r.json()
        except Exception:
            out[ioc.value] = {"error": "Invalid JSON response", "queriedDomain": target}
            continue
        if not isinstance(data, dict):
            out[ioc.value] = {"error": "Unexpected response format", "queriedDomain": target}
            continue

        out[ioc.value] = {
            "queriedDomain": target,
            "soc_summary": _build_soc_summary(target, data),
            "_raw_keys": list(data.keys()),
        }
    return out
