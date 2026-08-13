"""Whoxy WHOIS + Reverse WHOIS client (domain, URL, and whois-keyword IOC types)."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests

from config import Settings
from core.http import get_session
from ioc.parser import IOC

logger = logging.getLogger(__name__)

WHOXY_BASE = "https://api.whoxy.com/"


def _host_from_url(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").strip().lower()
    except ValueError:
        return ""


def _extract_sld_name(value: str) -> str:
    """Extract only the SLD label without TLD (e.g. 'example' from sub.evil.example.com)."""
    host = _host_from_url(value) if value.startswith(("http://", "https://")) else value.strip().lower()
    labels = [p for p in host.split(".") if p]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else host


def _whois_lookup(domain: str, key: str) -> dict:
    try:
        r = get_session().get(
            WHOXY_BASE,
            params={"key": key, "whois": domain},
            timeout=15,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}
    try:
        data = r.json()
    except ValueError:
        return {"error": "Invalid JSON response"}
    if data.get("status") == 0:
        return {"error": data.get("status_reason", "Unknown error")}
    return data


def _reverse_whois(field: str, value: str, key: str, max_results: int = 10) -> dict:
    """Run a reverse WHOIS lookup by email, company, or keyword."""
    try:
        r = get_session().get(
            WHOXY_BASE,
            params={"key": key, "reverse": "whois", field: value, "mode": "mini"},
            timeout=15,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}
    try:
        data = r.json()
    except ValueError:
        return {"error": "Invalid JSON response"}
    if data.get("status") == 0:
        return {"error": data.get("status_reason", "Unknown error")}
    records = data.get("whois_records") or []
    domains = []
    for rec in records[:max_results]:
        if isinstance(rec, dict):
            dn = rec.get("domain_name") or rec.get("domain")
            if dn:
                domains.append(dn)
    return {
        "total_results": data.get("total_results", 0),
        "total_pages": data.get("total_pages", 0),
        "related_domains": domains,
    }


def _keyword_reverse_whois(keyword: str, key: str, max_results: int = 20) -> dict:
    """Run reverse WHOIS by keyword — used for bare-word IOC type 'whois'."""
    return _reverse_whois("keyword", keyword, key, max_results=max_results)


def _extract_registrant(whois_data: dict) -> tuple[str, str, str]:
    """Return (email, name, company) from a WHOIS response."""
    reg = whois_data.get("registrant_contact") or {}
    if not isinstance(reg, dict):
        reg = {}
    email = (reg.get("email_address") or "").strip()
    name = (reg.get("full_name") or "").strip()
    company = (reg.get("company_name") or "").strip()
    return email, name, company


def whoxy_lookup_batch(items: list[IOC], settings: Settings) -> dict[str, dict]:
    """Run Whoxy lookups for domain/URL (WHOIS + reverse) and whois-keyword (reverse by keyword) IOCs."""
    out: dict[str, dict] = {}
    if not settings.whoxy_key:
        return out

    for ioc in items:
        # ── Bare keyword → reverse WHOIS by keyword ──────────────────────────
        if ioc.type == "whois":
            result = _keyword_reverse_whois(ioc.value, settings.whoxy_key)
            out[ioc.value] = {
                "mode": "keyword",
                "keyword": ioc.value,
                "reverse_whois": result,
            }
            continue

        if ioc.type not in ("domain", "url"):
            continue

        # ── Domain/URL → WHOIS + reverse by registrant ───────────────────────
        domain = _extract_sld_name(ioc.value)
        if not domain:
            out[ioc.value] = {"error": "Could not extract domain"}
            continue

        whois_data = _whois_lookup(domain, settings.whoxy_key)
        if whois_data.get("error"):
            out[ioc.value] = {"error": whois_data["error"]}
            continue

        registrant_email, registrant_name, registrant_company = _extract_registrant(whois_data)

        domain_info = whois_data.get("domain_registrar") or {}
        if not isinstance(domain_info, dict):
            domain_info = {}

        whois_summary = {
            "domain": domain,
            "registrar": domain_info.get("registrar_name") or "",
            "created_date": whois_data.get("create_date") or "",
            "updated_date": whois_data.get("update_date") or "",
            "expires_date": whois_data.get("expiry_date") or "",
            "domain_status": whois_data.get("domain_status") or [],
            "name_servers": whois_data.get("name_servers") or [],
            "registrant_email": registrant_email,
            "registrant_name": registrant_name,
            "registrant_company": registrant_company,
        }

        reverse_result: dict = {}
        if registrant_email and "@" in registrant_email:
            reverse_result = _reverse_whois("email", registrant_email, settings.whoxy_key)
        elif registrant_company:
            reverse_result = _reverse_whois("company", registrant_company, settings.whoxy_key)

        out[ioc.value] = {
            "mode": "domain",
            "domain": domain,
            "whois": whois_summary,
            "reverse_whois": reverse_result,
        }

    return out
