"""Ransomware.live victim search client (keyword and domain/URL IOC types)."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests

from config import Settings
from core.http import get_session
from ioc.parser import IOC

logger = logging.getLogger(__name__)

_BASE = "https://api-pro.ransomware.live"
_TIMEOUT = 15


def _host_from_url(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").strip().lower()
    except ValueError:
        return ""


def _extract_queries(ioc_value: str, ioc_type: str) -> tuple[str, str]:
    """Return (full_domain, sld) to use as search queries.

    For a URL, extract the hostname first, then the SLD.
    For a bare domain, use the domain as-is and extract the SLD.
    For a whois keyword, both values are the keyword itself.
    """
    if ioc_type == "whois":
        return ioc_value, ioc_value

    host = _host_from_url(ioc_value) if ioc_value.startswith(("http://", "https://")) else ioc_value.strip().lower()
    labels = [p for p in host.split(".") if p]
    if len(labels) >= 2:
        sld = labels[-2]
    else:
        sld = labels[0] if labels else host

    return host, sld


def _search_victims(query: str, key: str) -> dict:
    """Search ransomware victims by keyword via Ransomware.live API."""
    try:
        r = get_session().get(
            f"{_BASE}/victims/search",
            params={"q": query, "order": "discovered"},
            headers={"accept": "application/json", "X-API-KEY": key},
            timeout=_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if r.status_code == 404:
        return {"count": 0, "victims": []}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}
    try:
        return r.json()
    except ValueError:
        return {"error": "Invalid JSON response"}


def _merge_victims(primary: list[dict], secondary: list[dict]) -> list[dict]:
    """Merge two victim lists, deduplicating by id."""
    seen: set[str] = set()
    merged: list[dict] = []
    for v in primary + secondary:
        vid = v.get("id") or str(v)
        if vid not in seen:
            seen.add(vid)
            merged.append(v)
    return merged


def ransomware_live_lookup_batch(items: list[IOC], settings: Settings) -> dict[str, dict]:
    """Search Ransomware.live using both full domain and SLD for each IOC.

    Two queries are sent per domain/URL IOC: one for the full domain and one
    for the SLD label. Results are merged and deduplicated.

    Args:
        items: List of IOC objects to look up.
        settings: Settings containing the ransomware_live_key.

    Returns:
        Dict mapping IOC value to merged search results dict.
    """
    out: dict[str, dict] = {}
    if not settings.ransomware_live_key:
        return out

    for ioc in items:
        if ioc.type not in ("domain", "url", "whois"):
            continue

        full_domain, sld = _extract_queries(ioc.value, ioc.type)

        if not full_domain:
            out[ioc.value] = {"error": "Could not extract search query"}
            continue

        # ── Query 1: full domain / keyword ───────────────────────────────────
        data_full = _search_victims(full_domain, settings.ransomware_live_key)
        if data_full.get("error"):
            out[ioc.value] = data_full
            continue

        victims_full: list[dict] = data_full.get("victims") or []
        queries_run = [full_domain]

        # ── Query 2: SLD (only when different from full_domain) ──────────────
        victims_sld: list[dict] = []
        if sld and sld != full_domain:
            data_sld = _search_victims(sld, settings.ransomware_live_key)
            if not data_sld.get("error"):
                victims_sld = data_sld.get("victims") or []
            queries_run.append(sld)

        all_victims = _merge_victims(victims_full, victims_sld)

        out[ioc.value] = {
            "full_domain": full_domain,
            "sld": sld,
            "queries": queries_run,
            "count": len(all_victims),
            "victims": all_victims,
        }

    return out
