"""VirusTotal client (lookup-only)."""
from __future__ import annotations

import base64
import requests

from config import Settings
from core.infra_classifier import classify as classify_infra
from ioc.parser import IOC


VT_BASE = "https://www.virustotal.com/api/v3"


def _vt_get(path: str, key: str, params: dict | None = None) -> dict:
    try:
        r = requests.get(
            f"{VT_BASE}{path}",
            headers={"x-apikey": key},
            params=params,
            timeout=15,
        )
    except requests.RequestException:
        return {}
    if r.status_code != 200:
        return {}
    return r.json()


def _url_id(url: str) -> str:
    raw = url.encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("utf-8")
    return b64.rstrip("=")


def _lookup_url(url: str, key: str) -> dict:
    url_id = _url_id(url)
    data = _vt_get(f"/urls/{url_id}", key)
    return _pack_vt(data, key, "urls", url_id)


def _lookup_ip(ip: str, key: str) -> dict:
    data = _vt_get(f"/ip_addresses/{ip}", key)
    return _pack_vt(data, key, "ip_addresses", ip)


def _lookup_domain(domain: str, key: str) -> dict:
    data = _vt_get(f"/domains/{domain}", key)
    return _pack_vt(data, key, "domains", domain)


def _lookup_hash(h: str, key: str) -> dict:
    data = _vt_get(f"/files/{h}", key)
    return _pack_vt(data, key, "files", h)


def _pack_vt(data: dict, key: str, endpoint: str, ident: str) -> dict:
    vt_data = data.get("data", {}) if data else {}
    attrs = vt_data.get("attributes", {}) if vt_data else {}
    relationships = vt_data.get("relationships", {}) if vt_data else {}
    out = {
        "id": vt_data.get("id") or ident,
        "type": vt_data.get("type"),
        "stats": attrs.get("last_analysis_stats", {}),
        "analysis_results": attrs.get("last_analysis_results", {}),
        "attributes": attrs,
        "relationships": list(relationships.keys()),
    }
    comments = _vt_get(f"/{endpoint}/{ident}/comments", key, params={"limit": 5})
    if comments.get("data"):
        out["comments"] = comments.get("data", [])
    votes = _vt_get(f"/{endpoint}/{ident}/votes", key, params={"limit": 5})
    if votes.get("data"):
        out["votes"] = votes.get("data", [])
    if endpoint in ("ip_addresses", "domains"):
        resolutions = _vt_get(f"/{endpoint}/{ident}/resolutions", key, params={"limit": 10})
        if resolutions.get("data"):
            out["resolutions"] = resolutions.get("data", [])
    if endpoint == "files":
        behavior = _vt_get(f"/files/{ident}/behaviour_summary", key)
        if behavior.get("data"):
            out["behavior"] = behavior.get("data", {}).get("attributes", behavior.get("data"))
    out["infra_classification"] = _classify_vt_infra(endpoint, ident, attrs)
    return out


def _classify_vt_infra(endpoint: str, ident: str, attrs: dict) -> dict | None:
    """Derive an infra classification from VT attributes.

    Args:
        endpoint: VT endpoint segment (``ip_addresses``, ``domains``, ...).
        ident: The IOC identifier (IP / domain / hash / url-id).
        attrs: The ``attributes`` block returned by VT.

    Returns:
        A classification dict from ``core.infra_classifier.classify`` or
        ``None`` when VT did not include ASN/AS-owner info or the infra is
        unrecognized.
    """
    if not isinstance(attrs, dict):
        return None
    asn = attrs.get("asn")
    org = attrs.get("as_owner") or attrs.get("network")
    ip = ident if endpoint == "ip_addresses" else None
    if asn is None and not org:
        return None
    return classify_infra(asn=asn, org=org, ip=ip)


def vt_lookup_batch(items: list[IOC], settings: Settings) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not settings.vt_key:
        return out
    for ioc in items:
        if ioc.type == "ip":
            out[ioc.value] = _lookup_ip(ioc.value, settings.vt_key)
        elif ioc.type == "domain":
            out[ioc.value] = _lookup_domain(ioc.value, settings.vt_key)
        elif ioc.type == "hash":
            out[ioc.value] = _lookup_hash(ioc.value, settings.vt_key)
        elif ioc.type == "url":
            out[ioc.value] = _lookup_url(ioc.value, settings.vt_key)
        else:
            out[ioc.value] = {}
    return out
