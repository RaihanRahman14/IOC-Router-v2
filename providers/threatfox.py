"""ThreatFox client."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import requests

from config import Settings
from ioc.parser import IOC, scheme_variants


TF_BASE = "https://threatfox-api.abuse.ch/api/v1/"


MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


def _tf_query(query: str, value: str, key: str, exact_match: bool | None = None) -> dict:
    payload = {"query": query, "search_term": value}
    if exact_match is not None:
        payload["exact_match"] = bool(exact_match)
    try:
        r = requests.post(
            TF_BASE,
            headers={"Auth-Key": key},
            json=payload,
            timeout=15,
        )
    except requests.RequestException:
        return {}
    if r.status_code != 200:
        return {}
    return r.json()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _is_ip_port(value: str) -> bool:
    v = value.strip()
    if ":" not in v:
        return False
    host, port = v.rsplit(":", 1)
    if not port.isdigit():
        return False
    if not (1 <= int(port) <= 65535):
        return False
    return _is_ip(host)


def _query_variants(ioc: IOC) -> list[str]:
    value = (ioc.value or "").strip()
    if not value:
        return []
    variants = [value]
    if ioc.type == "url":
        # Feed lookup — http:// first, since that is the form most feeds store.
        variants.extend(scheme_variants(ioc))
        try:
            host = (urlparse(value).hostname or "").strip().lower()
        except ValueError:
            host = ""
        if host:
            variants.append(host)
    elif ioc.type == "domain":
        variants.append(f"http://{value}")
        variants.append(f"https://{value}")
    # Deduplicate preserve order
    out = []
    seen = set()
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _plan_queries(ioc: IOC) -> list[tuple[str, str, bool | None]]:
    value = (ioc.value or "").strip()
    if not value:
        return []

    # Hash IOC: prefer search_hash for MD5/SHA256.
    if ioc.type == "hash":
        if MD5_RE.match(value) or SHA256_RE.match(value):
            return [
                ("search_hash", value, None),
                ("search_ioc", value, True),
                ("search_ioc", value, False),
            ]
        return [("search_ioc", value, True), ("search_ioc", value, False)]

    if ioc.type == "ip" or _is_ip(value):
        return [
            ("search_ip", value, None),
            ("search_ioc", value, True),
            ("search_ioc", value, False),
        ]

    if ioc.type == "domain":
        queries: list[tuple[str, str, bool | None]] = [("search_domain", value, None)]
        for q in _query_variants(ioc):
            queries.append(("search_ioc", q, True))
            queries.append(("search_ioc", q, False))
        return queries

    # URL / IP:port / generic IOC string
    queries = []
    for q in _query_variants(ioc):
        queries.append(("search_ioc", q, True))
        queries.append(("search_ioc", q, False))
    if _is_ip_port(value):
        # IP:port still maps to search_ioc in ThreatFox
        pass
    return queries


def threatfox_lookup_batch(items: list[IOC], settings: Settings) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not settings.threatfox_key:
        for ioc in items:
            out[ioc.value] = {"error": "THREATFOX_KEY is missing"}
        return out
    for ioc in items:
        final_status = "no_result"
        final_rows = []
        used_query = ""
        used_method = ""
        for method, term, exact in _plan_queries(ioc):
            data = _tf_query(method, term, settings.threatfox_key, exact_match=exact)
            status = data.get("query_status") if isinstance(data, dict) else None
            if status == "ok":
                rows = data.get("data", []) if isinstance(data.get("data"), list) else []
                if rows:
                    final_status = "ok"
                    final_rows = rows
                    used_query = term
                    used_method = method
                    break
            elif status:
                final_status = str(status)
        out[ioc.value] = {
            "query_status": final_status,
            "query_used": used_query,
            "query_method": used_method,
            "data": final_rows,
        }
    return out
