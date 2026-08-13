"""VirusTotal client (lookup-only).

A single IOC costs several VT calls: the object itself, plus comments, votes,
and — depending on the type — resolutions or a behaviour summary. Run in
sequence, a handful of IOCs turns into dozens of chained round trips. The batch
below therefore works in two bounded-concurrency phases: fetch every primary
object, then fetch the enrichment calls for the objects that actually exist.
The request *count* is unchanged (in fact lower — see :func:`_enrichment_calls`);
only the waiting overlaps.
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from typing import Callable

import requests

from config import Settings
from core.http import get_session, run_parallel
from core.infra_classifier import classify as classify_infra
from ioc.parser import IOC, scheme_variants


logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"

# IOC types this client knows how to query. Anything else gets an empty result.
_SUPPORTED_TYPES = frozenset({"ip", "domain", "hash", "url"})

# VT endpoint segment per IOC type.
_ENDPOINTS = {
    "ip": "ip_addresses",
    "domain": "domains",
    "hash": "files",
    "url": "urls",
}


def _vt_get(path: str, key: str, params: dict | None = None) -> dict:
    """GET a VT API path and return the decoded body, or {} on any failure.

    Args:
        path: API path below :data:`VT_BASE`, e.g. ``"/domains/example.com"``.
        key: VirusTotal API key.
        params: Optional query parameters.

    Returns:
        The parsed JSON body, or an empty dict when the request failed, was
        rejected, or did not return an object.
    """
    try:
        r = get_session().get(
            f"{VT_BASE}{path}",
            headers={"x-apikey": key},
            params=params,
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.warning("VirusTotal request to %s failed: %s", path, exc)
        return {}
    if r.status_code == 429:
        # Worth its own line: a throttled lookup returns the same empty dict as
        # "VT has never seen this", and downstream that reads as a clean verdict.
        logger.warning("VirusTotal rate-limited the request to %s (HTTP 429)", path)
        return {}
    if r.status_code != 200:
        return {}
    try:
        return r.json()
    except ValueError:
        logger.warning("VirusTotal returned a non-JSON body for %s", path)
        return {}


def _url_id(url: str) -> str:
    raw = url.encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("utf-8")
    return b64.rstrip("=")


@dataclass
class _Primary:
    """The main VT object for one IOC, before enrichment calls are folded in."""

    endpoint: str
    ident: str
    data: dict = field(default_factory=dict)
    # Only set for a URL whose scheme the parser inferred and which matched.
    matched_url: str | None = None

    @property
    def exists(self) -> bool:
        """True when VT actually returned an object for this identifier."""
        return bool(self.data.get("data"))


def _fetch_primary_url(url: str, key: str, candidates: list[str] | None = None) -> _Primary:
    """Fetch a URL report, trying alternate scheme forms in order.

    ``candidates`` carries the http:// and https:// variants of a URL whose scheme
    the parser inferred. Deliberately sequential and first-hit-wins: firing both
    concurrently would spend an extra call on every URL that matches on the first
    form, and VT quota is scarcer than the latency saved.

    Args:
        url: Canonical URL value of the IOC.
        key: VirusTotal API key.
        candidates: Ordered URL forms to try. Defaults to ``[url]``.

    Returns:
        The primary object, keyed to ``url`` when no candidate held a report.
    """
    for candidate in (candidates or [url]):
        url_id = _url_id(candidate)
        data = _vt_get(f"/urls/{url_id}", key)
        if data.get("data"):
            return _Primary("urls", url_id, data, matched_url=candidate)
    return _Primary("urls", _url_id(url))


def _fetch_primary(ioc: IOC, key: str) -> _Primary:
    """Fetch the main VT object for one IOC.

    Args:
        ioc: The IOC to look up. Must be one of :data:`_SUPPORTED_TYPES`.
        key: VirusTotal API key.

    Returns:
        The primary object for the IOC.
    """
    if ioc.type == "url":
        return _fetch_primary_url(ioc.value, key, scheme_variants(ioc))
    endpoint = _ENDPOINTS[ioc.type]
    return _Primary(endpoint, ioc.value, _vt_get(f"/{endpoint}/{ioc.value}", key))


def _enrichment_calls(
    primary: _Primary, key: str
) -> dict[str, Callable[[], dict]]:
    """Build the follow-up calls that decorate a primary object.

    Only called for an object that exists. Previously these fired even when VT
    held no object at all, spending two to four calls of a scarce quota on an
    identifier guaranteed to return nothing — and the empty responses were
    dropped anyway, so skipping them leaves the result dict identical.

    Args:
        primary: The already-fetched primary object.
        key: VirusTotal API key.

    Returns:
        Mapping of result-dict field name to the callable fetching it.
    """
    endpoint, ident = primary.endpoint, primary.ident
    calls: dict[str, Callable[[], dict]] = {
        "comments": lambda: _vt_get(f"/{endpoint}/{ident}/comments", key, params={"limit": 5}),
        "votes": lambda: _vt_get(f"/{endpoint}/{ident}/votes", key, params={"limit": 5}),
    }
    if endpoint in ("ip_addresses", "domains"):
        calls["resolutions"] = lambda: _vt_get(
            f"/{endpoint}/{ident}/resolutions", key, params={"limit": 10}
        )
    if endpoint == "files":
        calls["behavior"] = lambda: _vt_get(f"/files/{ident}/behaviour_summary", key)
    return calls


def _pack_core(primary: _Primary) -> dict:
    """Build the result dict for one IOC from its primary object alone.

    Args:
        primary: The fetched primary object.

    Returns:
        The result dict, without the enrichment fields.
    """
    vt_data = primary.data.get("data", {}) or {}
    attrs = vt_data.get("attributes", {}) or {}
    relationships = vt_data.get("relationships", {}) or {}
    out = {
        "id": vt_data.get("id") or primary.ident,
        "type": vt_data.get("type"),
        "stats": attrs.get("last_analysis_stats", {}),
        "analysis_results": attrs.get("last_analysis_results", {}),
        "attributes": attrs,
        "relationships": list(relationships.keys()),
        "infra_classification": _classify_vt_infra(primary.endpoint, primary.ident, attrs),
    }
    if primary.matched_url:
        out["matched_url"] = primary.matched_url
    return out


def _apply_enrichment(out: dict, field_name: str, response: dict) -> None:
    """Fold one enrichment response into the result dict, if it carried data.

    Args:
        out: The result dict being assembled, mutated in place.
        field_name: Which enrichment this is (``comments``, ``behavior``, ...).
        response: The raw VT response for that call.
    """
    data = response.get("data")
    if not data:
        return
    if field_name == "behavior":
        out["behavior"] = response.get("data", {}).get("attributes", data)
    else:
        out[field_name] = data


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
    """Look up every supported IOC in the batch and return results by IOC value.

    Args:
        items: The IOCs to enrich. Unsupported types yield an empty result.
        settings: Settings carrying ``vt_key``.

    Returns:
        Mapping of IOC value to its VT result dict.
    """
    out: dict[str, dict] = {ioc.value: {} for ioc in items}
    if not settings.vt_key:
        return out

    key = settings.vt_key
    targets = [ioc for ioc in items if ioc.type in _SUPPORTED_TYPES]
    if not targets:
        return out

    # Phase 1 — one primary object per IOC, all in flight together.
    primaries = run_parallel(
        {ioc.value: (lambda i=ioc: _fetch_primary(i, key)) for ioc in targets},
        label="VirusTotal lookup",
    )
    for value, primary in primaries.items():
        out[value] = _pack_core(primary)

    # Phase 2 — every enrichment call for every IOC as one flat batch, so a
    # single slow object cannot hold up another IOC's follow-up calls.
    tasks: dict[tuple[str, str], Callable[[], dict]] = {}
    for value, primary in primaries.items():
        if not primary.exists:
            continue
        for field_name, call in _enrichment_calls(primary, key).items():
            tasks[(value, field_name)] = call

    for (value, field_name), response in run_parallel(
        tasks, label="VirusTotal enrichment"
    ).items():
        _apply_enrichment(out[value], field_name, response)

    return out
