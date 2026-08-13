"""Streamlit cache wrappers for all provider lookups."""
from __future__ import annotations

import streamlit as st

from config import Settings
from ioc.parser import IOC
from providers.virustotal import vt_lookup_batch
from providers.urlscan import urlscan_lookup_batch
from providers.abuseipdb import abuseipdb_lookup_batch
from providers.threatfox import threatfox_lookup_batch
from providers.malwarebazaar import malwarebazaar_lookup_batch
from providers.shodan import shodan_lookup_batch
from providers.dnsdumpster import dnsdumpster_lookup_batch
from providers.hybrid_analysis import hybrid_analysis_lookup_batch
from providers.mxtoolbox import mxtoolbox_lookup_batch
from providers.whoxy import whoxy_lookup_batch
from providers.ransomware_live import ransomware_live_lookup_batch
from providers import nvd

CACHE_REV = "providers-v14"

# CVE feeds age differently from IOC reputation, so they get their own TTLs:
# the NVD publication window is polled hourly, while a published MITRE record
# and a by-id lookup barely move once written.
CVE_FEED_TTL = 3600
CVE_RECORD_TTL = 86400


def _inflate(payload: list) -> list[IOC]:
    """Rebuild IOC objects from the cache-key tuples produced by the callers.

    Accepts both the legacy ``(value, type)`` shape and the current
    ``(value, type, scheme_inferred)`` shape so older payload builders keep working.

    Args:
        payload: Sequence of 2- or 3-element IOC tuples.

    Returns:
        The reconstructed IOC list.
    """
    out: list[IOC] = []
    for row in payload:
        value, ioc_type = row[0], row[1]
        inferred = bool(row[2]) if len(row) > 2 else False
        out.append(IOC(value=value, type=ioc_type, scheme_inferred=inferred))
    return out


# Every wrapper takes ``cache_rev`` so bumping CACHE_REV invalidates *all*
# provider caches, and ``show_spinner=False`` because these run on orchestrator
# worker threads, where a spinner has no script slot to draw into.
@st.cache_data(ttl=86400, show_spinner=False)
def vt_cached(payload: list, vt_key: str, cache_rev: str) -> dict:
    return vt_lookup_batch(_inflate(payload), Settings(vt_key=vt_key))


@st.cache_data(ttl=86400, show_spinner=False)
def urlscan_cached(
    payload: list, urlscan_key: str, allow_submit_flag: bool, cache_rev: str
) -> dict:
    return urlscan_lookup_batch(
        _inflate(payload),
        Settings(urlscan_key=urlscan_key),
        allow_submit=allow_submit_flag,
    )


@st.cache_data(ttl=86400, show_spinner=False)
def abuse_cached(payload: list, abuse_key: str, cache_rev: str) -> dict:
    return abuseipdb_lookup_batch(_inflate(payload), Settings(abuse_key=abuse_key))


@st.cache_data(ttl=86400, show_spinner=False)
def tf_cached(payload: list, tf_key: str, cache_rev: str) -> dict:
    return threatfox_lookup_batch(_inflate(payload), Settings(threatfox_key=tf_key))


@st.cache_data(ttl=86400, show_spinner=False)
def mb_cached(payload: list, mb_key: str, cache_rev: str) -> dict:
    return malwarebazaar_lookup_batch(_inflate(payload), Settings(malwarebazaar_key=mb_key))


@st.cache_data(ttl=86400, show_spinner=False)
def shodan_cached(payload: list, shodan_key: str, cache_rev: str) -> dict:
    return shodan_lookup_batch(_inflate(payload), Settings(shodan_key=shodan_key))


@st.cache_data(ttl=86400, show_spinner=False)
def dnsd_cached(payload: list, dnsd_key: str, cache_rev: str) -> dict:
    return dnsdumpster_lookup_batch(_inflate(payload), Settings(dnsdumpster_key=dnsd_key))


@st.cache_data(ttl=86400, show_spinner=False)
def ha_cached(payload: list, ha_key: str, cache_rev: str) -> dict:
    # ``ha_key`` is forwarded, not just used as a cache key: without it the
    # provider falls back to reading HYBRID_ANALYSIS_KEY from the environment,
    # which silently ignores a key the analyst typed into the API drawer.
    return hybrid_analysis_lookup_batch(
        _inflate(payload), Settings(hybrid_analysis_key=ha_key)
    )


@st.cache_data(ttl=86400, show_spinner=False)
def mxtoolbox_cached(payload: list, mxtoolbox_key: str, cache_rev: str) -> dict:
    return mxtoolbox_lookup_batch(_inflate(payload), Settings(mxtoolbox_key=mxtoolbox_key))


@st.cache_data(ttl=86400, show_spinner=False)
def whoxy_cached(payload: list, whoxy_key: str, cache_rev: str) -> dict:
    return whoxy_lookup_batch(_inflate(payload), Settings(whoxy_key=whoxy_key))


@st.cache_data(ttl=86400, show_spinner=False)
def ransomware_live_cached(payload: list, ransomware_live_key: str, cache_rev: str) -> dict:
    return ransomware_live_lookup_batch(
        _inflate(payload), Settings(ransomware_live_key=ransomware_live_key)
    )


# ── CVE feeds (NVD / CISA KEV / MITRE) ───────────────────────────────────────
# These wrap `providers.nvd`, which is deliberately Streamlit-free so the CVE
# lookup can be reused from the enrichment path without importing the UI layer.

@st.cache_data(ttl=CVE_FEED_TTL, show_spinner=False)
def kev_catalog_cached(cache_rev: str) -> dict:
    return nvd.fetch_kev_catalog()


@st.cache_data(ttl=CVE_RECORD_TTL, show_spinner=False)
def mitre_cve_cached(cve_id: str, cache_rev: str) -> dict:
    return nvd.fetch_mitre_cve(cve_id)


@st.cache_data(ttl=CVE_FEED_TTL, show_spinner=False)
def nvd_page_cached(pub_start: str, pub_end: str, start_index: int, cache_rev: str) -> dict:
    return nvd.fetch_nvd_page(pub_start, pub_end, start_index)


def mitre_records_cached(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch MITRE records for many CVEs, reusing the per-record cache.

    Not itself cached: the per-id wrapper already is, and caching the batch on
    top would key on the whole id list — a single new CVE in the window would
    miss and re-fetch every record in it.

    Args:
        cve_ids: CVE identifiers to enrich.

    Returns:
        Mapping of CVE ID to its MITRE record.
    """
    return nvd.fetch_mitre_records(
        cve_ids, fetch=lambda cve_id: mitre_cve_cached(cve_id, CACHE_REV)
    )


@st.cache_data(ttl=CVE_RECORD_TTL, show_spinner=False)
def cve_by_id_cached(cve_id: str, cache_rev: str) -> dict | None:
    """Look up one CVE by id, reusing the cached KEV catalog.

    Cached for a day: this sits in the enrichment path, and the fingerprint set
    only matches years-old CVEs whose published record does not move. Without
    it every Run re-fetched the same handful of identifiers.
    """
    return nvd.fetch_cve_by_id(cve_id, kev_catalog=kev_catalog_cached(cache_rev))
