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

CACHE_REV = "providers-v13"


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


@st.cache_data(ttl=86400)
def vt_cached(payload: list, vt_key: str) -> dict:
    return vt_lookup_batch(_inflate(payload), Settings(vt_key=vt_key))


@st.cache_data(ttl=86400)
def urlscan_cached(payload: list, urlscan_key: str, allow_submit_flag: bool) -> dict:
    return urlscan_lookup_batch(
        _inflate(payload),
        Settings(urlscan_key=urlscan_key),
        allow_submit=allow_submit_flag,
    )


@st.cache_data(ttl=86400)
def abuse_cached(payload: list, abuse_key: str, cache_rev: str) -> dict:
    return abuseipdb_lookup_batch(_inflate(payload), Settings(abuse_key=abuse_key))


@st.cache_data(ttl=86400)
def tf_cached(payload: list, tf_key: str, cache_rev: str) -> dict:
    return threatfox_lookup_batch(_inflate(payload), Settings(threatfox_key=tf_key))


@st.cache_data(ttl=86400)
def mb_cached(payload: list, mb_key: str, cache_rev: str) -> dict:
    return malwarebazaar_lookup_batch(_inflate(payload), Settings(malwarebazaar_key=mb_key))


@st.cache_data(ttl=86400)
def shodan_cached(payload: list, shodan_key: str, cache_rev: str) -> dict:
    return shodan_lookup_batch(_inflate(payload), Settings(shodan_key=shodan_key))


@st.cache_data(ttl=86400)
def dnsd_cached(payload: list, dnsd_key: str, cache_rev: str) -> dict:
    return dnsdumpster_lookup_batch(_inflate(payload), Settings(dnsdumpster_key=dnsd_key))


@st.cache_data(ttl=86400)
def ha_cached(payload: list, ha_key: str, cache_rev: str) -> dict:
    return hybrid_analysis_lookup_batch(_inflate(payload))


@st.cache_data(ttl=86400)
def mxtoolbox_cached(payload: list, mxtoolbox_key: str, cache_rev: str) -> dict:
    return mxtoolbox_lookup_batch(_inflate(payload), Settings(mxtoolbox_key=mxtoolbox_key))


@st.cache_data(ttl=86400)
def whoxy_cached(payload: list, whoxy_key: str, cache_rev: str) -> dict:
    return whoxy_lookup_batch(_inflate(payload), Settings(whoxy_key=whoxy_key))


@st.cache_data(ttl=86400)
def ransomware_live_cached(payload: list, ransomware_live_key: str, cache_rev: str) -> dict:
    return ransomware_live_lookup_batch(
        _inflate(payload), Settings(ransomware_live_key=ransomware_live_key)
    )
