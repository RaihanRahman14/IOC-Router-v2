"""Provider orchestration — routes IOCs to the right providers and assembles results."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from config import Settings
from ioc.parser import IOC
from ioc.verdict import summarize_results
from core.cache import (
    CACHE_REV,
    vt_cached,
    urlscan_cached,
    abuse_cached,
    tf_cached,
    mb_cached,
    shodan_cached,
    dnsd_cached,
    ha_cached,
    mxtoolbox_cached,
    whoxy_cached,
    ransomware_live_cached,
)

logger = logging.getLogger(__name__)


def auto_provider_flags(items: list[IOC], settings_obj: Settings) -> dict[str, bool]:
    """Return which providers should run, based on IOC types and available API keys."""
    types = {ioc.type for ioc in items}
    has_hash = "hash" in types
    return {
        "vt":     bool(settings_obj.vt_key)               and bool(types & {"ip", "domain", "url", "hash"}),
        "urlscan":bool(settings_obj.urlscan_key)           and bool(types & {"domain", "url"}),
        "abuse":  bool(settings_obj.abuse_key)             and bool(types & {"ip", "domain", "url"}),
        "tf":     bool(settings_obj.threatfox_key)         and bool(types & {"ip", "domain", "url", "hash"}),
        "mb":     bool(settings_obj.malwarebazaar_key)     and has_hash,
        "shodan": bool(settings_obj.shodan_key)            and bool(types & {"ip", "domain", "url"}),
        "dns":    bool(settings_obj.dnsdumpster_key)       and bool(types & {"domain", "url"}),
        "ha":         bool(settings_obj.hybrid_analysis_key)   and bool(types & {"ip", "domain", "url", "hash"}),
        "mxtoolbox":       bool(settings_obj.mxtoolbox_key)          and bool(types & {"ip", "domain", "url", "email"}),
        "whoxy":           bool(settings_obj.whoxy_key)              and bool(types & {"whois"}),
        "ransomware_live": bool(settings_obj.ransomware_live_key)    and bool(types & {"whois"}),
    }


def run_provider_lookups(
    items: list[IOC],
    settings: Settings,
    provider_flags: dict[str, bool],
    allow_urlscan_submit: bool,
) -> dict:
    """Call all enabled providers in parallel and return an assembled run_results dict.

    Each enabled provider lookup runs on its own worker thread. Provider lookups
    are I/O-bound (waiting on HTTP), so threads let the enabled providers wait on
    the network concurrently — total wall time is roughly the slowest provider
    rather than the sum of all of them. A provider that raises is logged and
    contributes an empty result instead of aborting the whole run.

    Args:
        items: Parsed IOCs to enrich.
        settings: Loaded API keys / config.
        provider_flags: Which providers are enabled (see :func:`auto_provider_flags`).
        allow_urlscan_submit: Whether URLScan may submit new scans (vs lookup-only).

    Returns:
        A run_results dict with per-provider result maps, the aggregated summary
        and rows, and the provider_flags used.
    """
    ioc_payload = [(i.value, i.type, i.scheme_inferred) for i in items]

    # name -> (enabled, zero-arg callable that performs the cached lookup)
    jobs: dict[str, tuple[bool, Callable[[], dict]]] = {
        "vt":              (provider_flags["vt"],              lambda: vt_cached(ioc_payload, settings.vt_key)),
        "urlscan":         (provider_flags["urlscan"],         lambda: urlscan_cached(ioc_payload, settings.urlscan_key, allow_urlscan_submit)),
        "abuse":           (provider_flags["abuse"],           lambda: abuse_cached(ioc_payload, settings.abuse_key, CACHE_REV)),
        "tf":              (provider_flags["tf"],              lambda: tf_cached(ioc_payload, settings.threatfox_key, CACHE_REV)),
        "mb":              (provider_flags["mb"],              lambda: mb_cached(ioc_payload, settings.malwarebazaar_key, CACHE_REV)),
        "shodan":          (provider_flags["shodan"],          lambda: shodan_cached(ioc_payload, settings.shodan_key, CACHE_REV)),
        "dnsd":            (provider_flags["dns"],             lambda: dnsd_cached(ioc_payload, settings.dnsdumpster_key, CACHE_REV)),
        "ha":              (provider_flags["ha"],              lambda: ha_cached(ioc_payload, settings.hybrid_analysis_key, CACHE_REV)),
        "mxtoolbox":       (provider_flags["mxtoolbox"],       lambda: mxtoolbox_cached(ioc_payload, settings.mxtoolbox_key, CACHE_REV)),
        "whoxy":           (provider_flags["whoxy"],           lambda: whoxy_cached(ioc_payload, settings.whoxy_key, CACHE_REV)),
        "ransomware_live": (provider_flags["ransomware_live"], lambda: ransomware_live_cached(ioc_payload, settings.ransomware_live_key, CACHE_REV)),
    }

    results: dict[str, dict] = {name: {} for name in jobs}
    active = {name: fn for name, (enabled, fn) in jobs.items() if enabled}

    if active:
        with ThreadPoolExecutor(max_workers=len(active)) as pool:
            futures = {pool.submit(fn): name for name, fn in active.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    results[name] = fut.result()
                except Exception as exc:  # noqa: BLE001 — one provider must not sink the run
                    logger.error("provider %s lookup failed: %s", name, exc)

    vt_results              = results["vt"]
    urlscan_results         = results["urlscan"]
    abuse_results           = results["abuse"]
    tf_results              = results["tf"]
    mb_results              = results["mb"]
    shodan_results          = results["shodan"]
    dnsd_results            = results["dnsd"]
    ha_results              = results["ha"]
    mxtoolbox_results       = results["mxtoolbox"]
    whoxy_results           = results["whoxy"]
    ransomware_live_results = results["ransomware_live"]

    summary, rows = summarize_results(
        items,
        vt_results,
        urlscan_results,
        abuse_results,
        tf_results,
        mb_results,
        shodan_results=shodan_results,
        hybrid_results=ha_results,
    )

    return {
        "items":          items,
        "summary":        summary,
        "rows":           rows,
        "vt":             vt_results,
        "urlscan":        urlscan_results,
        "abuse":          abuse_results,
        "tf":             tf_results,
        "mb":             mb_results,
        "shodan":         shodan_results,
        "dnsd":           dnsd_results,
        "ha":             ha_results,
        "mxtoolbox":        mxtoolbox_results,
        "whoxy":            whoxy_results,
        "ransomware_live":  ransomware_live_results,
        "provider_flags":   provider_flags,
    }
