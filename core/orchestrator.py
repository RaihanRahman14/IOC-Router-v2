"""Provider orchestration — routes IOCs to the right providers and assembles results."""
from __future__ import annotations

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
    """Call all enabled providers and return a fully assembled run_results dict."""
    ioc_payload = [(i.value, i.type) for i in items]

    vt_results      = vt_cached(ioc_payload, settings.vt_key)                                          if provider_flags["vt"]     else {}
    urlscan_results = urlscan_cached(ioc_payload, settings.urlscan_key, allow_urlscan_submit)           if provider_flags["urlscan"] else {}
    abuse_results   = abuse_cached(ioc_payload, settings.abuse_key, CACHE_REV)                          if provider_flags["abuse"]  else {}
    tf_results      = tf_cached(ioc_payload, settings.threatfox_key, CACHE_REV)                         if provider_flags["tf"]     else {}
    mb_results      = mb_cached(ioc_payload, settings.malwarebazaar_key, CACHE_REV)                     if provider_flags["mb"]     else {}
    shodan_results  = shodan_cached(ioc_payload, settings.shodan_key, CACHE_REV)                        if provider_flags["shodan"] else {}
    dnsd_results    = dnsd_cached(ioc_payload, settings.dnsdumpster_key, CACHE_REV)                     if provider_flags["dns"]    else {}
    ha_results              = ha_cached(ioc_payload, settings.hybrid_analysis_key, CACHE_REV)           if provider_flags["ha"]             else {}
    mxtoolbox_results       = mxtoolbox_cached(ioc_payload, settings.mxtoolbox_key, CACHE_REV)         if provider_flags["mxtoolbox"]      else {}
    whoxy_results           = whoxy_cached(ioc_payload, settings.whoxy_key, CACHE_REV)                 if provider_flags["whoxy"]          else {}
    ransomware_live_results = ransomware_live_cached(ioc_payload, settings.ransomware_live_key, CACHE_REV) if provider_flags["ransomware_live"] else {}

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
