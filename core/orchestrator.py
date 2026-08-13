"""Provider orchestration — runs every enabled provider lookup in parallel.

This module owns the fan-out step of an enrichment run. The caller decides
*which* IOCs each provider is allowed to see (see ``payload_for``); this module
only decides *how* those lookups are executed and how failures and timings are
recorded.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from config import Settings
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

# Provider short keys, in the order the UI lists them. Single source of truth —
# app.py imports this rather than keeping its own copy.
PROVIDER_KEYS: tuple[str, ...] = (
    "vt", "urlscan", "abuse", "tf", "mb", "shodan",
    "dns", "ha", "mxtoolbox", "whoxy", "ransomware_live",
)

# Provider key -> key under which its results are published in run_results.
# Only DNSDumpster differs: its flag/toggle key is "dns" while every downstream
# consumer reads run_results["dnsd"].
RESULT_KEYS: dict[str, str] = {**{p: p for p in PROVIDER_KEYS}, "dns": "dnsd"}

# One IOC as handed to a cached provider call: (value, type, scheme_inferred).
Payload = list[tuple[str, str, bool]]


def _build_jobs(
    settings: Settings,
    payload_for: Callable[[str], Payload],
    allow_urlscan_submit: bool,
) -> dict[str, Callable[[], dict]]:
    """Map each provider key to a zero-arg callable performing its cached lookup.

    Args:
        settings: Loaded API keys / config.
        payload_for: Returns the IOC tuples a given provider is allowed to query.
        allow_urlscan_submit: Whether URLScan may submit new scans (vs lookup-only).

    Returns:
        Mapping of provider key to the callable that performs its lookup.
    """
    return {
        "vt": lambda: vt_cached(payload_for("vt"), settings.vt_key, CACHE_REV),
        "urlscan": lambda: urlscan_cached(
            payload_for("urlscan"), settings.urlscan_key, allow_urlscan_submit, CACHE_REV
        ),
        "abuse": lambda: abuse_cached(payload_for("abuse"), settings.abuse_key, CACHE_REV),
        "tf": lambda: tf_cached(payload_for("tf"), settings.threatfox_key, CACHE_REV),
        "mb": lambda: mb_cached(payload_for("mb"), settings.malwarebazaar_key, CACHE_REV),
        "shodan": lambda: shodan_cached(payload_for("shodan"), settings.shodan_key, CACHE_REV),
        "dns": lambda: dnsd_cached(payload_for("dns"), settings.dnsdumpster_key, CACHE_REV),
        "ha": lambda: ha_cached(payload_for("ha"), settings.hybrid_analysis_key, CACHE_REV),
        "mxtoolbox": lambda: mxtoolbox_cached(
            payload_for("mxtoolbox"), settings.mxtoolbox_key, CACHE_REV
        ),
        "whoxy": lambda: whoxy_cached(payload_for("whoxy"), settings.whoxy_key, CACHE_REV),
        "ransomware_live": lambda: ransomware_live_cached(
            payload_for("ransomware_live"), settings.ransomware_live_key, CACHE_REV
        ),
    }


def _with_script_ctx(fn: Callable[[], dict]) -> Callable[[], dict]:
    """Wrap a worker callable so Streamlit's per-script context follows it.

    The provider calls go through ``@st.cache_data`` wrappers, which look up the
    running script's context. A bare worker thread has none, which downgrades
    every cache read to a miss and floods the log with ScriptRunContext warnings.
    Copying the main thread's context onto the worker keeps the cache effective.

    Falls back to the unwrapped callable outside a Streamlit runtime (tests,
    plain scripts), where there is no context to copy.

    Args:
        fn: The zero-arg provider callable to wrap.

    Returns:
        A callable that installs the script context before delegating to ``fn``.
    """
    try:
        from streamlit.runtime.scriptrunner import add_script_run_ctx, get_script_run_ctx
    except ImportError:
        return fn

    ctx = get_script_run_ctx()
    if ctx is None:
        return fn

    def _runner() -> dict:
        import threading

        add_script_run_ctx(threading.current_thread(), ctx)
        return fn()

    return _runner


def run_provider_lookups(
    settings: Settings,
    provider_flags: dict[str, bool],
    payload_for: Callable[[str], Payload],
    allow_urlscan_submit: bool,
) -> tuple[dict[str, dict], dict]:
    """Call every enabled provider concurrently and collect results and timings.

    Provider lookups are I/O-bound (they sit waiting on HTTP), so running each on
    its own worker thread means total wall time is roughly the slowest provider
    rather than the sum of all of them. A provider that raises is logged and
    contributes an empty result instead of aborting the whole run.

    Args:
        settings: Loaded API keys / config.
        provider_flags: Which providers have work to do, keyed by provider key.
            A provider whose flag is False is never called.
        payload_for: Returns the IOC tuples a given provider is allowed to query.
            Called once per enabled provider on the main thread (for the IOC
            count) and once inside the worker (for the lookup itself).
        allow_urlscan_submit: Whether URLScan may submit new scans.

    Returns:
        Tuple of ``(results, timings)``. ``results`` is keyed by the *result*
        key (see :data:`RESULT_KEYS`) and holds ``{}`` for any provider that was
        disabled or failed. ``timings`` carries ``providers`` (per-provider wall
        time and IOC count) and ``providers_total`` (wall time of the whole
        parallel block — not the sum of the per-provider times, which overlap).
    """
    jobs = _build_jobs(settings, payload_for, allow_urlscan_submit)
    results: dict[str, dict] = {RESULT_KEYS[key]: {} for key in jobs}
    timings: dict[str, dict] = {key: {"time": 0.0, "n": 0} for key in jobs}

    active = {key: fn for key, fn in jobs.items() if provider_flags.get(key)}
    if not active:
        return results, {"providers": timings, "providers_total": 0.0}

    for key in active:
        timings[key]["n"] = len(payload_for(key))

    block_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(active)) as pool:
        started: dict[object, float] = {}
        futures = {}
        for key, fn in active.items():
            fut = pool.submit(_with_script_ctx(fn))
            futures[fut] = key
            started[fut] = time.perf_counter()

        for fut in as_completed(futures):
            key = futures[fut]
            timings[key]["time"] = time.perf_counter() - started[fut]
            try:
                results[RESULT_KEYS[key]] = fut.result()
            except Exception as exc:  # noqa: BLE001 — one provider must not sink the run
                logger.error("provider %s lookup failed: %s", key, exc)

    return results, {
        "providers": timings,
        "providers_total": time.perf_counter() - block_start,
    }
