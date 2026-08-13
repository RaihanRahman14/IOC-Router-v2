"""Shared HTTP plumbing for provider clients — pooled sessions and fan-out.

Two things every provider needs and none of them should reimplement:

* :func:`get_session` — a connection-pooled :class:`requests.Session` so a batch
  of lookups against one API pays for the TCP + TLS handshake once instead of
  once per IOC.
* :func:`run_parallel` — bounded concurrent execution of independent lookups,
  with one failure isolated from the rest.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, TypeVar

import requests

logger = logging.getLogger(__name__)

K = TypeVar("K")
V = TypeVar("V")

# Providers are already fanned out one-thread-per-provider by core.orchestrator.
# This is the *inner* limit, so the ceiling on open sockets is roughly
# (providers) x (this). Kept deliberately small: the bottleneck being solved is
# serialized round trips, not throughput, and threat-intel APIs rate-limit
# aggressively enough that a wide burst buys 429s rather than speed.
DEFAULT_MAX_WORKERS = 6

_local = threading.local()


def get_session() -> requests.Session:
    """Return this thread's pooled HTTP session, creating it on first use.

    One session per thread rather than one global: :class:`requests.Session` is
    not documented as thread-safe, and the provider clients now run on worker
    threads. Thread-local keeps connection reuse (the whole point) without
    sharing mutable connection state across threads.

    Returns:
        A :class:`requests.Session` owned by the calling thread.
    """
    session = getattr(_local, "session", None)
    if session is None:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=DEFAULT_MAX_WORKERS,
            pool_maxsize=DEFAULT_MAX_WORKERS,
            max_retries=0,  # retries stay a provider-level decision
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        _local.session = session
    return session


def run_parallel(
    jobs: dict[K, Callable[[], V]],
    max_workers: int = DEFAULT_MAX_WORKERS,
    label: str = "job",
) -> dict[K, V]:
    """Run independent zero-arg callables concurrently and collect what succeeds.

    A callable that raises is logged and simply omitted from the result, so one
    bad lookup cannot sink the batch around it. Callers read results with
    ``.get(key)`` and supply their own default for the missing ones.

    Args:
        jobs: Mapping of caller-chosen key to the callable producing its value.
        max_workers: Upper bound on concurrent workers.
        label: Noun used in the failure log line, e.g. ``"VirusTotal lookup"``.

    Returns:
        Mapping of key to value for every job that completed without raising.
    """
    if not jobs:
        return {}

    # One job needs no pool — running inline avoids the thread hand-off and
    # keeps the call on the caller's stack, which makes tracebacks readable.
    if len(jobs) == 1:
        (key, fn), = jobs.items()
        try:
            return {key: fn()}
        except Exception as exc:  # noqa: BLE001 — isolate, same as the pooled path
            logger.error("%s %r failed: %s", label, key, exc)
            return {}

    out: dict[K, V] = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(jobs))) as pool:
        futures = {pool.submit(fn): key for key, fn in jobs.items()}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                out[key] = fut.result()
            except Exception as exc:  # noqa: BLE001 — one failure must not sink the batch
                logger.error("%s %r failed: %s", label, key, exc)
    return out
