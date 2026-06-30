"""Path-probe scanner — check HTTP status for many URL paths on one domain.

Classification rule (WAF/exists detection):
    - Confirmed:     200-399, 400-403  (endpoint reachable or WAF-blocked)
    - Not confirmed: 404-599           (not found, server error, etc.)

Errors (timeout, connection refused, malformed URL) are reported separately
as ``classification="error"`` so callers can show them without conflating
them with a real not-found.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Callable, Literal
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

Classification = Literal["confirmed", "not_confirmed", "error"]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (compatible; IOC-Router-PathProbe/1.0)"
)


@dataclass
class ProbeResult:
    """Outcome of probing a single path.

    Attributes:
        path: The original path supplied by the user (e.g. ``"/admin"``).
        url: Final absolute URL constructed for the request.
        status_code: HTTP status, or ``None`` if the request never completed.
        reason: HTTP reason phrase, or an error tag (``TIMEOUT``,
            ``CONNECTION_ERROR``, ``ERROR``).
        classification: ``"confirmed"`` | ``"not_confirmed"`` | ``"error"``.
        elapsed_ms: Wall-clock duration of the request, in milliseconds.
        final_url: URL after redirects (equals ``url`` if no redirect / error).
        content_length: Response body size in bytes, or ``None`` on error.
        error: Short error description when ``classification="error"``.
    """

    path: str
    url: str
    status_code: int | None
    reason: str
    classification: Classification
    elapsed_ms: int
    final_url: str
    content_length: int | None
    error: str | None = None

    def to_row(self) -> dict[str, object]:
        """Return a flat dict suitable for tabular rendering / CSV export."""
        return asdict(self)


def classify_status(code: int) -> Classification:
    """Classify an HTTP status code per the WAF/exists rule.

    Args:
        code: HTTP status code (100-599 expected).

    Returns:
        ``"confirmed"`` for 2xx, 3xx, and 400-403;
        ``"not_confirmed"`` for everything 404-599.
        Values outside 100-599 also fall through to ``"not_confirmed"``.
    """
    if 200 <= code <= 399:
        return "confirmed"
    if 400 <= code <= 403:
        return "confirmed"
    return "not_confirmed"


def clean_paths(raw_text: str) -> list[str]:
    """Aggressive parse of bulk input → deduplicated path list.

    Strips ``"``, ``'``, ``[``, ``]``, splits on newline or comma, ensures
    each path starts with ``/``, removes empties, preserves first-seen order.
    Use this when the user has the cleaner checkbox enabled.

    Args:
        raw_text: Multi-line user input. May contain quotes, brackets,
            and comma separators (e.g. ``["/admin"], '/login'``).

    Returns:
        Deduplicated list of paths, each starting with ``/``.
    """
    cleaned = (
        raw_text
        .replace('"', "")
        .replace("'", "")
        .replace("[", "")
        .replace("]", "")
    )
    paths: list[str] = []
    for item in cleaned.replace("\n", ",").split(","):
        item = item.strip()
        if not item:
            continue
        if not item.startswith("/"):
            item = "/" + item
        paths.append(item)
    return list(dict.fromkeys(paths))


def split_paths(raw_text: str) -> list[str]:
    """Conservative parse: newline-split only, no quote/bracket stripping.

    Use this when the user has the cleaner checkbox disabled — paths that
    legitimately contain ``,``, ``[``, or quotes (rare but possible) survive.

    Args:
        raw_text: Multi-line user input.

    Returns:
        Deduplicated list of stripped paths, each starting with ``/``.
    """
    paths: list[str] = []
    for line in raw_text.splitlines():
        item = line.strip()
        if not item:
            continue
        if not item.startswith("/"):
            item = "/" + item
        paths.append(item)
    return list(dict.fromkeys(paths))


def normalize_domain(domain: str) -> str:
    """Prepend ``https://`` if missing; strip trailing slash.

    Args:
        domain: User-supplied domain, with or without scheme.

    Returns:
        Normalized base URL without trailing slash.
    """
    d = domain.strip()
    if not d:
        return ""
    if not d.startswith(("http://", "https://")):
        d = "https://" + d
    return d.rstrip("/")


def _probe_one(
    session: requests.Session,
    base: str,
    path: str,
    *,
    method: str,
    timeout: float,
    follow_redirects: bool,
    verify_ssl: bool,
) -> ProbeResult:
    """Send one probe request and wrap the outcome in a :class:`ProbeResult`.

    Args:
        session: Shared :class:`requests.Session` (connection pooled).
        base: Normalized base URL (no trailing slash).
        path: User-supplied path starting with ``/``.
        method: HTTP method (``GET`` by default).
        timeout: Per-request timeout in seconds.
        follow_redirects: Whether to follow 3xx redirects.
        verify_ssl: Whether to verify TLS certs.

    Returns:
        A :class:`ProbeResult`. Network errors are captured, never raised.
    """
    url = urljoin(base + "/", path.lstrip("/"))
    start = time.time()
    try:
        resp = session.request(
            method.upper(),
            url,
            timeout=timeout,
            allow_redirects=follow_redirects,
            verify=verify_ssl,
        )
    except requests.exceptions.Timeout:
        elapsed_ms = int((time.time() - start) * 1000)
        return ProbeResult(
            path=path, url=url, status_code=None, reason="TIMEOUT",
            classification="error", elapsed_ms=elapsed_ms, final_url=url,
            content_length=None, error="timeout",
        )
    except requests.exceptions.ConnectionError as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return ProbeResult(
            path=path, url=url, status_code=None, reason="CONNECTION_ERROR",
            classification="error", elapsed_ms=elapsed_ms, final_url=url,
            content_length=None, error=f"connection: {exc.__class__.__name__}",
        )
    except requests.exceptions.RequestException as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        logger.error("path-probe request failed for %s: %s", url, exc)
        return ProbeResult(
            path=path, url=url, status_code=None, reason="ERROR",
            classification="error", elapsed_ms=elapsed_ms, final_url=url,
            content_length=None, error=str(exc)[:200],
        )

    elapsed_ms = int((time.time() - start) * 1000)
    clen_header = resp.headers.get("Content-Length")
    if clen_header and clen_header.isdigit():
        content_length: int | None = int(clen_header)
    else:
        content_length = len(resp.content)

    return ProbeResult(
        path=path,
        url=url,
        status_code=resp.status_code,
        reason=resp.reason or "",
        classification=classify_status(resp.status_code),
        elapsed_ms=elapsed_ms,
        final_url=str(resp.url),
        content_length=content_length,
    )


def probe_paths(
    domain: str,
    paths: list[str],
    *,
    method: str = "GET",
    timeout: float = 10.0,
    concurrency: int = 10,
    user_agent: str = DEFAULT_USER_AGENT,
    follow_redirects: bool = True,
    verify_ssl: bool = False,
    on_result: Callable[[ProbeResult], None] | None = None,
) -> list[ProbeResult]:
    """Probe ``paths`` against ``domain`` in parallel.

    Args:
        domain: Target domain. ``https://`` is prepended if no scheme.
        paths: Paths to probe — pass output of :func:`clean_paths` or
            :func:`split_paths`.
        method: HTTP method (``GET`` by default).
        timeout: Per-request timeout in seconds.
        concurrency: Max parallel workers (clamped to 1-50).
        user_agent: ``User-Agent`` header value.
        follow_redirects: Whether to follow 3xx redirects.
        verify_ssl: Whether to verify TLS certs. Default ``False`` — probes
            often target self-signed dev hosts.
        on_result: Optional callback invoked with each :class:`ProbeResult`
            as it completes (used for live UI updates).

    Returns:
        List of :class:`ProbeResult` in completion order. Empty list if
        ``domain`` or ``paths`` is empty.
    """
    base = normalize_domain(domain)
    if not base or not paths:
        return []

    workers = max(1, min(int(concurrency), 50))
    results: list[ProbeResult] = []

    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _probe_one,
                    session, base, p,
                    method=method, timeout=timeout,
                    follow_redirects=follow_redirects,
                    verify_ssl=verify_ssl,
                ): p
                for p in paths
            }
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception as exc:  # noqa: BLE001 — defensive
                    logger.error("probe future failed: %s", exc)
                    continue
                results.append(res)
                if on_result is not None:
                    try:
                        on_result(res)
                    except Exception as exc:  # noqa: BLE001 — UI cb shield
                        logger.error("on_result callback raised: %s", exc)
    finally:
        session.close()

    return results
