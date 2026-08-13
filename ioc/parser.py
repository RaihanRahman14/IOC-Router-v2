"""IOC parsing and normalization."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse
from dataclasses import dataclass
from typing import List


HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
URL_RE = re.compile(r"^(https?://).+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# Bare keyword: letters/digits/hyphens only, no dots — used for Whoxy keyword reverse WHOIS
WHOIS_KEYWORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{1,61}[A-Za-z0-9]$")

# Host (registrable name or IPv4 literal) followed by a path / query / fragment but
# no scheme — e.g. "example.com/login", "10.0.0.1/admin", "evil.net:8443/panel".
# The trailing delimiter is what separates these from a bare domain.
_SCHEMELESS_HOST = (
    r"(?:(?:(?!-)[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}"
    r"|(?:\d{1,3}\.){3}\d{1,3})"
)
SCHEMELESS_URL_RE = re.compile("^" + _SCHEMELESS_HOST + r"(?::\d{1,5})?[/?#].*$")

# Scheme assumed for schemeless URLs. Chosen for feed matching (ThreatFox and most
# IOC feeds store the http:// form); providers that submit a URL for live browsing
# reorder the variants from ``scheme_variants`` to try https:// first instead.
DEFAULT_SCHEME = "http"


@dataclass
class IOC:
    value: str
    type: str  # ip, domain, url, hash, email, whois
    # True when ``value`` only carries a scheme because the parser added one.
    # Providers use this to decide whether trying the other scheme is worthwhile.
    scheme_inferred: bool = False


def scheme_variants(ioc: IOC, https_first: bool = False) -> list[str]:
    """Return the URL forms a provider should try for this IOC.

    An explicit URL is returned as-is — the analyst typed that exact scheme and
    widening the query would only burn API calls. A URL whose scheme the parser
    inferred returns both the http:// and https:// forms.

    Args:
        ioc: The IOC to expand. Non-URL types return their raw value unchanged.
        https_first: Order https:// ahead of http://. Use for live submission,
            where https is what a browser would actually reach.

    Returns:
        Candidate URL strings, most preferred first, without duplicates.
    """
    value = (ioc.value or "").strip()
    if not value:
        return []
    if ioc.type != "url" or not ioc.scheme_inferred:
        return [value]

    host_path = value.split("://", 1)[-1]
    schemes = ("https", "http") if https_first else ("http", "https")
    out: list[str] = []
    for scheme in schemes:
        candidate = f"{scheme}://{host_path}"
        if candidate not in out:
            out.append(candidate)
    return out


def _normalize_url(value: str) -> str:
    try:
        parsed = urlparse(value)
    except ValueError:
        return value
    if not parsed.scheme or not parsed.netloc:
        return value
    netloc = parsed.netloc.lower()
    normalized = parsed._replace(netloc=netloc)
    return urlunparse(normalized)


def _detect_type(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None
    if HASH_RE.match(v):
        return "hash"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if EMAIL_RE.match(v):
        return "email"
    if URL_RE.match(v):
        return "url"
    if DOMAIN_RE.match(v):
        return "domain"
    if SCHEMELESS_URL_RE.match(v):
        return "url"
    if WHOIS_KEYWORD_RE.match(v):
        return "whois"
    return None


def parse_iocs(
    raw: str,
    auto_detect: bool = True,
    allowed_types: set[str] | None = None,
) -> List[IOC]:
    lines = [ln.strip() for ln in raw.splitlines()]
    cleaned = [ln for ln in lines if ln]
    seen: set[str] = set()
    unique: list[str] = []
    for item in cleaned:
        if item not in seen:
            seen.add(item)
            unique.append(item)

    iocs: List[IOC] = []
    for item in unique:
        t = _detect_type(item)
        if not t:
            continue
        if not auto_detect and allowed_types is not None and t not in allowed_types:
            continue
        scheme_inferred = False
        if t == "url":
            if not URL_RE.match(item):
                item = f"{DEFAULT_SCHEME}://{item}"
                scheme_inferred = True
            item = _normalize_url(item)
        elif t == "domain":
            item = item.lower()
        iocs.append(IOC(value=item, type=t, scheme_inferred=scheme_inferred))
    return iocs
