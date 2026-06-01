"""Infrastructure classification by ASN / provider.

Classifies an IP / ASN / provider into one of three buckets used by the IOC
router to influence verdicts:

  - BP (Benign Positive)  : anycast / CDN / public DNS — hard whitelist
                            (Threat Indicator severity: MEDIUM per project spec)
  - FP (False Positive)   : shared VPS / hyperscaler compute — confidence
                            discount (Threat Indicator severity: LOW)
  - HIGH_RISK             : bulletproof hosting — confidence boost
                            (Threat Indicator severity: HIGH)

For hyperscalers (AWS / GCP / Azure) where one ASN covers both CDN and compute,
the IP is refined against the published CDN ranges (CloudFront from
``ip-ranges.amazonaws.com``) to pick the correct bucket.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Optional

import requests


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ASN tables
# ---------------------------------------------------------------------------

# Category 1 — BP / hard whitelist. anycast or always-legitimate infra.
BP_ASNS: dict[int, dict] = {
    15169: {"provider": "Google",        "reason": "Google DNS / CDN / APIs (anycast)"},
    13335: {"provider": "Cloudflare",    "reason": "Cloudflare DNS / CDN (anycast)"},
    19281: {"provider": "Quad9",         "reason": "Quad9 public DNS resolver (anycast)"},
    20940: {"provider": "Akamai",        "reason": "Akamai CDN (anycast)"},
    54113: {"provider": "Fastly",        "reason": "Fastly CDN (anycast)"},
    # AWS / GCP / Azure are dual-use — refined further down. Kept out of this
    # table so the default classification is FP unless the IP falls inside a
    # known CDN range (e.g. CloudFront).
}

# Category 2 — FP-prone shared hosting / compute. Discount confidence only.
FP_ASNS: dict[int, dict] = {
    14061: {"provider": "DigitalOcean",  "reason": "Shared VPS, frequent abuse"},
    63949: {"provider": "Linode/Akamai", "reason": "Shared cloud infra, multi-tenant"},
    20473: {"provider": "Vultr",         "reason": "Budget VPS, attacker-friendly"},
    24940: {"provider": "Hetzner",       "reason": "Budget EU server, abuse-prone"},
    16276: {"provider": "OVHcloud",      "reason": "Massive shared hosting, high abuse"},
    51167: {"provider": "Contabo",       "reason": "Very cheap VPS, attacker magnet"},
    47583: {"provider": "Hostinger",     "reason": "Shared hosting"},
    26496: {"provider": "GoDaddy",       "reason": "Shared web hosting"},
    16509: {"provider": "Amazon AWS",    "reason": "EC2 compute (not CloudFront)"},
    # 15169 (Google) and 8075 (Microsoft) handled below via hyperscaler logic
    # — they appear in HYPERSCALER_ASNS so refinement can promote BP.
}

# Category 3 — bulletproof / abuse-friendly hosting. Boost confidence.
# Identification is primarily by ASN org name (case-insensitive substring),
# because BPH operators rotate ASNs and tier-1 ASNs are not always public.
HIGH_RISK_ASNS: dict[int, dict] = {
    # Proton66 / PROSPERO LLC
    200593: {"provider": "Proton66",     "reason": "Bulletproof hosting (ransomware infra)"},
    # Chang Way Technologies
    57523:  {"provider": "Chang Way",    "reason": "Bulletproof hosting"},
    # Media Land LLC
    206728: {"provider": "Media Land",   "reason": "Tier-1 bulletproof hosting"},
    # PQ Hosting / Selectel
    49505:  {"provider": "Selectel",     "reason": "Eastern EU abuse-friendly hosting"},
    # AEZA Group
    210644: {"provider": "AEZA Group",   "reason": "Russian bulletproof hosting"},
    # Flyservers
    209588: {"provider": "Flyservers",   "reason": "Linked to FIN7 activity"},
    # SmartApe
    56694:  {"provider": "SmartApe",     "reason": "Ransomware-affiliated hosting"},
}

# Fallback org-name substring matchers (lowercase). Used when ASN number is
# unknown / rotated but the org string identifies the provider.
HIGH_RISK_ORG_HINTS: tuple[tuple[str, dict], ...] = (
    ("proton66",       {"provider": "Proton66",      "reason": "Bulletproof hosting (ransomware infra)"}),
    ("prospero",       {"provider": "PROSPERO",      "reason": "Bulletproof hosting (ransomware infra)"}),
    ("chang way",      {"provider": "Chang Way",     "reason": "Bulletproof hosting"}),
    ("media land",     {"provider": "Media Land",    "reason": "Tier-1 bulletproof hosting"}),
    ("pq hosting",     {"provider": "PQ Hosting",    "reason": "Eastern EU abuse-friendly hosting"}),
    ("selectel",       {"provider": "Selectel",      "reason": "Eastern EU abuse-friendly hosting"}),
    ("aeza",           {"provider": "AEZA Group",    "reason": "Russian bulletproof hosting"}),
    ("flyservers",     {"provider": "Flyservers",    "reason": "Linked to FIN7 activity"}),
    ("smartape",       {"provider": "SmartApe",      "reason": "Ransomware-affiliated hosting"}),
)

# Hyperscaler ASNs that need IP-range refinement (CDN -> BP, compute -> FP).
HYPERSCALER_ASNS: dict[int, dict] = {
    16509: {"provider": "Amazon AWS",    "cdn_label": "Amazon CloudFront", "compute_label": "Amazon EC2"},
    15169: {"provider": "Google Cloud",  "cdn_label": "Google CDN / APIs", "compute_label": "Google Compute Engine"},
    8075:  {"provider": "Microsoft",     "cdn_label": "Azure CDN",         "compute_label": "Azure / Microsoft compute"},
}

# Category constants (also exported for downstream code).
CAT_BP = "BP"
CAT_FP = "FP"
CAT_HIGH_RISK = "HIGH_RISK"

# Threat-indicator severity mapping per project spec.
CATEGORY_TO_SEVERITY: dict[str, str] = {
    CAT_BP: "MEDIUM",
    CAT_FP: "LOW",
    CAT_HIGH_RISK: "HIGH",
}


# ---------------------------------------------------------------------------
# AWS CloudFront range cache
# ---------------------------------------------------------------------------

_AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
_AWS_CACHE_TTL = 24 * 60 * 60  # 24h

_aws_cache_lock = threading.Lock()
_aws_cache: dict = {
    "fetched_at": 0.0,
    "cloudfront_v4": [],   # list[ipaddress.IPv4Network]
    "cloudfront_v6": [],   # list[ipaddress.IPv6Network]
}


def _refresh_aws_ranges(timeout: int = 10) -> None:
    """Fetch AWS published ranges and cache CloudFront subnets.

    Args:
        timeout: HTTP timeout in seconds.

    Returns:
        None. Updates the module-level cache in place. Failures are logged
        and leave the existing cache untouched.
    """
    try:
        resp = requests.get(_AWS_RANGES_URL, timeout=timeout)
    except requests.RequestException as exc:
        logger.warning("AWS ip-ranges fetch failed: %s", exc)
        return
    if resp.status_code != 200:
        logger.warning("AWS ip-ranges HTTP %s", resp.status_code)
        return
    try:
        data = resp.json()
    except ValueError:
        logger.warning("AWS ip-ranges returned non-JSON body")
        return

    cf_v4: list[ipaddress.IPv4Network] = []
    for entry in data.get("prefixes") or []:
        if entry.get("service") == "CLOUDFRONT" and entry.get("ip_prefix"):
            try:
                cf_v4.append(ipaddress.ip_network(entry["ip_prefix"], strict=False))
            except ValueError:
                continue
    cf_v6: list[ipaddress.IPv6Network] = []
    for entry in data.get("ipv6_prefixes") or []:
        if entry.get("service") == "CLOUDFRONT" and entry.get("ipv6_prefix"):
            try:
                cf_v6.append(ipaddress.ip_network(entry["ipv6_prefix"], strict=False))
            except ValueError:
                continue

    with _aws_cache_lock:
        _aws_cache["fetched_at"] = time.time()
        _aws_cache["cloudfront_v4"] = cf_v4
        _aws_cache["cloudfront_v6"] = cf_v6


def _ensure_aws_cache(force: bool = False) -> None:
    """Refresh the AWS ranges cache if it is empty or stale."""
    with _aws_cache_lock:
        age = time.time() - _aws_cache.get("fetched_at", 0.0)
        has_data = bool(_aws_cache.get("cloudfront_v4") or _aws_cache.get("cloudfront_v6"))
    if force or not has_data or age > _AWS_CACHE_TTL:
        _refresh_aws_ranges()


def is_cloudfront_ip(ip: str) -> bool:
    """Return True if ``ip`` is in a published AWS CloudFront subnet.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        True if the address belongs to a CloudFront prefix, False otherwise
        (including parse failures and network errors).
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    _ensure_aws_cache()
    with _aws_cache_lock:
        nets = _aws_cache["cloudfront_v4"] if addr.version == 4 else _aws_cache["cloudfront_v6"]
        snap = list(nets)
    return any(addr in net for net in snap)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _normalize_asn(asn) -> Optional[int]:
    """Coerce ASN inputs like ``"AS15169"``, ``"15169"``, ``15169`` to int."""
    if asn is None:
        return None
    if isinstance(asn, int):
        return asn
    s = str(asn).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    try:
        return int(s)
    except ValueError:
        return None


def _match_high_risk_org(org: Optional[str]) -> Optional[dict]:
    if not org:
        return None
    needle = org.lower()
    for hint, payload in HIGH_RISK_ORG_HINTS:
        if hint in needle:
            return payload
    return None


def classify(asn=None, org: Optional[str] = None, ip: Optional[str] = None) -> Optional[dict]:
    """Classify an infrastructure data point.

    Args:
        asn: ASN as int or string (``"AS15169"`` / ``"15169"``). Optional.
        org: AS owner / organization name. Used as a fallback signal and for
            hyperscaler refinement when ASN alone is ambiguous.
        ip: Address string. Used to refine hyperscaler classification against
            published CDN ranges.

    Returns:
        A dict ``{"category", "severity", "provider", "reason", "asn"}`` when
        a match is found, or ``None`` when the infra does not match any
        known BP / FP / HIGH_RISK entry. The caller can treat ``None`` as
        "no infra hint — apply normal scoring".
    """
    asn_int = _normalize_asn(asn)

    # 1. High-risk org match wins over ASN (bulletproof providers rotate ASNs).
    org_match = _match_high_risk_org(org)
    if org_match:
        return _make_result(CAT_HIGH_RISK, org_match["provider"], org_match["reason"], asn_int)

    if asn_int is not None and asn_int in HIGH_RISK_ASNS:
        meta = HIGH_RISK_ASNS[asn_int]
        return _make_result(CAT_HIGH_RISK, meta["provider"], meta["reason"], asn_int)

    # 2. Hyperscaler refinement (AWS / GCP / Azure share ASN across CDN+compute).
    if asn_int is not None and asn_int in HYPERSCALER_ASNS:
        meta = HYPERSCALER_ASNS[asn_int]
        if asn_int == 16509 and ip and is_cloudfront_ip(ip):
            return _make_result(
                CAT_BP,
                meta["cdn_label"],
                "AWS CloudFront anycast CDN (matched ip-ranges.json)",
                asn_int,
            )
        # GCP / Azure: PTR-based refinement would need extra lookups; default
        # to FP for these ASNs because compute is the more common case.
        # Google's public DNS is still BP because 8.8.8.8 / 8.8.4.4 are
        # captured via the explicit IP shortcut below.
        if asn_int == 15169 and ip in ("8.8.8.8", "8.8.4.4"):
            return _make_result(CAT_BP, "Google Public DNS", "Public DNS resolver (anycast)", asn_int)
        if asn_int == 8075:
            return _make_result(CAT_FP, meta["compute_label"], "Azure / Microsoft compute (shared)", asn_int)
        if asn_int == 15169:
            return _make_result(CAT_FP, meta["compute_label"], "GCE compute (shared)", asn_int)
        if asn_int == 16509:
            return _make_result(CAT_FP, meta["compute_label"], "EC2 compute (shared)", asn_int)

    # 3. Pure BP table (non-hyperscaler).
    if asn_int is not None and asn_int in BP_ASNS:
        meta = BP_ASNS[asn_int]
        return _make_result(CAT_BP, meta["provider"], meta["reason"], asn_int)
    # 1.1.1.1 / 1.0.0.1 belong to Cloudflare AS13335 above. Quad9 9.9.9.9
    # belongs to AS19281 above. Both already covered by BP_ASNS.

    # 4. Pure FP table.
    if asn_int is not None and asn_int in FP_ASNS:
        meta = FP_ASNS[asn_int]
        return _make_result(CAT_FP, meta["provider"], meta["reason"], asn_int)

    return None


def _make_result(category: str, provider: str, reason: str, asn: Optional[int]) -> dict:
    return {
        "category": category,
        "severity": CATEGORY_TO_SEVERITY[category],
        "provider": provider,
        "reason": reason,
        "asn": asn,
    }


# ---------------------------------------------------------------------------
# Optional ASN lookup for providers that do not include ASN in their response
# (e.g. Shodan InternetDB).
# ---------------------------------------------------------------------------

_ASN_LOOKUP_URL = "https://ipwho.is/{ip}"
_asn_lookup_cache: dict[str, tuple[Optional[int], Optional[str]]] = {}
_asn_lookup_lock = threading.Lock()


def lookup_asn(ip: str, timeout: int = 5) -> tuple[Optional[int], Optional[str]]:
    """Look up ASN and org for ``ip`` via the free ipwho.is endpoint.

    Args:
        ip: IPv4 / IPv6 address string.
        timeout: HTTP timeout in seconds.

    Returns:
        Tuple ``(asn, org)`` where either element may be ``None`` if the
        lookup failed or the response lacked the field. Results are cached
        in-process for the lifetime of the module.

    Raises:
        Never raises — network and parse errors return ``(None, None)``.
    """
    if not ip:
        return None, None
    with _asn_lookup_lock:
        if ip in _asn_lookup_cache:
            return _asn_lookup_cache[ip]
    try:
        resp = requests.get(_ASN_LOOKUP_URL.format(ip=ip), timeout=timeout)
    except requests.RequestException:
        result: tuple[Optional[int], Optional[str]] = (None, None)
        with _asn_lookup_lock:
            _asn_lookup_cache[ip] = result
        return result
    if resp.status_code != 200:
        with _asn_lookup_lock:
            _asn_lookup_cache[ip] = (None, None)
        return None, None
    try:
        payload = resp.json()
    except ValueError:
        with _asn_lookup_lock:
            _asn_lookup_cache[ip] = (None, None)
        return None, None
    conn = payload.get("connection") or {}
    asn = _normalize_asn(conn.get("asn"))
    org = conn.get("org") or conn.get("isp")
    result = (asn, str(org) if org else None)
    with _asn_lookup_lock:
        _asn_lookup_cache[ip] = result
    return result
