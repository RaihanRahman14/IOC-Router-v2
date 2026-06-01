"""Recent CVE panel using NVD API v2 with lazy loading (10 per page)."""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

_WIB = timezone(timedelta(hours=7))  # UTC+7 Jakarta / WIB

import base64

import requests
import streamlit as st
import streamlit.components.v1 as components

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_NVD_MAX_PAGE = 2000  # NVD API hard limit per request
_CACHE_TTL = 900  # 15 minutes — shorter TTL to keep 3-hour window fresh

_SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#ef4444", "#2d0a0a"),
    "HIGH":     ("#f97316", "#2d1500"),
    "MEDIUM":   ("#eab308", "#2a2000"),
    "LOW":      ("#4ade80", "#0a2010"),
    "NONE":     ("#6b7280", "#1a1d23"),
    "N/A":      ("#6b7280", "#1a1d23"),
}

_FILTER_OPTIONS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "Common", "ALL", "Select"]
_SEVERITY_FILTERS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

CVE_RECORD_URL = "https://www.cve.org/CVERecord?id={cve_id}"

# Keywords checked case-insensitively across vendor + product + description.
_COMMON_APP_KEYWORDS: list[str] = [
    "cisco", "fortinet", "palo alto", "paloalto", "vmware", "dell",
    "huawei", "microsoft edge", "microsoft authenticator", "microsoft",
    "google chrome", "chrome", "firefox", "zoom", "slack",
    "whatsapp desktop", "telegram desktop", "notion", "google drive",
    "bitwarden", "lastpass",
]
# Short/ambiguous tokens — matched against vendor+product only to avoid false positives.
_COMMON_APP_VENDOR_ONLY: list[str] = ["hp", "edge"]

# Keyword → human-readable display label.
# _match_common_keyword sorts longest-first so "microsoft edge" wins over "microsoft",
# "microsoft authenticator" wins over "microsoft", "google chrome" wins over "chrome", etc.
_COMMON_KEYWORD_LABEL: dict[str, str] = {
    "microsoft authenticator": "Microsoft Authenticator",
    "microsoft edge":          "Microsoft Edge",
    "whatsapp desktop":        "WhatsApp Desktop",
    "telegram desktop":        "Telegram Desktop",
    "google chrome":           "Google Chrome",
    "google drive":            "Google Drive",
    "palo alto":               "Palo Alto Networks",
    "paloalto":                "Palo Alto Networks",
    "cisco":                   "Cisco",
    "fortinet":                "Fortinet",
    "vmware":                  "VMware",
    "dell":                    "Dell",
    "huawei":                  "Huawei",
    "microsoft":               "Microsoft",
    "chrome":                  "Google Chrome",
    "firefox":                 "Firefox",
    "zoom":                    "Zoom",
    "slack":                   "Slack",
    "notion":                  "Notion",
    "bitwarden":               "Bitwarden",
    "lastpass":                "LastPass",
    "hp":                      "HP",
    "edge":                    "Microsoft Edge",
}

# ── Description-based product extraction regexes ─────────────────────────────
# Tried in order inside _product_from_desc(); first match wins.

# "BigBlueButton is an open-source…" / "Mullvad VPN is a VPN client…"
# Also handles "(MantisBT)" abbreviation suffix.
_PRODUCT_IS_RE = re.compile(
    r"^([A-Z][A-Za-z0-9\+][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,4})"
    r"(?:\s+\([^)]+\))?\s+is\s+",
)

# "libheif is a HEIF…" — lowercase library/package names before "is a/an"
_LOWLIB_IS_RE = re.compile(
    r"^([a-z][A-Za-z0-9_\-\.]+)\s+is\s+(?:a|an|the|free|one|not|open)\s",
)

# "In MLflow version 3.9.0…" / "In BYD Atto3, an attacker…" / "In ScadaBR version 1.2.0…"
# Must be checked BEFORE _PRODUCT_SUBJECT_RE to prevent "In ScadaBR" being captured as product.
_IN_PRODUCT_START_RE = re.compile(
    r"^In\s+((?:[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,3}))"
    r"(?:,|\s+v\d|\s+version\b|\s+\()",
)

# "NVIDIA DGX OS contains…" / "HestiaCP versions 1.9.0 contain…" / "BillaBear (all versions…) contains…"
# "Technitium DNS Server aggressively tries…" / "Ledger Live with vulnerable versions…"
_PRODUCT_SUBJECT_RE = re.compile(
    r"^([A-Z][A-Za-z0-9\+][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,4})"
    r"(?:\s+\([^)]+\))?"
    r"\s+(?:contain|is\s+vulnerable|allow|prior\s+to|before\s+version|has\s+a|"
    r"is\s+susceptible|does\s+not\s+properly|fail|versions?\s+\d|v\d+\.\d|"
    r"uses\s+|requires?\s+|aggressively|with\s+vulnerable|devices?\s+contain)",
)

# "This vulnerability was fixed in Firefox 151…" — Mozilla-style advisories
_FIXED_IN_RE = re.compile(
    r"[Tt]his\s+vulnerability\s+was\s+fixed\s+in\s+"
    r"((?:[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,2}))"
    r"\s+\d",
)

# "This issue affects Apache OFBiz: before…" / "This issue affects Escargot: …"
_THIS_ISSUE_RE = re.compile(
    r"[Tt]his\s+issue\s+affects?\s+"
    r"((?:[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,3}))"
    r"(?::|\.|\s+(?:before|prior|through|version))",
)

# "The Piotnet Addons for Elementor Pro plugin for WordPress is vulnerable…"
# Lazy match stops at the first plugin/extension/component/module keyword.
_THE_PLUGIN_RE = re.compile(
    r"^The\s+([A-Z][A-Za-z0-9][A-Za-z0-9_\-]*(?:\s+[A-Za-z][A-Za-z0-9_\-]*){0,6}?)"
    r"\s+(?:plugin|extension|component|module)\s+(?:for\s+\S+\s+)?(?:is|before|prior|through)",
)

# "An issue was discovered in the Portrait Dell Color Management application before…"
# "discovered in the Motorola Factory Test component (com.motorola.motocit)…"
_IN_THE_APP_RE = re.compile(
    r"\bin\s+the\s+((?:[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,4}))"
    r"\s+(?:application|software|system|module|service|platform|tool|library|framework|plugin|extension|component)\b",
)

# "A path traversal vulnerability exists in the Altium Enterprise Server ComparisonService due to…"
# "A local privilege escalation vulnerability exists in O+ Connect because it fails…"
# "A flaw was found in Keycloak. An authenticated user…"
# No dot in character class — prevents "Keycloak." from being absorbed into the product name.
_EXISTS_IN_RE = re.compile(
    r"\b(?:exists|found|identified)\s+in\s+(?:the\s+)?"
    r"((?:[A-Z][A-Za-z0-9\+][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,3}))"
    r"(?:\s+(?:due\s+to|because|through|when|by\s+|allowing|via|where\s+)|[.,]|$)",
)

# "vulnerability exists in the /cgi-bin endpoint of Panabit PAP-XM320…"
# "authentication bypass exists in the embedded HTTP server of Panabit PAP-XM320…"
_OF_PRODUCT_RE = re.compile(
    r"\b(?:endpoint|interface|server|backend|component|service)\s+of\s+"
    r"((?:[A-Z][A-Za-z0-9\+][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,3}))"
    r"(?:\s+(?:up\s+to|before|prior|through|allows?|v\d)|\s*[,.]|$)",
)

# "versions of the package exifreader" / "affects the package foo"
_OF_PACKAGE_RE = re.compile(
    r"(?:of|for)\s+the\s+package\s+([A-Za-z][A-Za-z0-9_\-\.@/]+)",
    re.IGNORECASE,
)

# Sentence boundary — truncate here so "Keycloak. An" doesn't bleed into the product name.
# Matches ". " (sentence end) or common version/impact markers.
_DESC_BOUNDARY_RE = re.compile(
    r"(?:\.\s|\s+(?:prior\s+to|before\s+version|through\s+\d|allowed\s+a|"
    r"on\s+(?:Linux|Windows|Android|iOS|macOS|Mac\b)))",
    re.IGNORECASE,
)

# Last-resort: all "in {TitleCase word(s)}" up to 4 tokens; take the LAST match.
# Sub-components appear first ("in GFX"), the actual product appears last ("in Google Chrome").
# Second char allows '+' so "O+ Connect" is captured correctly.
_IN_PRODUCT_RE = re.compile(
    r"\bin\s+((?:[A-Z][A-Za-z0-9\+][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,3}))",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _product_from_desc(full_desc: str) -> str:
    """Extract the affected product name from a CVE description string.

    Tries patterns in priority order; returns empty string if nothing matches.
    """
    # 1. "BigBlueButton is an open-source…"
    m = _PRODUCT_IS_RE.match(full_desc)
    if m:
        return m.group(1).strip()

    # 2. "libheif is a HEIF…" (lowercase lib names)
    m = _LOWLIB_IS_RE.match(full_desc)
    if m:
        return m.group(1).strip()

    # 3. "In MLflow version 3.9…" / "In BYD Atto3, …"
    # Checked before _PRODUCT_SUBJECT_RE so "In {Product}" isn't captured with "In" prefix.
    m = _IN_PRODUCT_START_RE.match(full_desc)
    if m:
        return m.group(1).strip()

    # 4. "NVIDIA DGX OS contains…" / "Technitium DNS Server aggressively…"
    m = _PRODUCT_SUBJECT_RE.match(full_desc)
    if m:
        return m.group(1).strip()

    # 5. "This vulnerability was fixed in Firefox 151…"
    m = _FIXED_IN_RE.search(full_desc)
    if m:
        return m.group(1).strip()

    # 6. "This issue affects Apache OFBiz: before…"
    m = _THIS_ISSUE_RE.search(full_desc)
    if m:
        return m.group(1).strip()

    # 7. "The Piotnet Addons for Elementor Pro plugin for WordPress is vulnerable…"
    m = _THE_PLUGIN_RE.match(full_desc)
    if m:
        return m.group(1).strip()

    # 8. "An issue was discovered in the Portrait Dell Color Management application…"
    #    "in the Motorola Factory Test component (com.motorola.motocit)…"
    m = _IN_THE_APP_RE.search(full_desc)
    if m:
        return m.group(1).strip()

    # 9. "vulnerability exists in the Altium Enterprise Server ComparisonService due to…"
    #    "flaw was found in Keycloak. An authenticated user…"
    m = _EXISTS_IN_RE.search(full_desc)
    if m:
        return m.group(1).strip()

    # 10. "vulnerability exists in … endpoint of Panabit PAP-XM320 up to…"
    m = _OF_PRODUCT_RE.search(full_desc)
    if m:
        return m.group(1).strip()

    # 11. "of the package exifreader"
    m = _OF_PACKAGE_RE.search(full_desc)
    if m:
        return m.group(1).strip()

    # 11. Last resort — truncate at sentence/version boundary, collect all
    #     "in {TitleCase}" matches, return the last one (deepest = actual product).
    boundary = _DESC_BOUNDARY_RE.search(full_desc)
    text = full_desc[:boundary.start()] if boundary else full_desc
    matches = _IN_PRODUCT_RE.findall(text)
    if matches:
        return matches[-1].strip()

    # 12. If boundary truncation cleaned the text, grab the leading title-case sequence.
    #     Covers "Funnel Builder for WooCommerce Checkout prior to…" → "Funnel Builder".
    if boundary:
        m = re.match(
            r"^([A-Z][A-Za-z0-9\+][A-Za-z0-9_\-]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-]*){0,4})",
            text,
        )
        if m:
            return m.group(1).strip()

    return ""


def _match_common_keyword(text: str) -> str:
    """Return the display label for the first common-app keyword found in *text*.

    Checks longer keys first so "microsoft authenticator" wins over "microsoft".
    Returns empty string when nothing matches.
    """
    text_lower = text.lower()
    for kw in sorted(_COMMON_KEYWORD_LABEL, key=len, reverse=True):
        if kw in text_lower:
            return _COMMON_KEYWORD_LABEL[kw]
    # vendor-only keywords (hp, edge) — check without description to avoid false positives
    return ""


def _match_common_keyword_vendor_only(vendor_product: str) -> str:
    """Return the display label for vendor-only keywords (hp, edge)."""
    vp_lower = vendor_product.lower()
    for kw in _COMMON_APP_VENDOR_ONLY:
        if kw in vp_lower:
            return _COMMON_KEYWORD_LABEL.get(kw, kw.upper())
    return ""


def _is_common_app(v: dict) -> bool:
    """Return True if the CVE involves a well-known application from the common app list.

    Args:
        v: Parsed CVE dict from _parse_nvd_item.

    Returns:
        True if any common-app keyword is found in the CVE fields.
    """
    vendor = v.get("vendorProject", "").lower()
    product = v.get("product", "").lower()
    desc = v.get("description", "").lower()
    full_text = f"{vendor} {product} {desc}"
    vendor_product = f"{vendor} {product}"

    if any(kw in full_text for kw in _COMMON_APP_KEYWORDS):
        return True
    return any(kw in vendor_product for kw in _COMMON_APP_VENDOR_ONLY)


def _severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to a severity label."""
    if score is None:
        return "N/A"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _extract_cvss(metrics: dict) -> tuple[float | None, str]:
    """Extract best available CVSS score and severity from an NVD metrics dict.

    Prefers Primary (NVD) scores; falls back to Secondary (CNA) scores when
    NVD has not yet published its own analysis.

    Args:
        metrics: The metrics dict from an NVD CVE item.

    Returns:
        Tuple of (score, severity_label).
    """
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type", "").lower() == "primary"), None)
        entry = primary or entries[0]
        cvss_data = entry.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = (cvss_data.get("baseSeverity") or _severity_from_score(score)).upper()
        return score, severity
    return None, "N/A"


def _extract_vendor_product(configurations: list) -> tuple[str, str]:
    """Extract vendor and product name from NVD CPE configurations.

    Args:
        configurations: The configurations list from an NVD CVE item.

    Returns:
        Tuple of (vendor, product), empty strings if not found.
    """
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5 and parts[3] not in ("*", "-", ""):
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title() if parts[4] not in ("*", "-") else ""
                    return vendor, product
    return "", ""


def _parse_nvd_item(item: dict, kev_data: dict[str, dict]) -> dict:
    """Parse a single NVD vulnerability item into a display-ready dict.

    Vendor/product resolution order:
      1. NVD CPE configurations (populated after NVD analysis)
      2. CISA KEV catalog entry (available immediately for KEV CVEs)
      3. sourceIdentifier domain (e.g. "security@apache.org" → "Apache")
      4. Description text regex — "vulnerability in <Product>" pattern

    Args:
        item: A single entry from NVD vulnerabilities list.
        kev_data: Dict mapping CVE ID to {vendorProject, product} from CISA KEV.

    Returns:
        Dict with display fields for a CVE card.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    desc_full = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )
    desc = desc_full[:117] + "..." if len(desc_full) > 120 else desc_full

    score, severity = _extract_cvss(cve.get("metrics", {}))
    vendor, product = _extract_vendor_product(cve.get("configurations", []))

    kev_entry = kev_data.get(cve_id, {})

    if not vendor and not product and kev_entry:
        vendor = kev_entry.get("vendorProject", "")
        product = kev_entry.get("product", "")

    if not vendor and not product:
        full_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        if full_desc:
            vendor = _product_from_desc(full_desc)
            # Last fallback: if regex still found nothing but the CVE mentions a common app,
            # use the keyword label so "Common"-tagged CVEs always have a visible label.
            if not vendor:
                vendor = _match_common_keyword(full_desc)

    pub_raw = cve.get("published", "")
    try:
        # NVD published timestamps are UTC; convert to WIB (UTC+7) for display
        pub_utc = datetime.strptime(pub_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        pub_wib = pub_utc.astimezone(_WIB)
        date_published = pub_wib.strftime("%Y-%m-%d")
        time_published = pub_wib.strftime("%H:%M")
    except (ValueError, TypeError):
        date_published = pub_raw[:10]
        time_published = pub_raw[11:16] if len(pub_raw) >= 16 else ""

    return {
        "cveID": cve_id,
        "vendorProject": vendor,
        "product": product,
        "description": desc,
        "descriptionFull": desc_full,
        "datePublished": date_published,
        "timePublished": time_published,
        "publishedRaw": pub_raw,
        "score": score,
        "severity": severity,
        "isKev": bool(kev_entry),
    }


# ── API fetchers ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=_CACHE_TTL, show_spinner=False)
def _fetch_kev_data() -> dict[str, dict]:
    """Fetch CISA KEV catalog, keyed by CVE ID with vendor/product metadata.

    Returns:
        Dict mapping CVE ID to a dict with vendorProject and product strings.
    """
    try:
        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        return {
            v.get("cveID", ""): {
                "vendorProject": v.get("vendorProject", ""),
                "product": v.get("product", ""),
            }
            for v in resp.json().get("vulnerabilities", [])
        }
    except requests.RequestException as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return {}


@st.cache_data(ttl=_CACHE_TTL, show_spinner=False)
def _fetch_nvd_page(pub_start: str, pub_end: str, start_index: int) -> dict:
    """Fetch one page of CVEs from NVD API v2 (up to _NVD_MAX_PAGE results).

    Args:
        pub_start: ISO-8601 start datetime string (UTC).
        pub_end: ISO-8601 end datetime string (UTC).
        start_index: Zero-based offset for NVD pagination.

    Returns:
        Dict with keys: items (raw NVD list), total (int), error (bool).
    """
    try:
        resp = requests.get(
            NVD_CVE_URL,
            params={
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": _NVD_MAX_PAGE,
                "startIndex": start_index,
            },
            headers={"Accept": "application/json"},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "items": data.get("vulnerabilities", []),
            "total": data.get("totalResults", 0),
            "error": False,
        }
    except requests.RequestException as exc:
        logger.error("NVD page fetch failed (startIndex=%d): %s", start_index, exc)
        return {"items": [], "total": 0, "error": True}


# ── Session state helpers ─────────────────────────────────────────────────────

def _time_window(hours: int) -> tuple[str, str]:
    """Return (pub_start, pub_end) ISO strings (UTC) covering the last N hours.

    Args:
        hours: Number of hours back from now.

    Returns:
        Tuple of (pub_start, pub_end) formatted for the NVD API.
    """
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    now_utc = datetime.now(timezone.utc)
    start_utc = now_utc - timedelta(hours=hours)
    return start_utc.strftime(fmt), now_utc.strftime(fmt)


def _state_is_fresh() -> bool:
    """Return True if cached session state is within the cache TTL.

    Returns:
        True if the last fetch was less than _CACHE_TTL seconds ago.
    """
    fetched_at = st.session_state.get("cve_fetched_at", 0)
    return (time.time() - fetched_at) < _CACHE_TTL


def _fetch_all_for_window(hours: int) -> None:
    """Fetch all CVEs for a given hour window and store in session state.

    Args:
        hours: Number of hours back from now to use as the time window.
    """
    pub_start, pub_end = _time_window(hours)
    kev_data = _fetch_kev_data()

    all_items: list[dict] = []
    total = 0
    error = False
    start_index = 0

    while True:
        page = _fetch_nvd_page(pub_start, pub_end, start_index=start_index)
        if page["error"]:
            error = True
            break
        total = page["total"]
        all_items.extend(_parse_nvd_item(i, kev_data) for i in page["items"])
        start_index += len(page["items"])
        if start_index >= total or not page["items"]:
            break

    st.session_state["cve_items"] = all_items
    st.session_state["cve_total_nvd"] = total
    st.session_state["cve_pub_start"] = pub_start
    st.session_state["cve_pub_end"] = pub_end
    st.session_state["cve_error"] = error
    st.session_state["cve_hours"] = hours
    st.session_state["cve_fetched_at"] = time.time()


def _init_state() -> None:
    """Fetch all CVEs published in the last 3 hours and store in session state."""
    _fetch_all_for_window(hours=3)


def _reset_state() -> None:
    """Clear all CVE session state keys to force a fresh fetch on next render."""
    for key in ("cve_items", "cve_total_nvd", "cve_pub_start",
                "cve_pub_end", "cve_error", "cve_fetched_at", "cve_hours",
                "cve_selected_ids", "cve_copy_text"):
        st.session_state.pop(key, None)


# ── HTML builders ─────────────────────────────────────────────────────────────

def _severity_badge_html(score: float | None, severity: str) -> str:
    """Build an inline HTML severity badge.

    Args:
        score: CVSS base score or None.
        severity: Severity label string.

    Returns:
        HTML string for the badge.
    """
    fg, bg = _SEVERITY_STYLE.get(severity, _SEVERITY_STYLE["N/A"])
    score_label = f"{score:.1f}" if score is not None else "N/A"
    return (
        f'<span style="display:inline-flex;align-items:center;gap:5px;'
        f'background:{bg};border:1px solid {fg}33;border-radius:5px;'
        f'padding:2px 7px;font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;">'
        f'<span style="color:{fg};font-weight:700;">{severity}</span>'
        f'<span style="color:{fg};opacity:0.85;">{score_label}</span>'
        f'</span>'
    )


def _kev_badge_html() -> str:
    """Build a small KEV indicator badge.

    Returns:
        HTML string for the KEV badge.
    """
    return (
        '<span style="display:inline-flex;align-items:center;'
        'background:#1e3a5f;border:1px solid #3b82f633;border-radius:4px;'
        'padding:1px 5px;font-family:\'JetBrains Mono\',monospace;font-size:0.58rem;'
        'color:#60a5fa;font-weight:600;letter-spacing:0.03em;">KEV</span>'
    )


def _card_html(v: dict, common_app: bool = False) -> str:
    """Build HTML for a single CVE card.

    Args:
        v: Parsed CVE dict from _parse_nvd_item.
        common_app: If True, render with a red highlight border/background.

    Returns:
        HTML string for the card.
    """
    cve_id = v["cveID"]
    vendor = v["vendorProject"]
    product = v["product"]
    vendor_product = f"{vendor} · {product}" if vendor and product else vendor or product or "—"

    badge = _severity_badge_html(v["score"], v["severity"])
    kev_tag = f" {_kev_badge_html()}" if v["isKev"] else ""

    time_str = v.get("timePublished", "")
    date_label = f'{v["datePublished"]} {time_str} WIB' if time_str else v["datePublished"]

    if common_app:
        border = "rgba(239,68,68,0.45)"
        bg = "rgba(239,68,68,0.07)"
    else:
        border = "rgba(255,255,255,0.08)"
        bg = "rgba(255,255,255,0.02)"

    return (
        f'<div style="border:1px solid {border};border-radius:8px;'
        f'padding:10px 12px;margin-bottom:8px;background:{bg};">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">'
        f'<div style="display:flex;align-items:center;gap:6px;">'
        f'<a href="https://www.cve.org/CVERecord?id={cve_id}" target="_blank" '
        f'style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;'
        f'color:#60a5fa;font-weight:600;text-decoration:none;" '
        f'onmouseover="this.style.textDecoration=\'underline\'" '
        f'onmouseout="this.style.textDecoration=\'none\'">{cve_id}</a>'
        f'{kev_tag}'
        f'</div>'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;'
        f'color:#6b7280;white-space:nowrap;" title="Waktu ditambahkan ke NVD (WIB)">{date_label}</span>'
        f'</div>'
        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;'
        f'color:#e2e6f0;margin-top:4px;line-height:1.4;">{v["description"]}</div>'
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'margin-top:6px;gap:6px;">'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;'
        f'color:#9ca3af;">{vendor_product}</span>'
        f'{badge}'
        f'</div>'
        f'</div>'
    )


# ── Copy formatter ────────────────────────────────────────────────────────────

def _format_selected_text(selected: list[dict]) -> str:
    """Format selected CVE dicts into the copy-block text.

    Output per CVE:
        [CVE-ID](https://www.cve.org/CVERecord?id=CVE-ID)
        CVE Metrics: <score> (<severity>)
        Time published: <YYYY-MM-DD HH:MM WIB>
        Descriptions:
        <full description>

    Multiple CVEs are separated by a single blank line.

    Args:
        selected: List of parsed CVE dicts (from _parse_nvd_item).

    Returns:
        Formatted multi-line string ready for clipboard.
    """
    blocks: list[str] = []
    for v in selected:
        cve_id = v.get("cveID", "")
        url = CVE_RECORD_URL.format(cve_id=cve_id)
        score = v.get("score")
        severity = v.get("severity", "N/A")
        score_label = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"
        metrics_line = f"CVE Metrics: {score_label} ({severity})"

        date_pub = v.get("datePublished", "")
        time_pub = v.get("timePublished", "")
        published = f"{date_pub} {time_pub} WIB".strip() if time_pub else date_pub

        desc_full = v.get("descriptionFull") or v.get("description", "")

        blocks.append(
            f"[{cve_id}]({url})\n"
            f"{metrics_line}\n"
            f"Time published: {published}\n"
            f"Descriptions:\n"
            f"{desc_full}"
        )
    return "\n\n".join(blocks)


# ── Filter logic ──────────────────────────────────────────────────────────────

def _on_severity_change() -> None:
    """Enforce mutual exclusivity between ALL and individual severity filters.

    "Common" is treated as an independent boolean toggle — it is preserved
    across severity selection changes and never cleared by the ALL/severity logic.

    Rules:
    - If the user just selected ALL → keep ALL (+ Common if active).
    - If any individual severity is selected → remove ALL (+ keep Common).
    - If no severity remains selected → revert to ALL (+ keep Common).
    """
    selected: list[str] = list(st.session_state.get("cve_severity_pills") or [])
    prev: list[str] = list(st.session_state.get("cve_severity_pills_prev") or ["ALL"])

    newly_added = [s for s in selected if s not in prev]
    has_common_app = "Common" in selected
    has_select = "Select" in selected
    severity_sel = [s for s in selected if s not in ("Common", "Select")]

    if "ALL" in newly_added:
        new_severity = ["ALL"]
    elif any(s in _SEVERITY_FILTERS for s in severity_sel):
        new_severity = [s for s in severity_sel if s != "ALL"]
    else:
        new_severity = ["ALL"]

    independent = []
    if has_common_app:
        independent.append("Common")
    if has_select:
        independent.append("Select")
    new_selection = independent + new_severity
    st.session_state["cve_severity_pills"] = new_selection
    st.session_state["cve_severity_pills_prev"] = new_selection


# ── Main render ───────────────────────────────────────────────────────────────

def render_cve_panel() -> None:
    """Render the New CVE panel with lazy loading and severity filtering."""
    if "cve_items" not in st.session_state or not _state_is_fresh():
        with st.spinner("Loading CVEs…"):
            _init_state()

    error: bool = st.session_state.get("cve_error", False)
    items: list[dict] = st.session_state.get("cve_items", [])
    total_nvd: int = st.session_state.get("cve_total_nvd", 0)
    current_hours: int = st.session_state.get("cve_hours", 3)

    # ── Header ────────────────────────────────────────────────────────────────
    st.markdown(
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'margin-bottom:10px;">'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.88rem;'
        f'font-weight:700;color:#f5f7fb;letter-spacing:0.01em;">New CVE</span>'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.65rem;'
        f'color:#6b7280;">{total_nvd} total · NVD · last {current_hours}h</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if error:
        st.warning("Unable to reach NVD API. Check your connection.")
        return

    if not items and total_nvd == 0 and not error:
        st.markdown(
            '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;'
            'color:#6b7280;text-align:center;padding:32px 0;border:1px solid rgba(255,255,255,0.06);'
            'border-radius:10px;background:rgba(255,255,255,0.02);">'
            'No new CVEs published<br>since yesterday.'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    # ── Search bar ────────────────────────────────────────────────────────────
    st.markdown(
        """<style>
        div[data-testid="column"]:has(button[key="cve_search_btn"]) button {
            background-color: #e02020 !important;
            border-color: #e02020 !important;
            border-radius: 8px !important;
            color: #fff !important;
            font-size: 1.05rem !important;
            line-height: 1 !important;
            padding: 0 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            height: 38px !important;
            min-height: 38px !important;
            letter-spacing: 0 !important;
        }
        div[data-testid="column"]:has(button[key="cve_search_btn"]) button:hover {
            background-color: #b91c1c !important;
            border-color: #b91c1c !important;
        }
        div[data-testid="column"]:has(button[key="cve_search_btn"]) button p {
            font-size: 1.05rem !important;
            line-height: 1 !important;
            margin: 0 !important;
        }
        div[data-testid="stPills"] button {
            font-size: 0.6rem !important;
            padding: 2px 8px !important;
            min-height: 0 !important;
            height: auto !important;
            line-height: 1.4 !important;
        }
        div[data-testid="column"]:has(button[key="cve_search_btn"]) {
            padding-top: 0 !important;
        }
        div[data-testid="stTextInput"] {
            margin-bottom: -12px !important;
        }
        div[data-testid="stPills"] {
            margin-top: 4px !important;
        }
        </style>""",
        unsafe_allow_html=True,
    )
    col_search, col_btn = st.columns([5, 1])
    with col_search:
        search_input = st.text_input(
            label="CVE search",
            placeholder="Search by CVE ID, product, or attack type…",
            label_visibility="collapsed",
            key="cve_search_input",
        )
    with col_btn:
        search_clicked = st.button("▶", key="cve_search_btn", use_container_width=True)

    if search_clicked:
        st.session_state["cve_search_query"] = search_input.strip().lower()

    if "cve_search_query" not in st.session_state:
        st.session_state["cve_search_query"] = ""

    search_query: str = st.session_state["cve_search_query"]

    # ── Severity + Common filter ──────────────────────────────────────────────
    if "cve_severity_pills" not in st.session_state:
        st.session_state["cve_severity_pills"] = ["ALL"]
        st.session_state["cve_severity_pills_prev"] = ["ALL"]

    selected_filters: list[str] = st.pills(
        label="Severity filter",
        options=_FILTER_OPTIONS,
        selection_mode="multi",
        label_visibility="collapsed",
        key="cve_severity_pills",
        on_change=_on_severity_change,
    )

    active: set[str] = set(selected_filters) if selected_filters else {"ALL"}
    common_app_only: bool = "Common" in active
    select_mode: bool = "Select" in active
    active_severity = active - {"Common", "Select"}
    if not active_severity:
        active_severity = {"ALL"}

    filtered = items if "ALL" in active_severity else [v for v in items if v["severity"] in active_severity]

    if common_app_only:
        filtered = [v for v in filtered if _is_common_app(v)]

    if search_query:
        filtered = [
            v for v in filtered
            if search_query in v["cveID"].lower()
            or search_query in v.get("vendorProject", "").lower()
            or search_query in v.get("product", "").lower()
            or search_query in v.get("description", "").lower()
        ]

    # Sort newest-first
    filtered.sort(key=lambda v: v.get("publishedRaw", ""), reverse=True)

    # ── Selection state ──────────────────────────────────────────────────────
    if "cve_selected_ids" not in st.session_state:
        st.session_state["cve_selected_ids"] = set()
    selected_ids: set[str] = st.session_state["cve_selected_ids"]
    if not select_mode and selected_ids:
        # Hidden selections persist when toggling Select off then on again.
        pass

    # ── CVE cards (fixed-height scrollable) ──────────────────────────────────
    if filtered:
        if select_mode:
            with st.container(height=320, border=False):
                for v in filtered:
                    cve_id = v["cveID"]
                    col_chk, col_card = st.columns([1, 20])
                    with col_chk:
                        checked = st.checkbox(
                            label=f"Select {cve_id}",
                            value=cve_id in selected_ids,
                            key=f"cve_chk_{cve_id}",
                            label_visibility="collapsed",
                        )
                        if checked:
                            selected_ids.add(cve_id)
                        else:
                            selected_ids.discard(cve_id)
                    with col_card:
                        st.markdown(
                            _card_html(v, _is_common_app(v)),
                            unsafe_allow_html=True,
                        )
            st.session_state["cve_selected_ids"] = selected_ids
        else:
            st.markdown(
                '<div style="height:320px;overflow-y:auto;padding-right:4px;">'
                + "".join(_card_html(v, _is_common_app(v)) for v in filtered)
                + "</div>",
                unsafe_allow_html=True,
            )
    else:
        hint = " Try broadening your search or filter." if search_query else ""
        st.markdown(
            f'<div style="height:320px;display:flex;align-items:center;justify-content:center;'
            f'font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;color:#6b7280;'
            f'text-align:center;">'
            f'No CVEs match the current search or filter.{hint}'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── View more / Refresh / Copy ────────────────────────────────────────────
    st.markdown('<div style="margin-top:10px;"></div>', unsafe_allow_html=True)
    if select_mode:
        col_view, col_refresh, col_copy = st.columns([4, 1, 2])
    else:
        col_view, col_refresh, _col_spacer = st.columns([4, 1, 2])
    with col_view:
        if st.button("View more", key="cve_view_more", use_container_width=True):
            next_hours = current_hours + 3
            with st.spinner(f"Loading last {next_hours} hours…"):
                _fetch_all_for_window(hours=next_hours)
            st.rerun()
    with col_refresh:
        if st.button("↺", key="cve_refresh", use_container_width=True,
                     help="Reload newest CVEs from last 3 hours"):
            _reset_state()
            st.rerun()
    if select_mode:
        with col_copy:
            n_sel = len(selected_ids)
            ordered = [v for v in filtered if v["cveID"] in selected_ids]
            copy_text = _format_selected_text(ordered) if ordered else ""
            data_b64 = base64.b64encode(copy_text.encode("utf-8")).decode("ascii")
            disabled_attr = "disabled" if n_sel == 0 else ""
            disabled_style = (
                "background:rgba(255,255,255,0.04);color:#4b5563;cursor:not-allowed;"
                if n_sel == 0
                else "background:rgba(255,255,255,0.04);color:#e2e6f0;cursor:pointer;"
            )
            components.html(
                f"""
                <style>
                  html, body {{ margin:0; padding:0; }}
                  .cve-copy-btn {{
                    width:100%;
                    height:38px;
                    border:1px solid rgba(255,255,255,0.15);
                    border-radius:8px;
                    font-family:'JetBrains Mono', monospace;
                    font-size:0.85rem;
                    font-weight:500;
                    {disabled_style}
                    transition: background 0.15s;
                  }}
                  .cve-copy-btn:not([disabled]):hover {{
                    background: rgba(255,255,255,0.08) !important;
                  }}
                </style>
                <button class="cve-copy-btn" id="cve_copy_btn" {disabled_attr}>Copy</button>
                <script>
                  (function() {{
                    const btn = document.getElementById("cve_copy_btn");
                    const data = "{data_b64}";
                    if (!btn || btn.disabled) return;
                    btn.addEventListener("click", () => {{
                      const text = atob(data);
                      navigator.clipboard.writeText(text).then(() => {{
                        btn.textContent = "Copied!";
                        setTimeout(() => {{ btn.textContent = "Copy"; }}, 1500);
                      }}).catch(() => {{
                        btn.textContent = "Copy failed";
                        setTimeout(() => {{ btn.textContent = "Copy"; }}, 1500);
                      }});
                    }});
                  }})();
                </script>
                """,
                height=42,
            )

    info = f"last {current_hours}h loaded"
    if select_mode:
        info += f" · {len(selected_ids)} selected"
    st.markdown(
        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;'
        f'color:#6b7280;margin-top:6px;">{info}</div>',
        unsafe_allow_html=True,
    )
