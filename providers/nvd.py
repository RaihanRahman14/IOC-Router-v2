"""NVD / CISA KEV / MITRE cveawg client — CVE lookup and record parsing.

The data half of the CVE feature. Everything here is plain HTTP plus parsing:
no Streamlit, no caching, no session state. That split is what lets `app.py`
enrich a WAF fingerprint match with a CVE record without importing from the UI
layer, and lets the parsing be tested without stubbing Streamlit.

Caching lives in `core.cache` alongside every other provider's wrappers; the
Streamlit rendering lives in `ui.components.cve_panel`.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

import requests

from config import Settings
from core.http import get_session, run_parallel

logger = logging.getLogger(__name__)

_WIB = timezone(timedelta(hours=7))  # UTC+7 Jakarta / WIB

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MITRE_CVE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"

_NVD_MAX_PAGE = 2000  # NVD API hard limit per request
# MITRE enrichment is one small request per CVE and a window can hold hundreds,
# so this fans out wider than the default provider-level limit.
MITRE_PARALLEL_WORKERS = 12

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _nvd_headers(settings: Settings | None) -> dict[str, str]:
    """Build NVD request headers, adding the API key when one is configured.

    Args:
        settings: Settings carrying ``cve_nvd_key``. Read from the environment
            when omitted.

    Returns:
        Header dict for an NVD request.
    """
    headers = {"Accept": "application/json"}
    api_key = ((settings or Settings.from_env()).cve_nvd_key or "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers



# ── Common-application keyword tables ────────────────────────────────

# Keywords checked case-insensitively across vendor + product + description.
_COMMON_APP_KEYWORDS: list[str] = [
    "cisco", "fortinet", "palo alto", "paloalto", "vmware", "dell",
    "huawei", "microsoft edge", "microsoft authenticator", "microsoft",
    "google chrome", "chrome", "firefox", "zoom", "slack",
    "whatsapp desktop", "telegram desktop", "notion", "google drive",
    "bitwarden", "lastpass",
    "aruba", "atmos agent", "beyondtrust", "bitdefender",
    "check point", "checkpoint", "cyberark", "cyber ark",
    "device42", "hillstone", "hsm nshield", "nshield",
    "imperva", "nagios", "riverbed", "ruckus", "sangfor",
    "seciron", "sentinelone", "sentinel one", "tenable",
    "trend micro", "trendmicro", "veeam", "wordpress", "word press",
    "xfusion",
]
# Short/ambiguous tokens — matched against vendor+product only to avoid false positives
# (e.g. "padding oracle" in crypto CVEs, "runs on Linux", "azure" as a color).
_COMMON_APP_VENDOR_ONLY: list[str] = [
    "hp", "edge", "ibm",
    "aws", "azure", "f5", "linux", "oracle", "php", "mysql",
]

# Keyword → human-readable display label.
# _match_common_keyword sorts longest-first so "microsoft edge" wins over "microsoft",
# "microsoft authenticator" wins over "microsoft", "google chrome" wins over "chrome", etc.
_COMMON_KEYWORD_LABEL: dict[str, str] = {
    "microsoft authenticator": "Microsoft Authenticator",
    "microsoft edge":          "Microsoft Edge",
    "whatsapp desktop":        "WhatsApp Desktop",
    "telegram desktop":        "Telegram Desktop",
    "hsm nshield":             "HSM nShield Connect",
    "sentinel one":            "SentinelOne",
    "google chrome":           "Google Chrome",
    "google drive":            "Google Drive",
    "palo alto":               "Palo Alto Networks",
    "paloalto":                "Palo Alto Networks",
    "check point":             "Check Point",
    "checkpoint":              "Check Point",
    "cyber ark":               "CyberArk",
    "cyberark":                "CyberArk",
    "atmos agent":             "Atmos Agent",
    "trend micro":             "Trend Micro",
    "trendmicro":              "Trend Micro",
    "word press":              "WordPress",
    "wordpress":               "WordPress",
    "sentinelone":             "SentinelOne",
    "beyondtrust":             "BeyondTrust",
    "bitdefender":             "Bitdefender",
    "device42":                "Device42",
    "hillstone":               "Hillstone",
    "nshield":                 "HSM nShield Connect",
    "imperva":                 "Imperva",
    "riverbed":                "Riverbed",
    "sangfor":                 "Sangfor",
    "seciron":                 "SecIron",
    "tenable":                 "Tenable",
    "xfusion":                 "XFusion",
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
    "aruba":                   "Aruba",
    "nagios":                  "Nagios",
    "ruckus":                  "Ruckus",
    "veeam":                   "Veeam",
    "hp":                      "HP",
    "edge":                    "Microsoft Edge",
    "aws":                     "AWS",
    "azure":                   "Azure",
    "f5":                      "F5",
    "linux":                   "Linux",
    "oracle":                  "Oracle",
    "php":                     "PHP",
    "mysql":                   "MySQL",
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


# ── Parsing helpers ─────────────────────────────────────────────

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


def is_common_app(v: dict) -> bool:
    """Return True if the CVE involves a well-known application from the common app list.

    Args:
        v: Parsed CVE dict from parse_nvd_item.

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


def _extract_cwe(weaknesses: list) -> str:
    """Extract the first CWE-N identifier from an NVD weaknesses list.

    Args:
        weaknesses: The weaknesses list from an NVD CVE item.

    Returns:
        A CWE id like "CWE-346", or empty string if none found.
    """
    for w in weaknesses:
        for d in w.get("description", []):
            value = (d.get("value") or "").strip()
            if value.startswith("CWE-"):
                return value
    return ""


def _extract_mitre_vendor_product(mitre_data: dict) -> tuple[str, str, str]:
    """Extract vendor, product, and affected version range from a MITRE cveawg record.

    Args:
        mitre_data: Parsed JSON from cveawg.mitre.org/api/cve/{id}.

    Returns:
        Tuple of (vendor, product, version_range). Each is empty when unavailable
        or marked as "n/a" by the CNA.
    """
    cna = mitre_data.get("containers", {}).get("cna", {})
    affected = cna.get("affected", [])
    if not affected:
        return "", "", ""

    first = affected[0]
    vendor = (first.get("vendor") or "").strip()
    product = (first.get("product") or "").strip()
    if vendor.lower() in ("n/a", "na", ""):
        vendor = ""
    if product.lower() in ("n/a", "na", ""):
        product = ""

    version_range = ""
    for v in first.get("versions", []):
        if v.get("status") != "affected":
            continue
        less_than = (v.get("lessThan") or "").strip()
        less_than_or_eq = (v.get("lessThanOrEqual") or "").strip()
        version = (v.get("version") or "").strip()
        if less_than:
            version_range = f"< {less_than}"
        elif less_than_or_eq:
            version_range = f"<= {less_than_or_eq}"
        elif version and version.lower() not in ("n/a", "na", "*"):
            version_range = version
        if version_range:
            break

    return vendor, product, version_range


_CAPEC_MAX_LABEL_LEN = 80


def _extract_mitre_capec(mitre_data: dict) -> str:
    """Extract a concise attack pattern label from a MITRE cveawg record.

    The MITRE schema's `impacts[].descriptions[].value` is intended to hold a
    short CAPEC name (e.g. "DNS Rebinding") but some CNAs misuse it to store a
    multi-sentence impact narrative. To keep the card readable we only accept
    descriptions shorter than _CAPEC_MAX_LABEL_LEN and otherwise fall back to
    the bare CAPEC id.

    Args:
        mitre_data: Parsed JSON from cveawg.mitre.org/api/cve/{id}.

    Returns:
        A short attack pattern label (e.g. "DNS Rebinding (CAPEC-275)" or
        "CAPEC-275"), or "" when nothing concise is available.
    """
    cna = mitre_data.get("containers", {}).get("cna", {})
    for impact in cna.get("impacts", []):
        capec_id = (impact.get("capecId") or "").strip()

        short_desc = ""
        for d in impact.get("descriptions", []):
            value = (d.get("value") or "").strip()
            if not value:
                continue
            # Strip "CAPEC-N: " prefix so we don't double-print the id.
            cleaned = re.sub(r"^CAPEC-\d+\s*[:\-]\s*", "", value, flags=re.IGNORECASE)
            if len(cleaned) <= _CAPEC_MAX_LABEL_LEN:
                short_desc = cleaned
                break

        if short_desc and capec_id:
            return f"{short_desc} ({capec_id})"
        if short_desc:
            return short_desc
        if capec_id:
            return capec_id
    return ""


def parse_nvd_item(
    item: dict,
    kev_data: dict[str, dict],
    mitre_data: dict,
) -> dict:
    """Parse a single NVD vulnerability item into a display-ready dict.

    Vendor/product resolution order (per user spec):
      1. MITRE cveawg `affected[]` (vendor + product + version range)
      2. Description regex / common-keyword fallback

    Description resolution order:
      1. CISA KEV `shortDescription` (already SOC-friendly and concise)
      2. NVD English description (full text — visual clamp via CSS in card)

    Args:
        item: A single entry from NVD vulnerabilities list.
        kev_data: Dict mapping CVE ID to expanded KEV record (vendorProject,
            product, shortDescription, requiredAction, knownRansomwareCampaignUse,
            vulnerabilityName).
        mitre_data: Parsed JSON from cveawg.mitre.org for this CVE, or {} if
            the call failed / record is absent.

    Returns:
        Dict with display fields for a CVE card.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    nvd_desc_full = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    score, severity = _extract_cvss(cve.get("metrics", {}))
    cwe_id = _extract_cwe(cve.get("weaknesses", []))

    vendor, product, version_range = _extract_mitre_vendor_product(mitre_data)
    attack_pattern = _extract_mitre_capec(mitre_data)

    if not vendor and not product:
        # Fallback to regex / common-keyword match against NVD description
        vendor = _product_from_desc(nvd_desc_full)
        if not vendor:
            vendor = _match_common_keyword(nvd_desc_full)

    kev_entry = kev_data.get(cve_id, {})

    # Description: KEV shortDescription preferred when available, else full NVD.
    # No char truncation — the card uses CSS -webkit-line-clamp for visual
    # overflow, so the ellipsis only appears when the text actually exceeds
    # the visible line count rather than at an arbitrary mid-sentence cutoff.
    kev_short = (kev_entry.get("shortDescription") or "").strip()
    desc = kev_short if kev_short else nvd_desc_full

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

    is_ransomware = (
        kev_entry.get("knownRansomwareCampaignUse", "").lower() == "known"
    )

    return {
        "cveID": cve_id,
        "vendorProject": vendor,
        "product": product,
        "versionRange": version_range,
        "description": desc,
        "descriptionFull": desc,
        "datePublished": date_published,
        "timePublished": time_published,
        "publishedRaw": pub_raw,
        "score": score,
        "severity": severity,
        "cwe": cwe_id,
        "attackPattern": attack_pattern,
        "requiredAction": (kev_entry.get("requiredAction") or "").strip(),
        "isKev": bool(kev_entry),
        "isRansomware": is_ransomware,
    }


# ── API fetchers ──────────────────────────────────────────────────────────────

def time_window(hours: int) -> tuple[str, str]:
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


def fetch_kev_catalog() -> dict[str, dict]:
    """Fetch the CISA KEV catalog, keyed by CVE ID with expanded metadata.

    Returns:
        Dict mapping CVE ID to a dict with vendorProject, product,
        vulnerabilityName, shortDescription, requiredAction, and
        knownRansomwareCampaignUse fields. Empty on failure.
    """
    try:
        resp = get_session().get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        return {
            v.get("cveID", ""): {
                "vendorProject": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "vulnerabilityName": v.get("vulnerabilityName", ""),
                "shortDescription": v.get("shortDescription", ""),
                "requiredAction": v.get("requiredAction", ""),
                "knownRansomwareCampaignUse": v.get(
                    "knownRansomwareCampaignUse", "Unknown"
                ),
            }
            for v in resp.json().get("vulnerabilities", [])
        }
    except (requests.RequestException, ValueError) as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return {}


def fetch_mitre_cve(cve_id: str) -> dict:
    """Fetch a single CVE record from cveawg.mitre.org.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2026-11624").

    Returns:
        Parsed JSON dict, or {} on any non-200 response / network failure.
    """
    if not cve_id:
        return {}
    try:
        resp = get_session().get(
            MITRE_CVE_URL.format(cve_id=cve_id),
            headers={"Accept": "application/json"},
            timeout=20,
        )
        if resp.status_code != 200:
            return {}
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("MITRE fetch failed for %s: %s", cve_id, exc)
        return {}


def fetch_mitre_records(cve_ids, fetch=fetch_mitre_cve) -> dict[str, dict]:
    """Fetch MITRE records for many CVEs concurrently.

    Args:
        cve_ids: CVE identifiers to enrich. Duplicates and blanks are dropped.
        fetch: Per-id fetcher. Injectable so the caller can pass a cached
            variant — `core.cache` does exactly that, which is what keeps a
            page reload from re-fetching every record.

    Returns:
        Mapping of CVE ID to its MITRE record; ids whose fetch failed are absent.
    """
    wanted = [cve_id for cve_id in dict.fromkeys(cve_ids) if cve_id]
    if not wanted:
        return {}
    return run_parallel(
        {cve_id: (lambda c=cve_id: fetch(c)) for cve_id in wanted},
        max_workers=MITRE_PARALLEL_WORKERS,
        label="MITRE CVE fetch",
    )


def fetch_nvd_page(
    pub_start: str,
    pub_end: str,
    start_index: int,
    settings: Settings | None = None,
) -> dict:
    """Fetch one page of CVEs from NVD API v2 (up to _NVD_MAX_PAGE results).

    Args:
        pub_start: ISO-8601 start datetime string (UTC).
        pub_end: ISO-8601 end datetime string (UTC).
        start_index: Zero-based offset for NVD pagination.
        settings: Settings carrying ``cve_nvd_key``; read from env when omitted.

    Returns:
        Dict with keys: items (raw NVD list), total (int), error (bool).
    """
    try:
        resp = get_session().get(
            NVD_CVE_URL,
            params={
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": _NVD_MAX_PAGE,
                "startIndex": start_index,
            },
            headers=_nvd_headers(settings),
            timeout=45,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "items": data.get("vulnerabilities", []),
            "total": data.get("totalResults", 0),
            "error": False,
        }
    except (requests.RequestException, ValueError) as exc:
        logger.error("NVD page fetch failed (startIndex=%d): %s", start_index, exc)
        return {"items": [], "total": 0, "error": True}


def fetch_cve_by_id(
    cve_id: str,
    kev_catalog: dict[str, dict] | None = None,
    settings: Settings | None = None,
) -> dict | None:
    """Look up one CVE by identifier, with its CISA KEV status.

    Added for the WAF payload module's Layer 4 (``docs/waf_payload_analyzer.md``
    D4). Everything else in the CVE feature fetches by **publication-date
    window** — the newest few hours of CVEs. Every CVE a curated fingerprint can
    match is years old by definition, so none of them would ever appear there;
    hence this narrow by-id path.

    **Failure is not fatal to a verdict.** A fingerprint match is a local,
    offline result; this call only decorates it. Returning None must leave the
    caller reporting "not retrieved", never "not known-exploited".

    Args:
        cve_id: A CVE identifier, e.g. ``"CVE-2021-44228"``.
        kev_catalog: Pre-fetched KEV catalog. Fetched on demand when omitted —
            callers holding a cached copy should pass it, since the catalog is
            a single large download shared by every lookup.
        settings: Settings carrying ``cve_nvd_key``; read from env when omitted.

    Returns:
        A display-ready CVE dict as produced by :func:`parse_nvd_item`, or None
        when the identifier is malformed, unknown, or the lookup failed.
    """
    identifier = (cve_id or "").strip().upper()
    if not CVE_ID_RE.fullmatch(identifier):
        logger.warning("refusing malformed CVE id: %r", cve_id)
        return None

    try:
        resp = get_session().get(
            NVD_CVE_URL,
            params={"cveId": identifier},
            headers=_nvd_headers(settings),
            timeout=20,
        )
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
    except (requests.RequestException, ValueError) as exc:
        logger.error("NVD lookup for %s failed: %s", identifier, exc)
        return None

    if not items:
        return None

    catalog = fetch_kev_catalog() if kev_catalog is None else kev_catalog
    try:
        return parse_nvd_item(items[0], catalog, {})
    except (KeyError, TypeError, ValueError) as exc:
        logger.error("NVD response for %s could not be parsed: %s", identifier, exc)
        return None
