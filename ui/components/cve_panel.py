"""Recent CVE panel using NVD API v2 with lazy loading (10 per page).

Rendering and session state only. Fetching and record parsing live in
`providers.nvd`, and their Streamlit caching in `core.cache` — the same split
every other provider follows, which is what lets `app.py` look a CVE up during
enrichment without importing anything from the UI layer.
"""
from __future__ import annotations

import base64
import html
import logging
import re
import time
from urllib.parse import quote_plus

import streamlit as st
import streamlit.components.v1 as components

from core.cache import (
    CACHE_REV,
    CVE_FEED_TTL,
    kev_catalog_cached,
    mitre_records_cached,
    nvd_page_cached,
)
from providers.nvd import is_common_app, parse_nvd_item, time_window

logger = logging.getLogger(__name__)

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
CWE_DEFINITION_URL = "https://cwe.mitre.org/data/definitions/{code}.html"
GOOGLE_SEARCH_URL = "https://www.google.com/search?q={query}"


# ── Session state helpers ─────────────────────────────────────────────────────

def _state_is_fresh() -> bool:
    """Return True if cached session state is within the cache TTL.

    Returns:
        True if the last fetch was less than CVE_FEED_TTL seconds ago.
    """
    fetched_at = st.session_state.get("cve_fetched_at", 0)
    return (time.time() - fetched_at) < CVE_FEED_TTL


def _fetch_all_for_window(hours: int) -> None:
    """Fetch all CVEs for a given hour window and store in session state.

    Args:
        hours: Number of hours back from now to use as the time window.
    """
    pub_start, pub_end = time_window(hours)
    kev_data = kev_catalog_cached(CACHE_REV)

    raw_items: list[dict] = []
    total = 0
    error = False
    start_index = 0

    while True:
        page = nvd_page_cached(pub_start, pub_end, start_index, CACHE_REV)
        if page["error"]:
            error = True
            break
        total = page["total"]
        raw_items.extend(page["items"])
        start_index += len(page["items"])
        if start_index >= total or not page["items"]:
            break

    # MITRE cveawg enrichment per CVE (vendor/product/version/CAPEC), fetched
    # concurrently and cached per record so a reload within TTL skips the HTTP.
    cve_ids = [i.get("cve", {}).get("id", "") for i in raw_items]
    mitre_map = mitre_records_cached(cve_ids)

    all_items = [
        parse_nvd_item(item, kev_data, mitre_map.get(item.get("cve", {}).get("id", ""), {}))
        for item in raw_items
    ]

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


def _ransomware_badge_html() -> str:
    """Build a small RANSOMWARE indicator badge.

    Returns:
        HTML string for the RANSOMWARE badge.
    """
    return (
        '<span style="display:inline-flex;align-items:center;'
        'background:#3a0a0a;border:1px solid #ef444466;border-radius:4px;'
        'padding:1px 5px;font-family:\'JetBrains Mono\',monospace;font-size:0.58rem;'
        'color:#fca5a5;font-weight:600;letter-spacing:0.03em;">RANSOMWARE</span>'
    )


def _card_html(v: dict, common_app: bool = False) -> str:
    """Build HTML for a single CVE card.

    Layout (top → bottom):
        1. Header row    — CVE-ID + badges (KEV, RANSOMWARE) · date WIB
        2. Attack line   — "Attack: <pattern> · CWE-<N>" (only if present)
        3. Description   — KEV shortDescription if available, else NVD
        4. Required action — KEV requiredAction (only if present)
        5. Footer row    — vendor · product · version · severity badge

    Args:
        v: Parsed CVE dict from parse_nvd_item.
        common_app: If True, render with a red highlight border/background.

    Returns:
        HTML string for the card.
    """
    cve_id = v["cveID"]
    vendor = v["vendorProject"]
    product = v["product"]
    version_range = v.get("versionRange", "")

    parts = [p for p in (vendor, product, version_range) if p]
    vendor_product_text = " · ".join(parts) if parts else "—"

    # Only hyperlink to Google search when BOTH vendor and product were resolved
    # (either via MITRE affected[] or the regex fallback). Skip otherwise — a
    # search for just a vendor is too noisy to be useful.
    if vendor and product:
        gquery = quote_plus(f"{vendor} {product}")
        gurl = GOOGLE_SEARCH_URL.format(query=gquery)
        vendor_product_html = (
            f'<a href="{gurl}" target="_blank" '
            f'style="color:#9ca3af;text-decoration:none;'
            f'border-bottom:1px dashed rgba(156,163,175,0.4);" '
            f'onmouseover="this.style.borderBottomStyle=\'solid\'" '
            f'onmouseout="this.style.borderBottomStyle=\'dashed\'" '
            f'title="Search Google for {vendor} {product}">'
            f'{vendor_product_text}</a>'
        )
    else:
        vendor_product_html = vendor_product_text

    badge = _severity_badge_html(v["score"], v["severity"])
    kev_tag = f" {_kev_badge_html()}" if v["isKev"] else ""
    ransomware_tag = (
        f" {_ransomware_badge_html()}" if v.get("isRansomware") else ""
    )

    time_str = v.get("timePublished", "")
    date_label = f'{v["datePublished"]} {time_str} WIB' if time_str else v["datePublished"]

    # Attack line — CAPEC attack pattern from MITRE + CWE from NVD.
    # CWE label is hyperlinked to cwe.mitre.org definition page.
    attack_bits: list[str] = []
    attack_pattern = v.get("attackPattern", "")
    if attack_pattern:
        attack_bits.append(attack_pattern)
    cwe_id = v.get("cwe", "")
    if cwe_id:
        cwe_num = re.sub(r"^CWE-", "", cwe_id, flags=re.IGNORECASE)
        cwe_href = CWE_DEFINITION_URL.format(code=cwe_num)
        cwe_html = (
            f'<a href="{cwe_href}" target="_blank" '
            f'style="color:#a78bfa;text-decoration:none;'
            f'border-bottom:1px dashed rgba(167,139,250,0.4);" '
            f'onmouseover="this.style.borderBottomStyle=\'solid\'" '
            f'onmouseout="this.style.borderBottomStyle=\'dashed\'">{cwe_id}</a>'
        )
        attack_bits.append(cwe_html)
    attack_line = ""
    if attack_bits:
        attack_text = " · ".join(attack_bits)
        # Plain-text tooltip — strip the <a> wrapper so the HTML attribute is clean.
        tooltip_bits = [b for b in (attack_pattern, cwe_id) if b]
        tooltip = " · ".join(tooltip_bits).replace('"', "&quot;")
        # 2-line clamp keeps the card height tidy and consistent across cards.
        attack_line = (
            f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.8rem;'
            f'color:#a78bfa;margin-top:10px;line-height:1.45;letter-spacing:0.02em;'
            f'display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;'
            f'overflow:hidden;" title="{tooltip}">'
            f'<span style="color:#6b7280;">Attack:</span> {attack_text}'
            f'</div>'
        )

    # Required action line — from CISA KEV when available.
    # Same whitespace-collapse treatment as description (see comment below).
    required_action = v.get("requiredAction", "")
    action_line = ""
    if required_action:
        _clean_action = re.sub(r"\s+", " ", required_action).strip()
        action_line = (
            f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.8rem;'
            f'color:#fbbf24;margin-top:10px;line-height:1.5;'
            f'display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;'
            f'overflow:hidden;" title="{html.escape(_clean_action, quote=True)}">'
            f'<span style="color:#6b7280;">Required action:</span> {html.escape(_clean_action)}'
            f'</div>'
        )

    if common_app:
        border = "rgba(239,68,68,0.45)"
        bg = "rgba(239,68,68,0.07)"
    else:
        border = "rgba(255,255,255,0.08)"
        bg = "rgba(255,255,255,0.02)"

    # Normalize whitespace in description to a single line before escaping:
    #   • Raw \n inside the title="…" attribute breaks Streamlit's markdown
    #     pass-through (\n\n splits the HTML into separate paragraph blocks,
    #     leaking the rest of the card markup as literal text).
    #   • Leading 4-space indentation in CVE descriptions (common in Linux
    #     kernel patch text) triggers markdown's indented-code-block rule,
    #     producing a giant scrollable <pre> box inside the card.
    # Collapsing whitespace solves both — text still wraps naturally via the
    # CSS word-break/line-clamp on the container.
    _clean_desc = re.sub(r"\s+", " ", v["description"]).strip()
    desc_safe = html.escape(_clean_desc)
    desc_tooltip = html.escape(_clean_desc, quote=True)

    return (
        f'<div style="border:1px solid {border};border-radius:8px;'
        f'padding:16px 16px 14px 16px;margin-bottom:12px;background:{bg};">'
        # Header row
        f'<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">'
        f'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">'
        f'<a href="https://www.cve.org/CVERecord?id={cve_id}" target="_blank" '
        f'style="font-family:\'JetBrains Mono\',monospace;font-size:0.95rem;'
        f'color:#60a5fa;font-weight:600;text-decoration:none;" '
        f'onmouseover="this.style.textDecoration=\'underline\'" '
        f'onmouseout="this.style.textDecoration=\'none\'">{cve_id}</a>'
        f'{kev_tag}{ransomware_tag}'
        f'</div>'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.8rem;'
        f'color:#6b7280;white-space:nowrap;" title="Waktu ditambahkan ke NVD (WIB)">{date_label}</span>'
        f'</div>'
        # Attack pattern (above description)
        f'{attack_line}'
        # Description — full text, visually clamped to 6 lines with CSS overflow.
        # Hover tooltip shows the complete text.
        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.88rem;'
        f'color:#e2e6f0;margin-top:10px;line-height:1.55;'
        f'display:-webkit-box;-webkit-line-clamp:6;-webkit-box-orient:vertical;'
        f'overflow:hidden;white-space:normal;word-break:break-word;" '
        f'title="{desc_tooltip}">{desc_safe}</div>'
        # Required action (below description)
        f'{action_line}'
        # Footer row — vendor/product/version + severity badge
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'margin-top:12px;gap:6px;">'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.82rem;'
        f'color:#9ca3af;">{vendor_product_html}</span>'
        f'{badge}'
        f'</div>'
        f'</div>'
    )


# ── Copy formatter ────────────────────────────────────────────────────────────

def _format_selected_text(selected: list[dict]) -> str:
    """Format selected CVE dicts as plain text for WhatsApp messages.

    WhatsApp bold uses single asterisks (`*text*`). WhatsApp does not support
    markdown-style anchor links — arbitrary anchor text cannot be clickable.
    Only raw URLs are auto-linked.

    Output per CVE (Opsi B layout). Fields without data render as "-":

        *CVE-ID* ⚠️ KEV · RANSOMWARE          (badges only shown if applicable)

        *Severity*: <score> (<sev>) · <CWE> · <attack pattern>
        *Affected*: <vendor> · <product> · <version>
        *Time published*: <YYYY-MM-DD HH:MM WIB>

        *Description*:
        <full description>

        *Required Action*:
        <CISA KEV requiredAction>

        *Reference*: https://www.cve.org/CVERecord?id=CVE-ID

    Multiple CVEs are separated by a blank line.

    Args:
        selected: List of parsed CVE dicts (from parse_nvd_item).

    Returns:
        Formatted multi-line plain-text string ready for clipboard.
    """
    blocks: list[str] = []
    for v in selected:
        cve_id = v.get("cveID", "")
        url = CVE_RECORD_URL.format(cve_id=cve_id)

        # Header — inline KEV / RANSOMWARE tags only when applicable
        tags: list[str] = []
        if v.get("isKev"):
            tags.append("KEV")
        if v.get("isRansomware"):
            tags.append("RANSOMWARE")
        tag_suffix = f" ⚠️ {' · '.join(tags)}" if tags else ""

        # Severity line: score (sev) · CWE · attack pattern
        score = v.get("score")
        severity = v.get("severity", "N/A")
        if isinstance(score, (int, float)):
            severity_label = f"{score:.1f} ({severity})"
        else:
            severity_label = "-"
        sev_parts = [severity_label]
        cwe = (v.get("cwe") or "").strip()
        if cwe:
            sev_parts.append(cwe)
        attack = (v.get("attackPattern") or "").strip()
        if attack:
            sev_parts.append(attack)
        severity_line = " · ".join(sev_parts) if sev_parts else "-"

        # Affected: vendor · product · version
        vendor = (v.get("vendorProject") or "").strip()
        product = (v.get("product") or "").strip()
        version = (v.get("versionRange") or "").strip()
        affected_parts = [p for p in (vendor, product, version) if p]
        affected = " · ".join(affected_parts) if affected_parts else "-"

        # Time published
        date_pub = v.get("datePublished", "")
        time_pub = v.get("timePublished", "")
        if date_pub and time_pub:
            published = f"{date_pub} {time_pub} WIB"
        elif date_pub:
            published = date_pub
        else:
            published = "-"

        # Description — already prefers KEV shortDescription over NVD in parser
        desc_full = (v.get("descriptionFull") or v.get("description") or "").strip()
        if not desc_full:
            desc_full = "-"

        # Required action — from CISA KEV. Skip the whole block when absent so
        # the message isn't padded with bare "-" placeholders.
        action = (v.get("requiredAction") or "").strip()
        action_block = f"\n\n*Required Action*:\n{action}" if action else ""

        blocks.append(
            f"*{cve_id}*{tag_suffix}\n"
            f"\n"
            f"*Severity*: {severity_line}\n"
            f"*Affected*: {affected}\n"
            f"*Time published*: {published}\n"
            f"\n"
            f"*Description*:\n"
            f"{desc_full}"
            f"{action_block}"
            f"\n\n*Reference*: {url}"
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

    # Mobile-only top spacer so the "New CVE" header sits below the fixed app header.
    st.markdown(
        '<style>'
        '.cve-mobile-topspacer { height: 0; }'
        '@media (max-width: 768px) {'
        '  .cve-mobile-topspacer { height: 80px; }'
        '}'
        '</style>'
        '<div class="cve-mobile-topspacer"></div>',
        unsafe_allow_html=True,
    )

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
        filtered = [v for v in filtered if is_common_app(v)]

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
                            _card_html(v, is_common_app(v)),
                            unsafe_allow_html=True,
                        )
            st.session_state["cve_selected_ids"] = selected_ids
        else:
            st.markdown(
                '<div style="height:320px;overflow-y:auto;padding-right:4px;">'
                + "".join(_card_html(v, is_common_app(v)) for v in filtered)
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
                      // atob() returns a binary string (one char per byte) so
                      // multi-byte UTF-8 like "·" arrives as garbled "Â·".
                      // Re-decode the byte sequence as UTF-8 before copying.
                      const binary = atob(data);
                      const bytes = new Uint8Array(binary.length);
                      for (let i = 0; i < binary.length; i++) {{
                        bytes[i] = binary.charCodeAt(i);
                      }}
                      const text = new TextDecoder("utf-8").decode(bytes);
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
