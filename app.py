"""IOC Router - Streamlit app entrypoint (3-tab layout)."""
from __future__ import annotations

import time

import streamlit as st
import streamlit.components.v1 as components

from config import Settings
from ioc.parser import IOC, parse_iocs
from ioc.verdict import summarize_results
from core.cache import (
    vt_cached, urlscan_cached, abuse_cached, tf_cached,
    mb_cached, shodan_cached, dnsd_cached, ha_cached, mxtoolbox_cached,
    whoxy_cached, ransomware_live_cached,
    CACHE_REV,
)
from ui.styles import build_global_css_and_header, LANDING_CSS
from ui.components.drawer import render_api_drawer
from ui.components.output_renderer import render_results_output, render_session_hero
from ui.components.ioc_card import render_ioc_cards
from ui.components.ai_panel import render_ai_panel
from ui.components.cve_panel import render_cve_panel
from ui.components.bug_report import render_bug_report_button
from ui.components.note_popup import render_note_button
from ui.components.timing_popup import render_timing_button
from ui.components.tab_switcher import render_tab_switch_buttons
from ui.components.path_probe_panel import render_path_probe_panel

st.set_page_config(
    page_title="IOC Router",
    page_icon="IOC",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Pre-header state init: the header HTML embeds tab buttons whose active
# state depends on st.session_state["active_tab"], so it MUST be resolved
# before we build the header markup. The same applies to a pending tab
# switch queued by the enrichment run (writes session_state directly here
# are safe because no widget with that key has been instantiated yet).
if "active_tab" not in st.session_state:
    st.session_state["active_tab"] = "Input"
_pending_tab = st.session_state.pop("_pending_tab_switch", None)
if _pending_tab in ("Input", "Result", "CVE"):
    st.session_state["active_tab"] = _pending_tab

st.markdown(
    build_global_css_and_header(st.session_state["active_tab"]),
    unsafe_allow_html=True,
)

render_bug_report_button()
render_note_button()
render_timing_button()
render_tab_switch_buttons()

# JavaScript drawer + header-button controller — runs in a zero-height iframe so it
# actually executes (React blocks <script> injected via innerHTML).
# Uses window.parent to reach the Streamlit app's real document.
components.html(
    """
    <script>
    (function() {
        var pw  = window.parent;
        var pd  = pw.document;

        // Persist state on the parent window object so reruns don't reset it
        if (pw._drawerInited) return;   // already bootstrapped — skip duplicate runs
        pw._drawerInited  = true;
        pw._drawerOpen    = (pw.sessionStorage.getItem('drawerOpen') === '1');

        pw._applyDrawer = function(open) {
            var sb = pd.querySelector('section[data-testid="stSidebar"]');
            var bd = pd.getElementById('drawer-backdrop');
            var burger = pd.getElementById('drawer-burger-btn');
            if (!sb) return;
            sb.style.setProperty('transform', open ? 'translateX(0)' : 'translateX(-300px)', 'important');
            sb.style.setProperty('visibility', 'visible', 'important');
            if (bd) bd.style.display = open ? 'block' : 'none';
            if (burger) {
                if (open) burger.classList.add('open');
                else burger.classList.remove('open');
            }
            pw._drawerOpen = open;
            pw.sessionStorage.setItem('drawerOpen', open ? '1' : '0');
        };

        function attachBurger() {
            var btn = pd.getElementById('drawer-burger-btn');
            if (btn && !btn._burgerReady) {
                btn._burgerReady = true;
                btn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    pw._applyDrawer(!pw._drawerOpen);
                });
            }
        }

        function attachBackdrop() {
            var bd = pd.getElementById('drawer-backdrop');
            if (bd && !bd._backdropReady) {
                bd._backdropReady = true;
                bd.addEventListener('click', function() {
                    pw._applyDrawer(false);
                });
            }
        }

        function clickHiddenButton(labelText) {
            var stBtns = pd.querySelectorAll('[data-testid="stButton"] button');
            stBtns.forEach(function(b) {
                if (b.textContent.trim() === labelText) {
                    b.click();
                }
            });
        }

        function attachHeaderButtons() {
            var rb = pd.getElementById('report-bug-header-btn');
            if (rb && !rb._rbReady) {
                rb._rbReady = true;
                rb.addEventListener('click', function(e) {
                    e.stopPropagation();
                    clickHiddenButton('Report Bug 🐞');
                });
            }
            var nb = pd.getElementById('note-header-btn');
            if (nb && !nb._noteReady) {
                nb._noteReady = true;
                nb.addEventListener('click', function(e) {
                    e.stopPropagation();
                    clickHiddenButton('Notes ⓘ');
                });
            }
            var tm = pd.getElementById('timing-header-btn');
            if (tm && !tm._timingReady) {
                tm._timingReady = true;
                tm.addEventListener('click', function(e) {
                    e.stopPropagation();
                    clickHiddenButton('Timing ⏱');
                });
            }
            // Header tab buttons (Input / Result / CVE) → forward to hidden
            // Streamlit buttons identified by their st-key-* wrapper class.
            // Targeting the key class is more reliable than text matching
            // (which can break on emoji whitespace / DOM wrapping).
            ['Input', 'Result', 'CVE'].forEach(function(tabName) {
                var tb = pd.getElementById('tab-btn-' + tabName);
                if (tb && !tb._tabReady) {
                    tb._tabReady = true;
                    tb.addEventListener('click', function(e) {
                        e.stopPropagation();
                        var hidden = pd.querySelector(
                            '.st-key-tab_switch_btn_' + tabName + ' button'
                        );
                        if (hidden) hidden.click();
                    });
                }
            });
            // Hide the Report Bug + Notes Streamlit trigger buttons (replaced by header HTML).
            // The Switch-to-* buttons are hidden via CSS (.st-key-tab_switch_btn_*).
            var HIDE_LABELS = ['Report Bug 🐞', 'Notes ⓘ', 'Timing ⏱'];
            pd.querySelectorAll('[data-testid="stButton"] button').forEach(function(b) {
                var t = b.textContent.trim();
                if (HIDE_LABELS.indexOf(t) !== -1) {
                    var wrapper = b.closest('[data-testid="stButton"]');
                    if (wrapper && wrapper.parentElement) {
                        wrapper.parentElement.style.setProperty('display', 'none', 'important');
                    }
                }
            });
        }

        function init(tries) {
            var sb = pd.querySelector('section[data-testid="stSidebar"]');
            if (sb) {
                pw._applyDrawer(pw._drawerOpen);
                attachBurger();
                attachBackdrop();
                attachHeaderButtons();
            } else if (tries < 50) {
                setTimeout(function() { init(tries + 1); }, 100);
            }
        }
        init(0);

        // Re-attach after every Streamlit DOM update
        var _t = null;
        new MutationObserver(function() {
            clearTimeout(_t);
            _t = setTimeout(function() {
                attachBurger();
                attachBackdrop();
                attachHeaderButtons();
                var sb = pd.querySelector('section[data-testid="stSidebar"]');
                if (sb) {
                    var want = pw._drawerOpen ? 'translateX(0px)' : 'translateX(-300px)';
                    if (sb.style.transform !== want) pw._applyDrawer(pw._drawerOpen);
                }
                pd.querySelectorAll('section[data-testid="stSidebar"] input[type="password"]')
                  .forEach(function(el) {
                    if (!el._noCopy) {
                        el._noCopy = true;
                        el.addEventListener('copy', function(e) { e.preventDefault(); });
                        el.addEventListener('cut',  function(e) { e.preventDefault(); });
                    }
                });
            }, 200);
        }).observe(pd.body, { childList: true, subtree: true });
    })();
    </script>
    """,
    height=0,
)

settings = Settings.from_env()

# ── API-key drawer: session state init ───────────────────────────────────────
for _k in ["sk_gemini", "sk_grok", "sk_vt", "sk_urlscan", "sk_abuse",
           "sk_threatfox", "sk_mb", "sk_shodan", "sk_dnsd", "sk_ha", "sk_mxtoolbox", "sk_whoxy",
           "sk_ransomware_live"]:
    if _k not in st.session_state:
        st.session_state[_k] = ""

for _k, _v in {
    "ioc_grp_ip": False, "ioc_grp_domain": False, "ioc_grp_hash": False,
    "ioc_grp_email": False, "ioc_grp_keyword": False,
    "auto_detect_and_provider": True,
    "analysis_mode": "Triage",
    "triage_speed": "Detailed",
    "active_tab": "Input",
}.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


def _sk(key: str) -> str | None:
    """Return a non-empty stripped session-state API key, or None."""
    v = str(st.session_state.get(key) or "").strip()
    return v if v else None


# Session-state keys override .env values when non-empty
settings.vt_key = _sk("sk_vt") or settings.vt_key
settings.urlscan_key = _sk("sk_urlscan") or settings.urlscan_key
settings.abuse_key = _sk("sk_abuse") or settings.abuse_key
settings.threatfox_key = _sk("sk_threatfox") or settings.threatfox_key
settings.malwarebazaar_key = _sk("sk_mb") or settings.malwarebazaar_key
settings.shodan_key = _sk("sk_shodan") or settings.shodan_key
settings.dnsdumpster_key = _sk("sk_dnsd") or settings.dnsdumpster_key
settings.hybrid_analysis_key = _sk("sk_ha") or settings.hybrid_analysis_key
settings.mxtoolbox_key = _sk("sk_mxtoolbox") or settings.mxtoolbox_key
settings.whoxy_key = _sk("sk_whoxy") or settings.whoxy_key
settings.ransomware_live_key = _sk("sk_ransomware_live") or settings.ransomware_live_key
settings.gemini_key = _sk("sk_gemini") or settings.gemini_key
settings.groq_key = _sk("sk_grok") or settings.groq_key

if "run_results" not in st.session_state:
    st.session_state["run_results"] = None
if "auto_generate_ai" not in st.session_state:
    st.session_state["auto_generate_ai"] = False


def _clear_ai_outputs() -> None:
    """Clear all AI-generated session state outputs."""
    st.session_state["ai_desc"] = ""
    st.session_state["ai_threat_analysis"] = ""
    st.session_state["ai_ioc_links"] = ""


def _clear_all_outputs() -> None:
    """Clear all run results and AI outputs from session state."""
    st.session_state["run_results"] = None
    _clear_ai_outputs()


# Input-tab context keys that the user fills in PRE-Run. On a successful Run
# these values are snapshotted into ``result_<key>`` so the Result tab gets
# its own editable copy (edits in Result do NOT propagate back to Input).
_INPUT_CONTEXT_KEYS: tuple[str, ...] = (
    "output_format", "alert_name", "host", "host_ip", "time_detected",
    "device_action", "device_action_others", "critical_asset_sel",
    "file_path", "parent_process", "child_process", "raw_log",
)


def _snapshot_input_context_to_result() -> None:
    """Copy each Input-tab context value into its ``result_``-prefixed twin.

    Called from the enrichment block on a successful Run so the Result tab's
    AI context expander shows what the user actually ran with — and any
    subsequent edits there stay isolated from the Input tab.
    """
    for _k in _INPUT_CONTEXT_KEYS:
        if _k in st.session_state:
            st.session_state[f"result_{_k}"] = st.session_state[_k]


render_api_drawer()

if not settings.vt_key:
    st.warning("VirusTotal API key belum di-set. Set env var: VT_KEY")

# ── Variable defaults (overridden by widgets below) ───────────────────────────
output_format: str = st.session_state.get("output_format", "Ticket notes")
auto_generate_on_run: bool = st.session_state.get("auto_generate_on_run", False)
auto_detect_and_provider: bool = st.session_state.get("auto_detect_and_provider", True)
auto_detect: bool = auto_detect_and_provider
auto_choose_provider: bool = auto_detect_and_provider
critical_asset: bool = st.session_state.get("critical_asset_sel", "Non Critical Asset") == "Critical Asset"
allow_urlscan_submit: bool = True
run: bool = False
raw: str = st.session_state.get("ioc_input", "")
raw_log: str = st.session_state.get("raw_log", "")
alert_name: str = st.session_state.get("alert_name", "")
host: str = st.session_state.get("host", "")
host_ip: str = st.session_state.get("host_ip", "")
time_detected: str = st.session_state.get("time_detected", "")
device_action: str = st.session_state.get("device_action", "")
device_action_others: str = st.session_state.get("device_action_others", "")
parent_process: str = st.session_state.get("parent_process", "")
child_process: str = st.session_state.get("child_process", "")
file_path: str = st.session_state.get("file_path", "")

# ── Handle pending resets before rendering ────────────────────────────────────
if st.session_state.get("reset_input"):
    st.session_state["ioc_input"] = ""
    st.session_state["raw_log"] = ""
    st.session_state["device_action"] = ""
    st.session_state["device_action_others"] = ""
    st.session_state["parent_process"] = ""
    st.session_state["child_process"] = ""
    st.session_state["file_path"] = ""
    st.session_state["reset_input"] = False
    raw = ""
    raw_log = ""
    device_action = ""
    device_action_others = ""
    parent_process = ""
    child_process = ""
    file_path = ""

if st.session_state.get("load_sample"):
    st.session_state["ioc_input"] = "8.8.8.8\nexample.com\nhttps://example.com/login\n44d88612fea8a8f36de82e1278abb02f"
    st.session_state["load_sample"] = False
    raw = st.session_state["ioc_input"]

# ── Provider groups — constants & helpers ────────────────────────────────────
_PROVIDER_LABELS: dict[str, str] = {
    "vt":              "VirusTotal",
    "urlscan":         "URLScan",
    "abuse":           "AbuseIPDB",
    "tf":              "ThreatFox",
    "mb":              "MalwareBazaar",
    "shodan":          "Shodan",
    "dns":             "DNSDumpster",
    "ha":              "Hybrid Analysis",
    "mxtoolbox":       "MxToolBox",
    "whoxy":           "WhoXY (unavailable)",
    "ransomware_live": "Ransomware Live",
}
_PROVIDER_DISABLED: set[str] = {"whoxy"}
_GROUP_PROVIDERS_FULL: dict[str, list[str]] = {
    "ip":         ["vt", "abuse", "tf", "shodan", "ha", "mxtoolbox"],
    "domain_url": ["vt", "urlscan", "abuse", "tf", "shodan", "dns", "ha", "mxtoolbox"],
    "hash":       ["vt", "tf", "mb", "ha"],
    "email":      ["mxtoolbox"],
    "keyword":    ["whoxy", "ransomware_live"],
}
_GROUP_PROVIDERS_LOOKUP: dict[str, list[str]] = {
    "ip":         ["vt", "abuse", "mxtoolbox"],
    "domain_url": ["shodan", "mxtoolbox"],
    "email":      ["mxtoolbox"],
}


def _get_group_providers(mode: str) -> dict[str, list[str]]:
    """Return the IOC-group -> provider mapping for the given analysis mode.

    Args:
        mode: ``"Triage"``, ``"Lookup"``, or ``"Path Probe"``.

    Returns:
        Mapping of IOC group key to list of provider keys appropriate for the
        mode. ``"Path Probe"`` returns an empty mapping — that mode has its
        own scanner and does not use the IOC provider pipeline.
    """
    if mode == "Path Probe":
        return {}
    if mode == "Lookup":
        return _GROUP_PROVIDERS_LOOKUP
    # Triage: exclude MxToolBox and the entire Keyword group; drop empty groups
    triage_map = {
        g: [p for p in ps if p != "mxtoolbox"]
        for g, ps in _GROUP_PROVIDERS_FULL.items()
        if g != "keyword"
    }
    return {g: ps for g, ps in triage_map.items() if ps}


_GROUP_PROVIDERS: dict[str, list[str]] = _GROUP_PROVIDERS_FULL
_GROUP_IOC_KEY: dict[str, str] = {
    "ip":         "ioc_grp_ip",
    "domain_url": "ioc_grp_domain",
    "hash":       "ioc_grp_hash",
    "email":      "ioc_grp_email",
    "keyword":    "ioc_grp_keyword",
}
_GROUP_LABEL: dict[str, str] = {
    "ip":         "IP",
    "domain_url": "Domain / URL",
    "hash":       "Hash",
    "email":      "Email",
    "keyword":    "Keyword",
}
_PROVIDER_TO_GROUPS: dict[str, list[str]] = {}
for _g, _ps in _GROUP_PROVIDERS.items():
    for _p in _ps:
        _PROVIDER_TO_GROUPS.setdefault(_p, []).append(_g)

_IOC_TYPE_TO_GROUP: dict[str, str] = {
    "ip":     "ip",
    "domain": "domain_url",
    "url":    "domain_url",
    "hash":   "hash",
    "email":  "email",
    "whois":  "keyword",
}


def _on_provider_toggle(p: str, group: str) -> None:
    """Each group's provider checkbox is independent — no cross-group sync."""


def _on_ioc_group_toggle(group: str) -> None:
    """Enable all providers in a group when the IOC type header is checked."""
    mode = st.session_state.get("analysis_mode", "Triage")
    group_providers = _get_group_providers(mode)
    if st.session_state.get(_GROUP_IOC_KEY[group], True):
        for p in group_providers.get(group, []):
            if p not in _PROVIDER_DISABLED:
                st.session_state[f"prov_{p}_{group}"] = True


def _render_providers_expander(expanded: bool = True, mode: str = "Triage") -> None:
    """Render grouped Providers expander with per-IOC-type sections.

    Args:
        expanded: Whether the expander is expanded by default.
        mode: Analysis mode, "Triage" or "Lookup". Controls which IOC groups
            and providers are shown.
    """
    group_providers = _get_group_providers(mode)
    for p, groups in _PROVIDER_TO_GROUPS.items():
        for g in groups:
            gkey = f"prov_{p}_{g}"
            if gkey not in st.session_state:
                st.session_state[gkey] = False

    for ioc_key in _GROUP_IOC_KEY.values():
        if ioc_key not in st.session_state:
            st.session_state[ioc_key] = False

    expander_title = "🔍 Lookup & Providers" if mode == "Lookup" else "🔍 IOC & Providers"
    with st.expander(expander_title, expanded=expanded):
        for i, (group, providers) in enumerate(group_providers.items()):
            st.checkbox(
                _GROUP_LABEL[group],
                key=_GROUP_IOC_KEY[group],
                on_change=_on_ioc_group_toggle,
                args=(group,),
            )
            _gap, _pcol = st.columns([0.05, 0.95])
            with _pcol:
                _cols = st.columns(3)
                ioc_active = st.session_state.get(_GROUP_IOC_KEY[group], False)
                for j, p in enumerate(providers):
                    with _cols[j % 3]:
                        st.checkbox(
                            _PROVIDER_LABELS[p],
                            key=f"prov_{p}_{group}",
                            disabled=p in _PROVIDER_DISABLED or not ioc_active,
                            on_change=_on_provider_toggle,
                            args=(p, group),
                        )
            if i < len(group_providers) - 1:
                st.divider()


def _render_context_expander(
    key_suffix: str,
    include_ai_settings: bool = False,
    key_prefix: str = "",
) -> None:
    """Render the Context expander (Output format + alert metadata + raw log).

    Widget ``key`` is built as ``f"{key_prefix}{field_name}"``. Pass
    ``key_prefix=""`` (default) for the Input tab — those widgets own the
    canonical keys (``output_format``, ``alert_name``, ...). Pass
    ``key_prefix="result_"`` for the Result tab so its widgets bind to a
    separate ``result_*`` namespace; edits there stay isolated and do NOT
    propagate back to the Input tab. The two namespaces are linked one-way:
    on a successful Run, :func:`_snapshot_input_context_to_result` copies
    Input values into the ``result_*`` keys.

    Args:
        key_suffix: Suffix appended to button keys (Clear / Load Sample) to
            keep them unique across tabs (``"input"`` vs ``"result"``).
        include_ai_settings: When True, appends an "AI settings" section and
            renames the expander to "AI context" (Result tab only).
        key_prefix: Prefix prepended to every stateful widget key. Use
            ``"result_"`` for Result tab.
    """
    global output_format, alert_name, host, host_ip, time_detected
    global device_action, device_action_others, critical_asset
    global file_path, parent_process, child_process, raw_log
    _title = "🗂️ AI context" if include_ai_settings else "🗂️ Context"
    _kp = key_prefix
    with st.expander(_title):
        output_format = st.selectbox(
            "Output format", ["Ticket notes", "Table", "JSON", "Shareable Text"], index=0, key=f"{_kp}output_format"
        )

        _opt = st.columns(2)
        with _opt[0]:
            alert_name = st.text_input(
                "Alert Name", placeholder="e.g. Suspicious Outbound", key=f"{_kp}alert_name"
            )
            host_ip = st.text_input("Host IP", placeholder="192.168.x.x", key=f"{_kp}host_ip")
        with _opt[1]:
            host = st.text_input("Host", placeholder="hostname", key=f"{_kp}host")
            time_detected = st.text_input(
                "Time Detected", placeholder="2025-01-01 08:00:00", key=f"{_kp}time_detected"
            )

        _proc = st.columns([2, 1])
        with _proc[0]:
            device_action = st.selectbox(
                "Device Action",
                ["None", "Blocked", "Isolated", "Prevented", "Allowed", "Detected", "File Cleaned", "Others"],
                key=f"{_kp}device_action",
            )
        with _proc[1]:
            _asset_sel = st.selectbox(
                "Asset Criticality",
                ["Non Critical Asset", "Critical Asset"],
                index=0, key=f"{_kp}critical_asset_sel",
            )
            critical_asset = _asset_sel == "Critical Asset"
        if device_action == "Others":
            device_action_others = st.text_input(
                "Specify Action",
                placeholder="e.g. Terminated, Logged, Alerted...",
                key=f"{_kp}device_action_others",
            )

        file_path = st.text_input(
            "File Path", placeholder="e.g. C:\\Users\\user\\Downloads\\malware.exe", key=f"{_kp}file_path"
        )
        parent_process = st.text_input(
            "Parent Process", placeholder="e.g. explorer.exe", key=f"{_kp}parent_process"
        )
        child_process = st.text_input(
            "Child Process", placeholder="e.g. cmd.exe", key=f"{_kp}child_process"
        )

        raw_log = st.text_area(
            "Context (optional)",
            placeholder="Paste raw log or describe context here for additional AI context...",
            height=80,
            key=f"{_kp}raw_log",
        )

        # AI settings — only rendered in Result tab (where AI Description lives).
        # Lazy import keeps the Input tab free of the providers.gemini import path.
        if include_ai_settings:
            st.divider()
            st.markdown("**AI settings**")
            if not settings.gemini_key:
                st.info("Gemini API key not set. Set the env var: GEMINI_KEY")
            _ai_col1, _ai_col2 = st.columns(2)
            with _ai_col1:
                st.selectbox("AI Provider", ["Gemini", "Groq"], key="ai_provider")
            with _ai_col2:
                st.selectbox(
                    "Tone",
                    ["High level language", "SOC L1 concise", "More formal"],
                    key="ai_tone",
                )
            _c1, _c2 = st.columns(2)
            with _c1:
                st.checkbox("Use only evidence shown (no guessing)", key="ai_use_only_evidence")
            with _c2:
                st.checkbox("Sanitize sensitive data", key="ai_sanitize")
            if st.session_state.get("ai_provider") == "Gemini":
                from providers.gemini import gemini_list_models  # local import — only needed here
                if st.button("Fetch Gemini Models", key=f"fetch_gemini_models_{key_suffix}"):
                    _models, _err = gemini_list_models(settings)
                    st.session_state["gemini_models"] = _models
                    st.session_state["gemini_models_err"] = _err
                if st.session_state.get("gemini_models_err"):
                    st.error(st.session_state["gemini_models_err"])
                _gm_list = st.session_state.get("gemini_models", [])
                if _gm_list:
                    _default_model = settings.gemini_model or "gemini-2.5-flash"
                    _default_index = _gm_list.index(_default_model) if _default_model in _gm_list else 0
                    st.selectbox(
                        "Gemini Model (from list)", _gm_list,
                        index=_default_index, key="gemini_model_select",
                    )
                    settings.gemini_model = st.session_state.get("gemini_model_select") or settings.gemini_model
                settings.gemini_api_version = "v1"
            st.divider()

        _act = st.columns(2)
        with _act[0]:
            if st.button("🗑️ Clear", use_container_width=True, key=f"clear_{key_suffix}"):
                _clear_all_outputs()
                st.session_state["reset_input"] = True
                st.rerun()
        with _act[1]:
            if st.button("📋 Load Sample IOCs", use_container_width=True, key=f"load_sample_{key_suffix}"):
                st.session_state["load_sample"] = True
                st.rerun()


# ── Tab bar ───────────────────────────────────────────────────────────────────
# The tab bar is rendered in the fixed header (see build_global_css_and_header).
# active_tab was already resolved at the top of this script (before the header
# was built) — we just read it back here.
active_tab: str = st.session_state["active_tab"]

# ══════════════════════════════════════════════════════════════════════════════
# Tab 1 — INPUT (center column from landing, no Note column, no CVE column)
# ══════════════════════════════════════════════════════════════════════════════
if active_tab == "Input":
    st.markdown(LANDING_CSS, unsafe_allow_html=True)

    # Center the input column with reasonable max width (no side columns now)
    _l, _center_col, _r = st.columns([0.5, 3.0, 0.5], gap="large")

    _input_mode = st.session_state.get("analysis_mode", "Triage")

    if _input_mode == "Path Probe":
        with _center_col:
            # Mirror Mode popover — the in-card popover (where mode lives in
            # IOC view) isn't rendered here, so we expose an identical one
            # at the top of Path Probe so the user can switch back.
            _pp_mode_opts = ("Triage", "Lookup", "Path Probe")
            _pp_idx = _pp_mode_opts.index(_input_mode)
            _pp_a, _pp_b = st.columns([1.5, 4])
            with _pp_a:
                with st.popover(f"{_input_mode} ▾", use_container_width=True):
                    st.radio(
                        "Mode",
                        _pp_mode_opts,
                        index=_pp_idx,
                        key="analysis_mode",
                        label_visibility="collapsed",
                    )
            render_path_probe_panel()
    else:
        with _center_col:
            # Hint pills
            st.markdown('<div class="ioc-hint-row">', unsafe_allow_html=True)
            _hp = st.columns(5)
            _hints = [
                ("IP Address", "8.8.8.8"),
                ("Domain", "evil.example.com"),
                ("URL", "https://phish.example.com/login"),
                ("MD5 Hash", "44d88612fea8a8f36de82e1278abb02f"),
                ("Email", "user@suspicious.io"),
            ]
            for _i, (_label, _val) in enumerate(_hints):
                with _hp[_i]:
                    if st.button(_label, key=f"hint_{_i}", use_container_width=True):
                        _cur = st.session_state.get("ioc_input", "")
                        st.session_state["ioc_input"] = (_cur + "\n" + _val).strip() if _cur else _val
                        st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("<div style='height:6px'/>", unsafe_allow_html=True)

            # Chat card
            with st.container(border=True):
                raw = st.text_area(
                    "IOC",
                    placeholder="Enter IOCs — IP, domain, URL, hash, or email (one per line)...",
                    height=110,
                    key="ioc_input",
                    label_visibility="collapsed",
                )
                # Toolbar row inside card
                _current_mode = st.session_state.get("analysis_mode", "Triage")
                _auto_on = st.session_state.get("auto_detect_and_provider", True)
                _show_speed = _current_mode == "Triage" and _auto_on
                if _show_speed:
                    _tc_mode, _tc_speed, _tc1, _tc2, _tc_run = st.columns(
                        [0.95, 0.85, 1.5, 1.15, 0.5]
                    )
                else:
                    _tc_mode, _tc1, _tc2, _tc_run = st.columns([0.95, 1.8, 1.15, 0.5])
                _auto_label = (
                    "Auto detect Lookup & Provider"
                    if _current_mode == "Lookup"
                    else "Auto detect IOC & Provider"
                )
                _mode_opts_inline = ("Triage", "Lookup", "Path Probe")
                _mode_idx_inline = (
                    _mode_opts_inline.index(_current_mode)
                    if _current_mode in _mode_opts_inline
                    else 0
                )
                with _tc_mode:
                    with st.popover(f"{_current_mode} ▾", use_container_width=True):
                        st.radio(
                            "Mode",
                            _mode_opts_inline,
                            index=_mode_idx_inline,
                            key="analysis_mode",
                            label_visibility="collapsed",
                        )
                with _tc1:
                    st.checkbox(_auto_label, key="auto_detect_and_provider")
                if _show_speed:
                    with _tc_speed:
                        _current_speed = st.session_state.get("triage_speed", "Detailed")
                        with st.popover(f"{_current_speed} ▾", use_container_width=True):
                            st.radio(
                                "Triage speed",
                                ["Fast", "Detailed"],
                                index=0 if _current_speed == "Fast" else 1,
                                key="triage_speed",
                                label_visibility="collapsed",
                            )
                with _tc2:
                    auto_generate_on_run = st.checkbox("Auto AI Description", value=False, key="auto_generate_on_run")
                with _tc_run:
                    run = st.button("▶", type="primary", key="run_btn_chat", use_container_width=True)

            # Auto AI Description settings dropdown — shown below the input card
            if auto_generate_on_run:
                with st.expander("🤖 AI Description", expanded=True):
                    _ai_col1, _ai_col2 = st.columns(2)
                    with _ai_col1:
                        st.selectbox("AI Provider", ["Gemini", "Groq"], index=0, key="auto_ai_desc_provider")
                    with _ai_col2:
                        st.selectbox("Tone", ["High level language", "SOC L1 concise", "More formal"], index=0, key="auto_ai_tone")
                    _chk1, _chk2 = st.columns(2)
                    with _chk1:
                        st.checkbox("Use only evidence shown (no guessing)", value=True, key="auto_ai_use_only_evidence")
                    with _chk2:
                        st.checkbox("Sanitize sensitive data", value=True, key="auto_ai_sanitize")

            # Providers section — shown when Auto detect & Provider is off
            if not st.session_state.get("auto_detect_and_provider", True):
                _render_providers_expander(
                    expanded=True,
                    mode=st.session_state.get("analysis_mode", "Triage"),
                )

            # Context expander
            _render_context_expander(key_suffix="input")

            st.markdown(
                '<p style="text-align:center;font-family:\'JetBrains Mono\',monospace;'
                'font-size:0.72rem;color:#6b7280;margin-top:10px;line-height:1.8;">'
                'Enter one or more IOCs above, then press '
                '<strong style="color:#e2e6f0;">▶ Run</strong> to start the analysis.'
                '<br>Official Documentation: '
                '<a href="https://github.com/minzelo/IOC-Router-v2" target="_blank" '
                'style="color:#6b7280;text-decoration:underline;">github.com/minzelo/IOC-Router-v2</a>'
                "</p>",
                unsafe_allow_html=True,
            )

# ══════════════════════════════════════════════════════════════════════════════
# Tab 3 — CVE (full-width CVE feed)
# ══════════════════════════════════════════════════════════════════════════════
elif active_tab == "CVE":
    render_cve_panel()

# ══════════════════════════════════════════════════════════════════════════════
# Tab 2 — RESULT (left = TA + Timing + AI Output + Context; right = Results)
# ══════════════════════════════════════════════════════════════════════════════
else:  # active_tab == "Result"
    components.html(
        """
        <script>
        (function() {
            function tagMainSplit() {
                var blocks = window.parent.document.querySelectorAll('[data-testid="stHorizontalBlock"]');
                // Skip the radio's internal block — find the next horizontal block
                for (var i = 0; i < blocks.length; i++) {
                    if (!blocks[i].closest('[data-testid="stRadio"]')) {
                        blocks[i].classList.add('ioc-main-split');
                        break;
                    }
                }
            }
            if (document.readyState === 'complete') { tagMainSplit(); }
            else { window.addEventListener('load', tagMainSplit); }
            setTimeout(tagMainSplit, 300);
        })();
        </script>
        """,
        height=0,
    )

    # Full-width session hero (Score panel + verdict counts) — rendered above
    # the split so it spans both the TA/AI Output column and the Results column.
    if st.session_state.get("run_results"):
        render_session_hero(st.session_state["run_results"]["summary"])

    split_left, split_right = st.columns([1, 1], gap="small")

# ── IOC change detection (always run so verdicts stay aligned with input) ────
_allowed_ioc_types: set[str] | None = None
if not auto_detect:
    _allowed_ioc_types = set()
    if st.session_state.get("ioc_grp_ip", True):
        _allowed_ioc_types.add("ip")
    if st.session_state.get("ioc_grp_domain", True):
        _allowed_ioc_types.update({"domain", "url"})
    if st.session_state.get("ioc_grp_hash", True):
        _allowed_ioc_types.add("hash")
    if st.session_state.get("ioc_grp_email", True):
        _allowed_ioc_types.add("email")
    if st.session_state.get("ioc_grp_keyword", True):
        _allowed_ioc_types.add("whois")
parsed_input_items = parse_iocs(raw, auto_detect=auto_detect, allowed_types=_allowed_ioc_types) if raw.strip() else []
current_ioc_signature = tuple((ioc.value, ioc.type) for ioc in parsed_input_items)
previous_ioc_signature = st.session_state.get("ioc_signature_last")
ioc_changed = previous_ioc_signature is not None and previous_ioc_signature != current_ioc_signature
# Only clear results when the user is in the Input tab — that's the only
# place the IOC list can actually be edited. Restricting the clear here
# prevents the Result tab's context edits (which trigger a rerun but never
# touch ``ioc_input``) from spuriously wiping ``run_results``.
if ioc_changed and active_tab == "Input":
    _clear_all_outputs()
st.session_state["ioc_signature_last"] = current_ioc_signature

# ── Action handlers ───────────────────────────────────────────────────────────
# Clear / Load Sample are handled inline inside _render_context_expander —
# they call st.rerun() directly on click, no module-level handler needed here.

auto_run_enrichment = bool(st.session_state.get("auto_run_enrichment"))
if auto_run_enrichment:
    st.session_state["auto_run_enrichment"] = False

run_requested = run or auto_run_enrichment

if run_requested:
    st.session_state["auto_generate_ai"] = bool(auto_generate_on_run)
    if auto_generate_on_run:
        _raw_prov = st.session_state.get("auto_ai_desc_provider") or st.session_state.get("auto_ai_provider", "Gemini")
        auto_ai_provider = "Groq" if _raw_prov == "Groq" else "Gemini"
        st.session_state["ai_provider"] = auto_ai_provider


# Triage "Fast" mode — minimal provider set per IOC type for quick verdicts.
_FAST_PROVIDERS_BY_TYPE: dict[str, set[str]] = {
    "ip":     {"vt", "abuse"},
    "domain": {"vt", "urlscan", "shodan"},
    "url":    {"vt", "urlscan", "shodan"},
    "hash":   {"vt", "ha"},
}


def _manual_payload_for_provider(
    provider: str, items: list[IOC]
) -> list[tuple[str, str]]:
    """Return only the IOC tuples whose IOC group has this provider enabled."""
    return [
        (ioc.value, ioc.type)
        for ioc in items
        if st.session_state.get(
            f"prov_{provider}_{_IOC_TYPE_TO_GROUP.get(ioc.type, '')}",
            False,
        )
    ]


_PROVIDER_KEYS: tuple[str, ...] = (
    "vt", "urlscan", "abuse", "tf", "mb", "shodan",
    "dns", "ha", "mxtoolbox", "whoxy", "ransomware_live",
)


def _has_key_map(settings_obj: Settings) -> dict[str, bool]:
    """Return mapping of provider key to whether its API key is configured."""
    return {
        "vt":              bool(settings_obj.vt_key),
        "urlscan":         bool(settings_obj.urlscan_key),
        "abuse":           bool(settings_obj.abuse_key),
        "tf":              bool(settings_obj.threatfox_key),
        "mb":              bool(settings_obj.malwarebazaar_key),
        "shodan":          bool(settings_obj.shodan_key),
        "dns":             bool(settings_obj.dnsdumpster_key),
        "ha":              bool(settings_obj.hybrid_analysis_key),
        "mxtoolbox":       bool(settings_obj.mxtoolbox_key),
        "whoxy":           bool(settings_obj.whoxy_key),
        "ransomware_live": bool(settings_obj.ransomware_live_key),
    }


def _auto_allowed_by_type(
    items: list[IOC],
    settings_obj: Settings,
    mode: str,
    fast: bool,
) -> dict[str, set[str]]:
    """Per-IOC-type set of providers allowed under auto-detect for this mode.

    Args:
        items: Parsed IOC list.
        settings_obj: Settings carrying API keys.
        mode: "Triage" or "Lookup".
        fast: True if Triage Fast — additionally restricts per type.

    Returns:
        Mapping ioc_type -> set of provider keys that should run for that type,
        already gated on API-key availability and Fast-mode restrictions.
    """
    group_map = _get_group_providers(mode)
    has_key = _has_key_map(settings_obj)
    out: dict[str, set[str]] = {}
    for ioc in items:
        if ioc.type in out:
            continue
        group = _IOC_TYPE_TO_GROUP.get(ioc.type, "")
        base = set(group_map.get(group, []))
        if fast:
            base &= _FAST_PROVIDERS_BY_TYPE.get(ioc.type, set())
        out[ioc.type] = {p for p in base if has_key.get(p, False)}
    return out


def _manual_allowed_by_type(items: list[IOC]) -> dict[str, set[str]]:
    """Per-IOC-type set of providers checklisted by the user (manual mode)."""
    out: dict[str, set[str]] = {}
    for ioc in items:
        if ioc.type in out:
            continue
        group = _IOC_TYPE_TO_GROUP.get(ioc.type, "")
        out[ioc.type] = {
            p for p in _PROVIDER_KEYS
            if st.session_state.get(f"prov_{p}_{group}", False)
        }
    return out


# ── Enrichment execution (triggered from Input tab Run button) ───────────────
if run_requested and raw.strip():
    items = parsed_input_items
    if not items:
        st.info("Tidak ada IOC valid setelah parsing.")
    else:
        if auto_choose_provider:
            _current_mode = st.session_state.get("analysis_mode", "Triage")
            _is_triage_fast = (
                _current_mode == "Triage"
                and st.session_state.get("triage_speed", "Detailed") == "Fast"
            )
            allowed_by_type = _auto_allowed_by_type(
                items, settings, mode=_current_mode, fast=_is_triage_fast,
            )
        else:
            allowed_by_type = _manual_allowed_by_type(items)

        def _payload(p: str) -> list[tuple[str, str]]:
            return [
                (ioc.value, ioc.type)
                for ioc in items
                if p in allowed_by_type.get(ioc.type, set())
            ]

        provider_flags = {p: bool(_payload(p)) for p in _PROVIDER_KEYS}

        _provider_timings: dict[str, dict] = {}

        def _timed(key: str, enabled: bool, call_fn):
            """Run a provider call, measure wall time, record n_iocs.

            Args:
                key: Provider short key (matches _PROVIDER_KEYS).
                enabled: Whether this provider has any IOC to query.
                call_fn: Zero-arg callable returning the provider result dict.

            Returns:
                The provider result dict, or {} when disabled.
            """
            payload = _payload(key) if enabled else []
            if not enabled:
                _provider_timings[key] = {"time": 0.0, "n": 0}
                return {}
            t0 = time.perf_counter()
            result = call_fn()
            _provider_timings[key] = {
                "time": time.perf_counter() - t0,
                "n": len(payload),
            }
            return result

        vt_results              = _timed("vt",              provider_flags["vt"],              lambda: vt_cached(_payload("vt"), settings.vt_key))
        urlscan_results         = _timed("urlscan",         provider_flags["urlscan"],         lambda: urlscan_cached(_payload("urlscan"), settings.urlscan_key, allow_urlscan_submit))
        abuse_results           = _timed("abuse",           provider_flags["abuse"],           lambda: abuse_cached(_payload("abuse"), settings.abuse_key, CACHE_REV))
        tf_results              = _timed("tf",              provider_flags["tf"],              lambda: tf_cached(_payload("tf"), settings.threatfox_key, CACHE_REV))
        mb_results              = _timed("mb",              provider_flags["mb"],              lambda: mb_cached(_payload("mb"), settings.malwarebazaar_key, CACHE_REV))
        shodan_results          = _timed("shodan",          provider_flags["shodan"],          lambda: shodan_cached(_payload("shodan"), settings.shodan_key, CACHE_REV))
        dnsd_results            = _timed("dns",             provider_flags["dns"],             lambda: dnsd_cached(_payload("dns"), settings.dnsdumpster_key, CACHE_REV))
        ha_results              = _timed("ha",              provider_flags["ha"],              lambda: ha_cached(_payload("ha"), settings.hybrid_analysis_key, CACHE_REV))
        mxtoolbox_results       = _timed("mxtoolbox",       provider_flags["mxtoolbox"],       lambda: mxtoolbox_cached(_payload("mxtoolbox"), settings.mxtoolbox_key, CACHE_REV))
        whoxy_results           = _timed("whoxy",           provider_flags["whoxy"],           lambda: whoxy_cached(_payload("whoxy"), settings.whoxy_key, CACHE_REV))
        ransomware_live_results = _timed("ransomware_live", provider_flags["ransomware_live"], lambda: ransomware_live_cached(_payload("ransomware_live"), settings.ransomware_live_key, CACHE_REV))
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
        st.session_state["run_results"] = {
            "items": items,
            "summary": summary,
            "rows": rows,
            "vt": vt_results,
            "urlscan": urlscan_results,
            "abuse": abuse_results,
            "tf": tf_results,
            "mb": mb_results,
            "shodan": shodan_results,
            "dnsd": dnsd_results,
            "ha": ha_results,
            "mxtoolbox": mxtoolbox_results,
            "whoxy": whoxy_results,
            "ransomware_live": ransomware_live_results,
            "provider_flags": provider_flags,
            "allowed_by_type": {t: sorted(ps) for t, ps in allowed_by_type.items()},
            "timings": {
                "providers": _provider_timings,
                "providers_total": sum(v["time"] for v in _provider_timings.values()),
            },
        }
        # New enrichment run invalidates any prior AI timing — it belongs to
        # the previous result set. Auto-AI (if enabled) will repopulate it.
        st.session_state.pop("ai_timing", None)
        # Snapshot the Input-tab context fields into ``result_*`` keys so the
        # Result tab's AI context expander has an isolated editable copy.
        _snapshot_input_context_to_result()
        # Auto-switch to Result tab so the user sees the new output immediately.
        # Use a pending flag because writing session_state["active_tab"]
        # directly after the segmented_control widget was instantiated above
        # raises StreamlitAPIException. The flag is consumed at the top of the
        # next script run, before the widget renders.
        st.session_state["_pending_tab_switch"] = "Result"
        st.rerun()

# ── Tab 2 (Result) rendering — runs after enrichment block above ─────────────
if active_tab == "Result":
    _has_run_results = bool(st.session_state.get("run_results"))

    with split_left:
        if _has_run_results:
            # render_ai_panel renders: Threat Analysis → Timing → AI Description
            render_ai_panel(st.session_state["run_results"], settings)
            # "AI context" expander — owns its own ``result_*`` state namespace.
            # Edits here do NOT propagate back to the Input tab. On the next Run
            # the values are overwritten by snapshotting Input → result_*.
            _render_context_expander(
                key_suffix="result",
                include_ai_settings=True,
                key_prefix="result_",
            )
        else:
            st.info("Belum ada hasil — kembali ke tab **Input** dan klik ▶ Run.")

    with split_right:
        if _has_run_results:
            render_results_output(output_format, st.session_state["run_results"])
            render_ioc_cards(st.session_state["run_results"])
        else:
            st.info("Tabel verdict dan kartu per-IOC akan muncul di sini.")
