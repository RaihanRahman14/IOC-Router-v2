"""IOC Router - Streamlit app entrypoint (refactored)."""
from __future__ import annotations

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
from ui.styles import GLOBAL_CSS_AND_HEADER, LANDING_CSS
from ui.components.drawer import render_api_drawer
from ui.components.output_renderer import render_results_output
from ui.components.ioc_card import render_ioc_cards
from ui.components.ai_panel import render_ai_panel
from ui.components.cve_panel import render_cve_panel
from ui.components.bug_report import render_bug_report_button

st.set_page_config(
    page_title="IOC Router",
    page_icon="IOC",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(GLOBAL_CSS_AND_HEADER, unsafe_allow_html=True)

render_bug_report_button()

# JavaScript drawer controller — runs in a zero-height iframe so it
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

        function attachReportBtn() {
            var headerBtn = pd.getElementById('report-bug-header-btn');
            if (headerBtn && !headerBtn._rbReady) {
                headerBtn._rbReady = true;
                headerBtn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    // Find and click the hidden Streamlit trigger button
                    var stBtns = pd.querySelectorAll('[data-testid="stButton"] button');
                    stBtns.forEach(function(b) {
                        if (b.textContent.trim() === 'Report Bug 🐞') {
                            b.click();
                        }
                    });
                });
            }
            // Hide the Streamlit trigger button (replaced by the header HTML button)
            pd.querySelectorAll('[data-testid="stButton"] button').forEach(function(b) {
                if (b.textContent.trim() === 'Report Bug 🐞') {
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
                attachReportBtn();
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
                attachReportBtn();
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
    st.session_state["ai_short"] = ""
    st.session_state["ai_desc"] = ""
    st.session_state["ai_threat_analysis"] = ""
    st.session_state["ai_ioc_links"] = ""


def _clear_all_outputs() -> None:
    """Clear all run results and AI outputs from session state."""
    st.session_state["run_results"] = None
    _clear_ai_outputs()


render_api_drawer()

if not settings.vt_key:
    st.warning("VirusTotal API key belum di-set. Set env var: VT_KEY")

# ── Pre-compute layout mode ───────────────────────────────────────────────────
_has_results = bool(st.session_state["run_results"])
_was_landing = not _has_results  # True when Run is first clicked from chat UI

# ── Variable defaults (overridden by widgets below) ───────────────────────────
output_format: str = st.session_state.get("output_format", "Ticket notes")
auto_generate_on_run: bool = st.session_state.get("auto_generate_on_run", False)
auto_detect_and_provider: bool = st.session_state.get("auto_detect_and_provider", True)
auto_detect: bool = auto_detect_and_provider
auto_choose_provider: bool = auto_detect_and_provider
critical_asset: bool = st.session_state.get("critical_asset_sel", "Non Critical Asset") == "Critical Asset"
allow_urlscan_submit: bool = True
run: bool = False
clear: bool = False
load_sample: bool = False
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
        mode: Either "Triage" or "Lookup".

    Returns:
        Mapping of IOC group key to list of provider keys appropriate for the mode.
    """
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


if not _has_results:
    # ── LANDING: Note left | Input center | CVE right ─────────────────────────
    st.markdown(LANDING_CSS, unsafe_allow_html=True)

    _note_col, _center_col, _right_col = st.columns([0.75, 2.4, 0.9], gap="large")

    with _note_col:
        st.markdown(
            '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.88rem;'
            'font-weight:700;color:#f5f7fb;letter-spacing:0.01em;margin-bottom:10px;">Note</div>',
            unsafe_allow_html=True,
        )
        _notes = [
            "<strong>Gemini, Grok, and MxToolBox</strong> require own API key",
            "For more efficient and fast query turn off Auto Provider and deselect not needed providers",
            "Whoxy provider is currently not available",
            "To refresh output do a hard refresh",
            "Project is still Under development",
        ]
        _note_items = "".join(
            f'<li style="margin-bottom:10px;line-height:1.5;">{n}</li>'
            for n in _notes
        )
        st.markdown(
            f'<ul style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;'
            f'color:#9ca3af;padding-left:1.1rem;margin:0;list-style-type:disc;">'
            f'{_note_items}'
            f'</ul>',
            unsafe_allow_html=True,
        )

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
            with _tc_mode:
                with st.popover(f"{_current_mode} ▾", use_container_width=True):
                    st.radio(
                        "Mode",
                        ["Triage", "Lookup"],
                        index=0 if _current_mode == "Triage" else 1,
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
        with st.expander("🗂️ Context"):
            output_format = st.selectbox(
                "Output format", ["Ticket notes", "Table", "JSON", "Shareable Text"], index=0, key="output_format"
            )

            _opt = st.columns(2)
            with _opt[0]:
                alert_name = st.text_input(
                    "Alert Name", placeholder="e.g. Suspicious Outbound", key="alert_name"
                )
                host_ip = st.text_input("Host IP", placeholder="192.168.x.x", key="host_ip")
            with _opt[1]:
                host = st.text_input("Host", placeholder="hostname", key="host")
                time_detected = st.text_input(
                    "Time Detected", placeholder="2025-01-01 08:00:00", key="time_detected"
                )

            _proc = st.columns([2, 1])
            with _proc[0]:
                device_action = st.selectbox(
                    "Device Action",
                    ["None", "Blocked", "Isolated", "Prevented", "Allowed", "Detected", "File Cleaned", "Others"],
                    key="device_action",
                )
            with _proc[1]:
                _asset_sel = st.selectbox("Asset Criticality", ["Non Critical Asset", "Critical Asset"], index=0, key="critical_asset_sel")
                critical_asset = _asset_sel == "Critical Asset"
            if device_action == "Others":
                device_action_others = st.text_input(
                    "Specify Action",
                    placeholder="e.g. Terminated, Logged, Alerted...",
                    key="device_action_others",
                )

            file_path = st.text_input(
                "File Path", placeholder="e.g. C:\\Users\\user\\Downloads\\malware.exe", key="file_path"
            )
            parent_process = st.text_input(
                "Parent Process", placeholder="e.g. explorer.exe", key="parent_process"
            )
            child_process = st.text_input(
                "Child Process", placeholder="e.g. cmd.exe", key="child_process"
            )

            raw_log = st.text_area(
                "Context (optional)",
                placeholder="Paste raw log or describe context here for additional AI context...",
                height=80,
                key="raw_log",
            )

            _act = st.columns(2)
            with _act[0]:
                clear = st.button("🗑️ Clear", use_container_width=True, key="clear_landing")
            with _act[1]:
                load_sample = st.button(
                    "📋 Load Sample IOCs", use_container_width=True, key="load_sample_landing"
                )

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

    with _right_col:
        render_cve_panel()

    split_right = _right_col
    split_left = _center_col

else:
    # ── SPLIT LAYOUT: Input left + Results right ──────────────────────────────
    components.html(
        """
        <script>
        (function() {
            function tagMainSplit() {
                var blocks = window.parent.document.querySelectorAll('[data-testid="stHorizontalBlock"]');
                if (blocks.length > 0) {
                    blocks[0].classList.add('ioc-main-split');
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

    split_left, split_right = st.columns([1, 1], gap="small")

    with split_left:
        st.subheader("Input")
        raw = st.text_area(
            "IOC",
            placeholder="8.8.8.8\nexample.com\nhttps://evil.com/login\n<hash>",
            height=160,
            key="ioc_input",
        )
        raw_log = st.text_area(
            "Context (optional)",
            placeholder="Paste raw log or describe context here for additional AI description context",
            height=120,
            key="raw_log",
        )
        alert_name = st.text_input("Alert Name (optional)", key="alert_name")
        host = st.text_input("Host (optional)", key="host")
        host_ip = st.text_input("Host IP (optional)", key="host_ip")
        time_detected = st.text_input("Time Detected (optional)", key="time_detected")

        _sp_proc = st.columns(3)
        with _sp_proc[0]:
            device_action = st.selectbox(
                "Device Action",
                ["None", "Blocked", "Isolated", "Prevented", "Allowed", "Detected", "File Cleaned", "Others"],
                key="device_action",
            )
        with _sp_proc[1]:
            parent_process = st.text_input(
                "Parent Process", placeholder="e.g. explorer.exe", key="parent_process"
            )
        with _sp_proc[2]:
            child_process = st.text_input(
                "Child Process", placeholder="e.g. cmd.exe", key="child_process"
            )
        if device_action == "Others":
            device_action_others = st.text_input(
                "Specify Action",
                placeholder="e.g. Terminated, Logged, Alerted...",
                key="device_action_others",
            )

        _current_mode_r = st.session_state.get("analysis_mode", "Triage")
        _auto_on_r = st.session_state.get("auto_detect_and_provider", True)
        _show_speed_r = _current_mode_r == "Triage" and _auto_on_r
        if _show_speed_r:
            col_chk = st.columns([0.6, 0.55, 1.0, 1.0, 1.0])
        else:
            col_chk = st.columns([0.6, 1.2, 1.0, 1.0])
        _auto_label_r = (
            "Auto detect Lookup & Provider"
            if _current_mode_r == "Lookup"
            else "Auto detect & Provider"
        )
        with col_chk[0]:
            with st.popover(f"{_current_mode_r} ▾", use_container_width=True):
                st.radio(
                    "Mode",
                    ["Triage", "Lookup"],
                    index=0 if _current_mode_r == "Triage" else 1,
                    key="analysis_mode",
                    label_visibility="collapsed",
                )
        if _show_speed_r:
            with col_chk[1]:
                _current_speed_r = st.session_state.get("triage_speed", "Detailed")
                with st.popover(f"{_current_speed_r} ▾", use_container_width=True):
                    st.radio(
                        "Triage speed",
                        ["Fast", "Detailed"],
                        index=0 if _current_speed_r == "Fast" else 1,
                        key="triage_speed",
                        label_visibility="collapsed",
                    )
            with col_chk[2]:
                st.checkbox(_auto_label_r, value=True, key="auto_detect_and_provider")
            _gen_col, _asset_col = col_chk[3], col_chk[4]
        else:
            with col_chk[1]:
                st.checkbox(_auto_label_r, value=True, key="auto_detect_and_provider")
            _gen_col, _asset_col = col_chk[2], col_chk[3]
        with _gen_col:
            auto_generate_on_run = st.checkbox(
                "Auto Generate AI Output", value=False, key="auto_generate_on_run"
            )
        with _asset_col:
            _asset_sel = st.selectbox("Asset Criticality", ["Non Critical Asset", "Critical Asset"], index=0, key="critical_asset_sel")
            critical_asset = _asset_sel == "Critical Asset"

        if auto_generate_on_run:
            col_drop = st.columns([1, 1, 3])
            with col_drop[0]:
                st.selectbox("AI Provider", ["Gemini", "Groq"], index=0, key="auto_ai_provider")
            with col_drop[1]:
                output_format = st.selectbox(
                    "Output format", ["Ticket notes", "Table", "JSON", "Shareable Text"], index=0, key="output_format"
                )
        else:
            col_drop = st.columns([1, 4])
            with col_drop[0]:
                output_format = st.selectbox(
                    "Output format", ["Ticket notes", "Table", "JSON", "Shareable Text"], index=0, key="output_format"
                )

        if not auto_detect_and_provider:
            _render_providers_expander(
                expanded=False,
                mode=st.session_state.get("analysis_mode", "Triage"),
            )

        col_btn = st.columns([1.6, 0.8, 1.8, 2.8], gap="small")
        with col_btn[0]:
            run = st.button("Run Enrichment", type="primary", key="run_btn_split")
        with col_btn[1]:
            clear = st.button("Clear", key="clear_split")
        with col_btn[2]:
            load_sample = st.button("Load sample IOCs", key="load_sample_split")

# ── IOC change detection ──────────────────────────────────────────────────────
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
if ioc_changed:
    _clear_all_outputs()
st.session_state["ioc_signature_last"] = current_ioc_signature

# ── Action handlers ───────────────────────────────────────────────────────────
if clear:
    _clear_all_outputs()
    st.session_state["reset_input"] = True
    st.rerun()

if load_sample:
    st.session_state["load_sample"] = True
    st.rerun()

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


# ── Right panel / Results ─────────────────────────────────────────────────────
with split_right:
    if not _was_landing:
        st.subheader("Results")
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

            vt_results = vt_cached(_payload("vt"), settings.vt_key) if provider_flags["vt"] else {}
            urlscan_results = (
                urlscan_cached(_payload("urlscan"), settings.urlscan_key, allow_urlscan_submit)
                if provider_flags["urlscan"]
                else {}
            )
            abuse_results   = abuse_cached(_payload("abuse"), settings.abuse_key, CACHE_REV)             if provider_flags["abuse"]   else {}
            tf_results      = tf_cached(_payload("tf"), settings.threatfox_key, CACHE_REV)               if provider_flags["tf"]      else {}
            mb_results      = mb_cached(_payload("mb"), settings.malwarebazaar_key, CACHE_REV)           if provider_flags["mb"]      else {}
            shodan_results  = shodan_cached(_payload("shodan"), settings.shodan_key, CACHE_REV)          if provider_flags["shodan"]  else {}
            dnsd_results    = dnsd_cached(_payload("dns"), settings.dnsdumpster_key, CACHE_REV)          if provider_flags["dns"]     else {}
            ha_results      = ha_cached(_payload("ha"), settings.hybrid_analysis_key, CACHE_REV)         if provider_flags["ha"]      else {}
            mxtoolbox_results      = mxtoolbox_cached(_payload("mxtoolbox"), settings.mxtoolbox_key, CACHE_REV)           if provider_flags["mxtoolbox"]      else {}
            whoxy_results          = whoxy_cached(_payload("whoxy"), settings.whoxy_key, CACHE_REV)                       if provider_flags["whoxy"]           else {}
            ransomware_live_results = (
                ransomware_live_cached(_payload("ransomware_live"), settings.ransomware_live_key, CACHE_REV)
                if provider_flags["ransomware_live"]
                else {}
            )
            summary, rows = summarize_results(
                items,
                vt_results,
                urlscan_results,
                abuse_results,
                tf_results,
                mb_results,
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
            }
            if _was_landing:
                st.rerun()

    if st.session_state["run_results"]:
        render_results_output(output_format, st.session_state["run_results"])
        render_ioc_cards(st.session_state["run_results"])
    elif run_requested and not _was_landing:
        st.info("Please enter at least one IOC first.")

with split_left:
    if st.session_state.get("run_results"):
        render_ai_panel(st.session_state["run_results"], settings)
