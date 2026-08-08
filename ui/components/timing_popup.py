"""Timing popup dialog — displays provider + AI timing breakdown from header."""
from __future__ import annotations

import streamlit as st

from ui.components.popup_state import (
    POPUP_TIMING,
    close_popup,
    dismiss_callback,
    is_open,
    open_popup,
)

_PROV_LABEL_MAP: dict[str, str] = {
    "vt": "VirusTotal", "urlscan": "urlscan", "abuse": "AbuseIPDB",
    "tf": "ThreatFox", "mb": "MalwareBazaar", "shodan": "Shodan",
    "dns": "DNSDumpster", "ha": "Hybrid Analysis",
    "mxtoolbox": "MxToolBox", "whoxy": "Whoxy",
    "ransomware_live": "Ransomware.live",
}


@st.dialog("Timing", on_dismiss=dismiss_callback(POPUP_TIMING))
def _timing_dialog() -> None:
    """Render the timing breakdown dialog body. Close X is hidden — only Back closes."""
    st.markdown(
        """
        <div class="timing-dialog-marker" style="display:none"></div>
        <style>
          div[role="dialog"]:has(.timing-dialog-marker) button[aria-label="Close"],
          div[role="dialog"]:has(.timing-dialog-marker) button[kind="header"],
          div[role="dialog"]:has(.timing-dialog-marker) [data-testid="stDialogCloseButton"] {
            display: none !important;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )

    run_results = st.session_state.get("run_results") or {}
    timings = run_results.get("timings") or {}
    prov_timings: dict = timings.get("providers") or {}
    prov_total: float = float(timings.get("providers_total") or 0.0)
    ai_timing = st.session_state.get("ai_timing") or {}
    ai_time: float = float(ai_timing.get("time") or 0.0) if ai_timing else 0.0
    grand_total: float = prov_total + ai_time

    if not prov_timings and not ai_timing:
        st.info("No timing data yet — run an enrichment from the Input tab first.")
    else:
        if prov_timings:
            active = [
                (k, v) for k, v in prov_timings.items()
                if v.get("n", 0) > 0 or v.get("time", 0.0) > 0
            ]
            active.sort(key=lambda kv: kv[1].get("time", 0.0), reverse=True)
            if active:
                st.markdown("**Providers**")
                for k, v in active:
                    name = _PROV_LABEL_MAP.get(k, k)
                    n = int(v.get("n", 0))
                    t = float(v.get("time", 0.0))
                    st.markdown(
                        f"- {name}: `{t:.2f}s` &nbsp;·&nbsp; "
                        f"{n} IOC{'s' if n != 1 else ''}",
                        unsafe_allow_html=True,
                    )
                st.markdown(f"**Providers subtotal:** `{prov_total:.2f}s`")
        if ai_timing:
            st.divider()
            st.markdown("**AI (Threat Analysis)**")
            st.markdown(f"- {ai_timing.get('provider', 'AI')}: `{ai_time:.2f}s`")
        st.divider()
        st.markdown(f"**Total elapsed:** `{grand_total:.2f}s`")
        st.caption(
            "Provider times include cache hits (near-instant) and network calls. "
            "AI time only appears once a Threat Analysis has actually been generated."
        )

    if st.button("← Back", use_container_width=True, key="timing_back_btn"):
        close_popup(POPUP_TIMING)
        st.rerun()


def render_timing_button() -> None:
    """Render the hidden Streamlit trigger button for the timing popup.

    The visible ⏱ button is injected as raw HTML in the fixed header
    (see ``ui/styles.py``) and forwards its click to this hidden button
    via the JS bootstrap in ``app.py``.
    """
    if st.button("Timing ⏱", key="timing_popup_btn"):
        open_popup(POPUP_TIMING)
        st.rerun()

    if is_open(POPUP_TIMING):
        _timing_dialog()
