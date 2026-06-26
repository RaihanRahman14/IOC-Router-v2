"""Hidden tab-switch buttons. JS in app.py forwards clicks from the header
tab HTML buttons (.header-tab-btn) to these hidden Streamlit buttons.
"""
from __future__ import annotations

import streamlit as st

_TABS: tuple[str, ...] = ("Input", "Result", "CVE")


def render_tab_switch_buttons() -> None:
    """Render one hidden Streamlit button per tab.

    Each button label is the literal ``Switch to <Tab>`` — the JS controller
    locates the button by exact text match, so do not change these labels
    without also updating the JS in ``app.py``.
    """
    for _tab in _TABS:
        if st.button(f"Switch to {_tab}", key=f"tab_switch_btn_{_tab}"):
            st.session_state["_pending_tab_switch"] = _tab
            st.rerun()
