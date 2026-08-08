"""Single-slot state shared by the header dialogs (Bug Report / Notes / Timing).

Streamlit allows only one ``@st.dialog``-decorated function to be invoked per
script run — a second call raises ``StreamlitAPIException``. Each popup used to
own an independent ``show_*`` boolean, and nothing cleared those booleans when a
dialog was dismissed with ESC or a backdrop click. A stale ``True`` plus a newly
clicked popup therefore opened two dialogs in the same run and crashed the app.

All popups now share one slot: opening one implicitly closes the others, and
each dialog passes :func:`dismiss_callback` to ``st.dialog(on_dismiss=...)`` so a
dismissal clears the slot instead of leaving it stuck open.
"""
from __future__ import annotations

from collections.abc import Callable

import streamlit as st

_ACTIVE_KEY = "active_popup"

POPUP_BUG_REPORT = "bug_report"
POPUP_NOTE = "note"
POPUP_TIMING = "timing"


def open_popup(name: str) -> None:
    """Make ``name`` the one open popup, closing whichever was open before.

    Args:
        name: Popup identifier, one of the ``POPUP_*`` constants.
    """
    st.session_state[_ACTIVE_KEY] = name


def close_popup(name: str | None = None) -> None:
    """Clear the open popup.

    Args:
        name: Only close if this popup is the open one. ``None`` closes
            whatever is open.
    """
    if name is None or st.session_state.get(_ACTIVE_KEY) == name:
        st.session_state[_ACTIVE_KEY] = None


def is_open(name: str) -> bool:
    """Return True when ``name`` is the currently open popup.

    Args:
        name: Popup identifier, one of the ``POPUP_*`` constants.

    Returns:
        True if this popup — and therefore no other — should be rendered.
    """
    return st.session_state.get(_ACTIVE_KEY) == name


def dismiss_callback(name: str) -> Callable[[], None]:
    """Build an ``on_dismiss`` handler that releases the slot held by ``name``.

    Args:
        name: Popup identifier, one of the ``POPUP_*`` constants.

    Returns:
        Zero-arg callback suitable for ``st.dialog(on_dismiss=...)``.
    """
    def _on_dismiss() -> None:
        close_popup(name)

    return _on_dismiss
