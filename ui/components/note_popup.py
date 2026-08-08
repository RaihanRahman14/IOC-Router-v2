"""Note popup dialog — displays landing-page notes triggered from header."""
from __future__ import annotations

import streamlit as st

from ui.components.popup_state import (
    POPUP_NOTE,
    close_popup,
    dismiss_callback,
    is_open,
    open_popup,
)

_NOTES: tuple[str, ...] = (
    "<strong>Gemini, Grok, and MxToolBox</strong> require own API key",
    "For more efficient and fast query turn off Auto Provider and deselect not needed providers",
    "Whoxy provider is currently not available",
    "To refresh output do a hard refresh",
    "Project is still Under development",
)


@st.dialog("Notes", on_dismiss=dismiss_callback(POPUP_NOTE))
def _note_dialog() -> None:
    """Render the notes dialog body. Close X is hidden — only the Back button closes."""
    # Marker + scoped CSS: hide Streamlit's built-in dialog close button only
    # for this dialog (Bug Report dialog still keeps its X).
    st.markdown(
        """
        <div class="note-dialog-marker" style="display:none"></div>
        <style>
          div[role="dialog"]:has(.note-dialog-marker) button[aria-label="Close"],
          div[role="dialog"]:has(.note-dialog-marker) button[kind="header"],
          div[role="dialog"]:has(.note-dialog-marker) [data-testid="stDialogCloseButton"] {
            display: none !important;
          }
        </style>
        """,
        unsafe_allow_html=True,
    )

    _items = "".join(
        f'<li style="margin-bottom:10px;line-height:1.55;">{n}</li>'
        for n in _NOTES
    )
    st.markdown(
        f'<ul style="font-family:\'JetBrains Mono\',monospace;font-size:0.82rem;'
        f'color:#c9d1d9;padding-left:1.2rem;margin:0 0 14px;list-style-type:disc;">'
        f'{_items}'
        f'</ul>',
        unsafe_allow_html=True,
    )

    if st.button("← Back", use_container_width=True, key="note_back_btn"):
        close_popup(POPUP_NOTE)
        st.rerun()


def render_note_button() -> None:
    """Render the Note (ⓘ) button. JS in app.py positions it next to Report Bug."""
    if st.button("Notes ⓘ", key="note_popup_btn"):
        open_popup(POPUP_NOTE)
        st.rerun()

    if is_open(POPUP_NOTE):
        _note_dialog()
