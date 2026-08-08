"""Bug report / feature request dialog component."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

import requests
import streamlit as st

from ui.components.popup_state import (
    POPUP_BUG_REPORT,
    close_popup,
    dismiss_callback,
    is_open,
    open_popup,
)

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except Exception:
    pass

logger = logging.getLogger(__name__)

_WIB = timezone(timedelta(hours=7))
_DIVIDER = "━" * 26


def _send_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    """POST a message to Telegram. Returns True on success."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        resp = requests.post(
            url,
            json={"chat_id": chat_id, "text": text},
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.error("Telegram send failed: %s", exc)
        return False


def _build_message(feature: str, what_happened: str, recommendation: str) -> str:
    now = datetime.now(_WIB).strftime("%Y-%m-%d %H:%M:%S")
    parts = [
        "🐛 IOC Router — Bug Report / Feature Request",
        _DIVIDER,
        f"🕐 {now} WIB",
        "",
        f"📌 Feature: {feature}",
        "",
        f"❓ What Happened:",
        what_happened,
    ]
    if recommendation.strip():
        parts += ["", "💡 Recommendation:", recommendation]
    parts += ["", _DIVIDER, "📍 minzelo · IOC Router v1.0"]
    return "\n".join(parts)


@st.dialog(
    "📣 Report a Bug / Request Feature",
    on_dismiss=dismiss_callback(POPUP_BUG_REPORT),
)
def _bug_report_dialog() -> None:
    _FEATURES = ["AI Description", "Provider's Output", "Threat Analysis", "Analyst Result", "UI", "Others"]

    feature_choice = st.selectbox("What Feature?", _FEATURES, key="br_feature_select")

    feature = feature_choice
    if feature_choice == "Others":
        feature = st.text_input(
            "Specify feature",
            placeholder="Describe which feature...",
            key="br_feature_other",
        ).strip() or "Others"

    what_happened = st.text_area(
        "What Happened? (Context)",
        placeholder="Describe the bug or the feature you'd like...",
        height=130,
        key="br_what_happened",
    )

    recommendation = st.text_area(
        "Recommendation (Optional)",
        placeholder="Any suggestion, fix, or improvement...",
        height=80,
        key="br_recommendation",
    )

    col_send, col_cancel = st.columns(2)
    with col_send:
        if st.button("Send Report 📤", type="primary", use_container_width=True, key="br_send"):
            if not what_happened.strip():
                st.error("Please describe what happened before sending.")
                return

            bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
            chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
            if not bot_token or not chat_id:
                st.error(
                    "Telegram not configured. "
                    "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env"
                )
                return

            msg = _build_message(feature, what_happened.strip(), recommendation.strip())
            with st.spinner("Sending…"):
                ok = _send_telegram(bot_token, chat_id, msg)

            if ok:
                close_popup(POPUP_BUG_REPORT)
                st.toast("Report sent! Thank you 🙏", icon="✅")
                st.rerun()
            else:
                st.error("Failed to send. Check your Telegram credentials and try again.")

    with col_cancel:
        if st.button("Cancel", use_container_width=True, key="br_cancel"):
            close_popup(POPUP_BUG_REPORT)
            st.rerun()


def render_bug_report_button() -> None:
    """Render the Report Bug button. JS in app.py positions it in the header."""
    if st.button("Report Bug 🐞", key="report_bug_btn"):
        open_popup(POPUP_BUG_REPORT)
        st.rerun()

    if is_open(POPUP_BUG_REPORT):
        _bug_report_dialog()
