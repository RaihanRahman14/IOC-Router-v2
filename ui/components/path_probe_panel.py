"""Path Probe panel — UI for the WAF/exists scanner.

Rendered inside the Input tab when the user toggles the mode switch to
``Path Probe``. Reuses the styling primitives of the IOC input area
(bordered container, JetBrains Mono hints) for visual consistency.
"""
from __future__ import annotations

import io
import logging

import pandas as pd
import streamlit as st

from providers.path_prober import (
    DEFAULT_USER_AGENT,
    ProbeResult,
    clean_paths,
    probe_paths,
    split_paths,
)

logger = logging.getLogger(__name__)

_SESSION_KEY_DOMAIN = "probe_domain"
_SESSION_KEY_PATHS = "probe_paths_raw"
_SESSION_KEY_CLEAN = "probe_clean_input"
_SESSION_KEY_RESULTS = "probe_results"

_CLASS_BADGE: dict[str, str] = {
    "confirmed":     "✅ Confirmed",
    "not_confirmed": "❌ Not Confirmed",
    "error":         "⚠️ Error",
}


def _ensure_state() -> None:
    """Initialize session-state keys with their defaults if missing."""
    defaults: dict[str, object] = {
        _SESSION_KEY_DOMAIN: "",
        _SESSION_KEY_PATHS: "",
        _SESSION_KEY_CLEAN: True,
        _SESSION_KEY_RESULTS: [],
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def _results_to_dataframe(results: list[ProbeResult]) -> pd.DataFrame:
    """Build a display-ready DataFrame from probe results.

    Args:
        results: List of :class:`ProbeResult` from the scanner.

    Returns:
        DataFrame with friendly column labels and a classification badge.
    """
    if not results:
        return pd.DataFrame(
            columns=["Status", "Class", "Reason", "Time (ms)", "Size", "URL"]
        )
    rows = []
    for r in results:
        rows.append({
            "Status":    r.status_code if r.status_code is not None else "-",
            "Class":     _CLASS_BADGE.get(r.classification, r.classification),
            "Reason":    r.reason,
            "Time (ms)": r.elapsed_ms,
            "Size":      r.content_length if r.content_length is not None else "-",
            "URL":       r.final_url,
        })
    return pd.DataFrame(rows)


def _run_probe(
    domain: str,
    raw_paths: str,
    clean: bool,
    timeout: float,
    concurrency: int,
) -> None:
    """Execute the probe and stash results in session state.

    Args:
        domain: User-supplied target domain.
        raw_paths: Raw text from the paths text area.
        clean: When True, applies the aggressive cleaner (strip quotes /
            brackets / commas). When False, uses newline-only split.
        timeout: Per-request timeout (seconds).
        concurrency: Max parallel workers.
    """
    paths = clean_paths(raw_paths) if clean else split_paths(raw_paths)
    if not domain.strip():
        st.warning("Please enter a domain.")
        return
    if not paths:
        st.warning("Please enter at least one path.")
        return

    placeholder = st.empty()
    progress = st.progress(0.0, text=f"Probing 0 / {len(paths)} ...")
    streamed: list[ProbeResult] = []

    def _on_result(res: ProbeResult) -> None:
        streamed.append(res)
        done = len(streamed)
        progress.progress(
            done / len(paths),
            text=f"Probing {done} / {len(paths)} ...",
        )
        placeholder.dataframe(
            _results_to_dataframe(streamed),
            use_container_width=True,
            hide_index=True,
        )

    results = probe_paths(
        domain,
        paths,
        timeout=timeout,
        concurrency=concurrency,
        user_agent=DEFAULT_USER_AGENT,
        follow_redirects=True,
        verify_ssl=False,
        on_result=_on_result,
    )
    progress.empty()
    placeholder.empty()
    st.session_state[_SESSION_KEY_RESULTS] = results
    logger.info(
        "path-probe completed: domain=%s paths=%d confirmed=%d",
        domain,
        len(paths),
        sum(1 for r in results if r.classification == "confirmed"),
    )


def _render_results() -> None:
    """Render the persistent results section (filters + table + export)."""
    results: list[ProbeResult] = st.session_state.get(_SESSION_KEY_RESULTS) or []
    if not results:
        return

    st.markdown("---")
    confirmed = sum(1 for r in results if r.classification == "confirmed")
    not_conf = sum(1 for r in results if r.classification == "not_confirmed")
    errored = sum(1 for r in results if r.classification == "error")

    _m1, _m2, _m3, _m4 = st.columns(4)
    _m1.metric("Total", len(results))
    _m2.metric("Confirmed", confirmed)
    _m3.metric("Not Confirmed", not_conf)
    _m4.metric("Errors", errored)

    _fcol, _ = st.columns([2, 3])
    with _fcol:
        active_classes = st.multiselect(
            "Filter classification",
            options=["confirmed", "not_confirmed", "error"],
            default=["confirmed", "not_confirmed", "error"],
            key="probe_filter_class",
        )

    filtered = [r for r in results if r.classification in active_classes]
    df = _results_to_dataframe(filtered)
    st.dataframe(df, use_container_width=True, hide_index=True)

    csv_buf = io.StringIO()
    df.to_csv(csv_buf, index=False)
    st.download_button(
        "⬇️ Export CSV",
        data=csv_buf.getvalue(),
        file_name="path_probe_results.csv",
        mime="text/csv",
        key="probe_export_csv",
    )


def render_path_probe_panel() -> None:
    """Render the full Path Probe panel.

    Layout (top-to-bottom):
        1. Domain input
        2. Paths bulk input (text area)
        3. Cleaner checkbox (directly below the paths input)
        4. Advanced expander (timeout, concurrency)
        5. Run button
        6. Results section (metrics + filter + table + CSV export)
    """
    _ensure_state()

    with st.container(border=True):
        st.text_input(
            "Domain",
            placeholder="example.com  or  https://example.com",
            key=_SESSION_KEY_DOMAIN,
        )

        st.text_area(
            "URL Paths (one per line — quotes / brackets / commas are OK)",
            placeholder='/admin\n/.env\n["/login"]\n"/api/v1/users"',
            height=180,
            key=_SESSION_KEY_PATHS,
        )

        st.checkbox(
            "🧹 Clean input — strip quotes, brackets, and commas before scanning",
            key=_SESSION_KEY_CLEAN,
            help=(
                "When enabled, characters \" ' [ ] are removed and entries "
                "split on both newlines and commas. Disable to preserve "
                "paths exactly as typed (newline-split only)."
            ),
        )

        with st.expander("⚙️ Advanced settings"):
            _ac1, _ac2 = st.columns(2)
            with _ac1:
                timeout = st.slider(
                    "Timeout (seconds)", 3, 30, 10, key="probe_timeout"
                )
            with _ac2:
                concurrency = st.slider(
                    "Concurrency (parallel workers)",
                    1, 50, 10, key="probe_concurrency",
                )

        _bc1, _bc2 = st.columns([3, 1])
        with _bc2:
            run_clicked = st.button(
                "▶ Start Probe",
                type="primary",
                use_container_width=True,
                key="probe_run_btn",
            )
        with _bc1:
            if st.button(
                "🗑️ Clear results",
                use_container_width=True,
                key="probe_clear_btn",
            ):
                st.session_state[_SESSION_KEY_RESULTS] = []
                st.rerun()

    if run_clicked:
        _run_probe(
            domain=st.session_state[_SESSION_KEY_DOMAIN],
            raw_paths=st.session_state[_SESSION_KEY_PATHS],
            clean=st.session_state[_SESSION_KEY_CLEAN],
            timeout=float(st.session_state.get("probe_timeout", 10)),
            concurrency=int(st.session_state.get("probe_concurrency", 10)),
        )

    _render_results()

    st.markdown(
        '<p style="text-align:center;font-family:\'JetBrains Mono\',monospace;'
        'font-size:0.72rem;color:#6b7280;margin-top:10px;line-height:1.8;">'
        'Use only on targets you own or are explicitly authorized to test.'
        "</p>",
        unsafe_allow_html=True,
    )
